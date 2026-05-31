import json
import os
import shlex
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from fastapi import FastAPI, HTTPException, Request
import jwt

import os
from dotenv import load_dotenv

load_dotenv()

# 读取配置
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "http://localhost:8001/.well-known/jwks.json")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000/mcp")

# 如果环境变量中有端口配置，自动构造 URL
auth_port = os.getenv("AUTH_SERVER_PORT", "8001")
mcp_port = os.getenv("MCP_SERVER_PORT", "8000")
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", f"http://localhost:{auth_port}/.well-known/jwks.json")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", f"http://localhost:{mcp_port}/mcp")

try:
    from guard_proxy.audit import (
        AUDIT_LOG_PATH,
        audit_events_for_intent,
        audit_trace_for_id,
        log_decision,
        log_execution,
        log_intent,
        recent_audit_events,
    )
    from guard_proxy.confirmations import ConfirmationStore
    from guard_proxy.policy_config import DEFAULT_POLICY_PATH, load_policy_config
except ImportError:
    from audit import (
        AUDIT_LOG_PATH,
        audit_events_for_intent,
        audit_trace_for_id,
        log_decision,
        log_execution,
        log_intent,
        recent_audit_events,
    )
    from confirmations import ConfirmationStore
    from policy_config import DEFAULT_POLICY_PATH, load_policy_config

app = FastAPI(title="Guard Proxy")

SECRET_KEY = "guardmcp-secret-key-2026-demo-shared-secret"
ALGORITHM = "RS256"
ISSUER = "oauth-server"
AUDIENCE = "mcp-resource"
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "http://localhost:18001/.well-known/jwks.json")
JWKS_CACHE_SECONDS = int(os.getenv("GUARD_JWKS_CACHE_SECONDS", "300"))
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:18000/mcp")
POLICY_CONFIG_PATH = os.getenv("GUARD_POLICY_PATH", str(DEFAULT_POLICY_PATH))


def resource_metadata_url(mcp_server_url: str) -> str:
    parsed = urllib.parse.urlsplit(mcp_server_url)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource", "", "")
    )


RESOURCE_METADATA_URL = resource_metadata_url(MCP_SERVER_URL)
POLICY_CONFIG = load_policy_config(POLICY_CONFIG_PATH)

ALLOWED_SOURCE_LABELS = POLICY_CONFIG["allowed_source_labels"]
TOOL_POLICIES = POLICY_CONFIG["tools"]
ALLOWED_MAIL_RECIPIENTS = POLICY_CONFIG["allowed_mail_recipients"]
ALLOWED_SHELL_COMMANDS = POLICY_CONFIG["allowed_shell_commands"]
DANGEROUS_SHELL_FRAGMENTS = POLICY_CONFIG["dangerous_shell_fragments"]

REQUIRED_INTENT_FIELDS = {
    "intent_id",
    "session_id",
    "tool_name",
    "tool_args",
    "purpose",
    "source_trace",
    "risk_ack",
}

CONFIRMATION_STORE = ConfirmationStore()
JWKS_CACHE: dict[str, Any] = {"expires_at": 0.0, "keys": {}}


def audit_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def normalize_audit_limit(limit: int) -> int:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    return limit


def deny(
    req_id: Any,
    reason: str,
    failed_check: str,
    tool_name: str | None = None,
    alternatives: list[dict[str, Any]] | None = None,
):
    result = {
        "decision": "deny",
        "audit_id": audit_id("guard-deny"),
        "tool_name": tool_name,
        "reason": reason,
        "failed_check": failed_check,
        "isError": True,
    }
    if alternatives:
        result["alternatives"] = alternatives
    return jsonrpc_result(req_id, result)


def scope_challenge(
    req_id: Any,
    tool_name: str,
    required_scopes: list[str],
    missing_scopes: list[str],
    alternatives: list[dict[str, Any]] | None = None,
):
    result = {
        "decision": "scope_challenge",
        "audit_id": audit_id("guard-challenge"),
        "tool_name": tool_name,
        "required_scopes": required_scopes,
        "missing_scopes": missing_scopes,
        "resource_metadata_url": RESOURCE_METADATA_URL,
        "message": f"Token is valid but lacks the required scope for {tool_name}.",
        "isError": True,
    }
    if alternatives:
        result["alternatives"] = alternatives
    return jsonrpc_result(req_id, result)


def user_confirm(req_id: Any, intent: dict[str, Any], issued_confirmation: dict[str, Any]):
    return jsonrpc_result(
        req_id,
        {
            "decision": "user_confirm",
            "audit_id": audit_id("guard-confirm"),
            "tool_name": intent["tool_name"],
            "intent_id": intent["intent_id"],
            "display_args": intent["tool_args"],
            "confirmation_hash": issued_confirmation["confirmation_hash"],
            "expires_at": issued_confirmation["expires_at_iso"],
            "expires_in_seconds": issued_confirmation["expires_in_seconds"],
            "message": "User confirmation required. Repeat the same tools/call with this confirmation_hash before it expires.",
            "isError": True,
        },
    )


def fetch_jwks() -> dict[str, Any]:
    now = time.time()
    if JWKS_CACHE["expires_at"] > now and JWKS_CACHE["keys"]:
        return JWKS_CACHE["keys"]

    request = urllib.request.Request(AUTH_JWKS_URL, method="GET")
    request.add_header("Accept", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        if JWKS_CACHE["keys"]:
            return JWKS_CACHE["keys"]
        raise HTTPException(status_code=401, detail=f"JWKS discovery failed: {exc}")

    keys: dict[str, Any] = {}
    for item in payload.get("keys", []):
        kid = item.get("kid")
        if kid:
            keys[kid] = item
    JWKS_CACHE["keys"] = keys
    JWKS_CACHE["expires_at"] = now + JWKS_CACHE_SECONDS
    return keys


def public_key_for_token(token: str):
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token header") from exc
    if header.get("alg") != ALGORITHM:
        raise HTTPException(status_code=401, detail="Unsupported token signing algorithm")
    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Missing token key id")

    jwk = fetch_jwks().get(kid)
    if jwk is None:
        JWKS_CACHE["expires_at"] = 0.0
        jwk = fetch_jwks().get(kid)
    if jwk is None:
        raise HTTPException(status_code=401, detail="Unknown token key id")
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))


def decode_bearer_token(auth_header: str | None) -> dict[str, Any]:
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    try:
        public_key = public_key_for_token(token)
        return jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def normalize_intent(params: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
    intent = params.get("intent")
    if isinstance(intent, dict):
        return intent

    tool_name = params.get("name")
    tool_args = params.get("arguments", {})
    return {
        "intent_id": params.get("intent_id", f"legacy-{uuid.uuid4()}"),
        "session_id": params.get("session_id", claims.get("session_id", "")),
        "tool_name": tool_name,
        "tool_args": tool_args if isinstance(tool_args, dict) else {},
        "purpose": params.get("purpose", "Legacy MCP tools/call request."),
        "source_trace": params.get(
            "source_trace",
            [
                {
                    "source_id": "legacy-client",
                    "label": "user",
                    "description": "Legacy MCP params without explicit intent.",
                }
            ],
        ),
        "risk_ack": bool(params.get("risk_ack", False)),
        "legacy_format": True,
    }


def validate_intent_shape(intent: dict[str, Any]) -> tuple[bool, str]:
    missing = sorted(REQUIRED_INTENT_FIELDS - set(intent))
    if missing:
        return False, f"Missing intent fields: {', '.join(missing)}"
    if not isinstance(intent["tool_name"], str) or not intent["tool_name"]:
        return False, "Invalid intent.tool_name"
    if not isinstance(intent["intent_id"], str) or not intent["intent_id"]:
        return False, "Invalid intent.intent_id"
    if not isinstance(intent["session_id"], str) or not intent["session_id"]:
        return False, "Invalid intent.session_id"
    if not isinstance(intent["tool_args"], dict):
        return False, "Invalid intent.tool_args"
    if not isinstance(intent["purpose"], str) or not intent["purpose"]:
        return False, "Invalid intent.purpose"
    if not isinstance(intent["source_trace"], list) or not intent["source_trace"]:
        return False, "Invalid intent.source_trace"
    if not isinstance(intent["risk_ack"], bool):
        return False, "Invalid intent.risk_ack"
    for source in intent["source_trace"]:
        if not isinstance(source, dict):
            return False, "Invalid source_trace item"
        if not isinstance(source.get("source_id"), str) or not source.get("source_id"):
            return False, "Invalid source_trace source_id"
        if not isinstance(source.get("label"), str) or not source.get("label"):
            return False, "Invalid source_trace label"
    return True, ""


def has_dangerous_path(path: str) -> bool:
    return (
        "\x00" in path
        or path.startswith("/")
        or path.startswith("~")
        or "\\" in path
        or ".." in path.split("/")
    )


def validate_file_args(tool_args: dict[str, Any], prefix: str) -> tuple[bool, str]:
    path = tool_args.get("path")
    if not isinstance(path, str) or not path:
        return False, "Missing or invalid path"
    if has_dangerous_path(path):
        return False, "Unsafe path"
    if not path.startswith(prefix):
        return False, f"Path must start with {prefix}"
    return True, ""


def validate_mail_args(tool_args: dict[str, Any]) -> tuple[bool, str]:
    to = tool_args.get("to")
    subject = tool_args.get("subject")
    body = tool_args.get("body")
    if not isinstance(to, str) or not isinstance(subject, str) or not isinstance(body, str):
        return False, "Mail arguments must include string to, subject and body"
    if to not in ALLOWED_MAIL_RECIPIENTS:
        return False, f"Recipient is not allowed: {to}"
    if len(subject) > 200:
        return False, "Mail subject too long"
    if len(body) > 2000:
        return False, "Mail body too long"
    return True, ""


def validate_shell_args(tool_args: dict[str, Any]) -> tuple[bool, str]:
    command = tool_args.get("command")
    if not isinstance(command, str) or not command.strip():
        return False, "Missing or invalid command"
    lowered = f" {command.lower()} "
    if any(fragment in lowered for fragment in DANGEROUS_SHELL_FRAGMENTS):
        return False, "Command contains a dangerous fragment"
    try:
        parts = shlex.split(command)
    except ValueError:
        return False, "Command cannot be parsed safely"
    if not parts:
        return False, "Missing command"
    if parts[0] not in ALLOWED_SHELL_COMMANDS:
        return False, f"Command is not allowed: {parts[0]}"
    return True, ""


def validate_args(tool_name: str, tool_args: dict[str, Any], policy: dict[str, Any]) -> tuple[bool, str]:
    arg_policy = policy["arg_policy"]
    policy_type = arg_policy["type"]
    if policy_type == "file":
        return validate_file_args(tool_args, arg_policy["prefix"])
    if policy_type == "mail":
        return validate_mail_args(tool_args)
    if policy_type == "shell":
        return validate_shell_args(tool_args)
    return False, f"Unknown argument policy for {tool_name}"


def degradation_alternatives(policy: dict[str, Any]) -> list[dict[str, Any]]:
    degrade = policy.get("degrade")
    if degrade is None:
        return []
    degraded_tool = degrade["to_tool"]
    degraded_policy = TOOL_POLICIES.get(degraded_tool, {})
    return [
        {
            "tool_name": degraded_tool,
            "arguments": degrade["default_args"],
            "required_scopes": degraded_policy.get("required_scopes", []),
            "reason": degrade["reason"],
        }
    ]


class PolicyEngine:
    def try_degrade(
        self,
        req_id: Any,
        intent: dict[str, Any],
        claims: dict[str, Any],
        policy: dict[str, Any],
        trigger_check: str,
    ) -> dict[str, Any] | None:
        degrade = policy.get("degrade")
        if degrade is None or trigger_check not in degrade["on_checks"]:
            return None

        degraded_tool = degrade["to_tool"]
        degraded_policy = TOOL_POLICIES.get(degraded_tool)
        if degraded_policy is None or degraded_policy["requires_confirmation"]:
            return None

        token_scopes = set(claims.get("scope", "").split())
        missing_scopes = [scope for scope in degraded_policy["required_scopes"] if scope not in token_scopes]
        if missing_scopes:
            return None

        source_labels = [source.get("label") for source in intent["source_trace"]]
        if any(label not in ALLOWED_SOURCE_LABELS for label in source_labels):
            return None
        if any(label not in degraded_policy["allowed_sources"] for label in source_labels):
            return None

        degraded_args = dict(degrade["default_args"])
        ok, _reason = validate_args(degraded_tool, degraded_args, degraded_policy)
        if not ok:
            return None

        return {
            "decision": "degraded",
            "audit_id": audit_id("guard-degraded"),
            "intent": intent,
            "tool_name": degraded_tool,
            "original_tool": intent["tool_name"],
            "degraded_tool": degraded_tool,
            "degraded_args": degraded_args,
            "reason": degrade["reason"],
            "triggered_by_check": trigger_check,
            "forward_params": {
                "name": degraded_tool,
                "arguments": degraded_args,
            },
        }

    def evaluate(self, req_id: Any, params: dict[str, Any], claims: dict[str, Any]) -> dict[str, Any]:
        intent = normalize_intent(params, claims)

        # 1. Intent structure and session binding.
        ok, reason = validate_intent_shape(intent)
        tool_name = intent.get("tool_name")
        if not ok:
            return deny(req_id, reason, "intent_structure", tool_name)
        if intent["session_id"] != claims.get("session_id"):
            return deny(req_id, "Intent session_id does not match token session_id", "intent_session", tool_name)

        # 2. Tool existence.
        if tool_name not in TOOL_POLICIES:
            return deny(req_id, f"Unknown tool: {tool_name}", "tool_exists", tool_name)
        policy = TOOL_POLICIES[tool_name]

        # 3. Resource audience.
        if claims.get("aud") != AUDIENCE:
            return deny(req_id, "Token audience does not match MCP resource", "audience", tool_name)

        # 4. Scope.
        token_scopes = set(claims.get("scope", "").split())
        required_scopes = policy["required_scopes"]
        missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]
        if missing_scopes:
            degraded = self.try_degrade(req_id, intent, claims, policy, "scope")
            if degraded is not None:
                return degraded
            return scope_challenge(
                req_id,
                tool_name,
                required_scopes,
                missing_scopes,
                degradation_alternatives(policy),
            )

        # 5. Source trace.
        source_labels = [source.get("label") for source in intent["source_trace"]]
        unknown_labels = [label for label in source_labels if label not in ALLOWED_SOURCE_LABELS]
        if unknown_labels:
            return deny(req_id, f"Unknown source labels: {', '.join(unknown_labels)}", "source_trace", tool_name)
        disallowed_labels = [label for label in source_labels if label not in policy["allowed_sources"]]
        if disallowed_labels:
            degraded = self.try_degrade(req_id, intent, claims, policy, "source_trace")
            if degraded is not None:
                return degraded
            return deny(
                req_id,
                f"Source labels not allowed for {tool_name}: {', '.join(disallowed_labels)}",
                "source_trace",
                tool_name,
                degradation_alternatives(policy),
            )

        # 6. Arguments.
        ok, reason = validate_args(tool_name, intent["tool_args"], policy)
        if not ok:
            degraded = self.try_degrade(req_id, intent, claims, policy, "arguments")
            if degraded is not None:
                return degraded
            return deny(req_id, reason, "arguments", tool_name, degradation_alternatives(policy))

        # 7. User confirmation.
        if policy["requires_confirmation"]:
            supplied_hash = intent.get("confirmation_hash") or params.get("confirmation_hash")
            if not supplied_hash:
                issued_confirmation = CONFIRMATION_STORE.issue(intent)
                if not issued_confirmation["ok"]:
                    return deny(req_id, issued_confirmation["reason"], "confirmation", tool_name)
                return user_confirm(req_id, intent, issued_confirmation)

            verified_confirmation = CONFIRMATION_STORE.verify(intent, supplied_hash)
            if not verified_confirmation["ok"]:
                return deny(req_id, verified_confirmation["reason"], "confirmation", tool_name)

        # 8. Allow execution.
        return {
            "decision": "allow",
            "audit_id": audit_id("guard-allow"),
            "intent": intent,
            "tool_name": tool_name,
            "forward_params": {
                "name": tool_name,
                "arguments": intent["tool_args"],
            },
        }


policy_engine = PolicyEngine()


def forward_to_mcp(body: dict[str, Any], auth_header: str | None) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(MCP_SERVER_URL, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    if auth_header:
        request.add_header("Authorization", auth_header)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except json.JSONDecodeError:
            detail = {"detail": exc.reason}
        raise HTTPException(status_code=exc.code, detail=detail)
    except urllib.error.URLError as exc:
        raise HTTPException(status_code=502, detail=f"MCP server unavailable: {exc.reason}")


def merge_guard_trace(mcp_response: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    result = mcp_response.get("result")
    if isinstance(result, dict):
        guard_trace = {
            "decision": decision["decision"],
            "audit_id": decision["audit_id"],
            "tool_name": decision["tool_name"],
            "intent_id": decision["intent"]["intent_id"],
            "policy_checks": [
                "intent_structure",
                "tool_exists",
                "audience",
                "scope",
                "source_trace",
                "arguments",
                "confirmation",
            ],
        }
        if decision["decision"] == "degraded":
            guard_trace.update(
                {
                    "original_tool": decision["original_tool"],
                    "degraded_tool": decision["degraded_tool"],
                    "degraded_args": decision["degraded_args"],
                    "reason": decision["reason"],
                    "triggered_by_check": decision["triggered_by_check"],
                }
            )
            result["mcp_decision"] = result.get("decision")
            result["mcp_audit_id"] = result.get("audit_id")
            result["decision"] = "degraded"
            result["audit_id"] = decision["audit_id"]
            result["tool_name"] = decision["degraded_tool"]
            result["original_tool"] = decision["original_tool"]
            result["degraded_tool"] = decision["degraded_tool"]
            result["degraded_args"] = decision["degraded_args"]
            result["reason"] = decision["reason"]
            result["triggered_by_check"] = decision["triggered_by_check"]
        result["guard"] = {
            **guard_trace,
        }
    return mcp_response


@app.post("/mcp")
async def guard_mcp_endpoint(request: Request):
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")
    auth_header = request.headers.get("authorization")

    if method != "tools/call":
        return forward_to_mcp(body, auth_header)

    claims = decode_bearer_token(auth_header)
    if not isinstance(params, dict):
        response = deny(req_id, "Invalid params object", "intent_structure")
        log_decision(req_id, method, claims, {}, response["result"])
        return response

    intent_for_audit = normalize_intent(params, claims)
    log_intent(req_id, method, claims, intent_for_audit)
    decision = policy_engine.evaluate(req_id, params, claims)
    decision_result = decision["result"] if "jsonrpc" in decision else decision
    log_decision(req_id, method, claims, intent_for_audit, decision_result)
    if "jsonrpc" in decision:
        return decision
    if decision["decision"] not in {"allow", "degraded"}:
        return jsonrpc_result(req_id, decision)

    forwarded_body = {
        **body,
        "params": decision["forward_params"],
    }
    mcp_response = forward_to_mcp(forwarded_body, auth_header)
    merged_response = merge_guard_trace(mcp_response, decision)
    log_execution(req_id, method, claims, intent_for_audit, decision, merged_response)
    return merged_response


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "guard_proxy",
        "mcp_server_url": MCP_SERVER_URL,
        "auth_jwks_url": AUTH_JWKS_URL,
        "policy_config_path": str(POLICY_CONFIG["path"]),
        "audit_log_path": str(AUDIT_LOG_PATH),
        "confirmation_log_path": str(CONFIRMATION_STORE.path),
        "confirmation_ttl_seconds": CONFIRMATION_STORE.ttl_seconds,
    }


@app.get("/audit/recent")
async def audit_recent(limit: int = 50, intent_id: str | None = None, event_type: str | None = None):
    normalized_limit = normalize_audit_limit(limit)
    events = recent_audit_events(
        limit=normalized_limit,
        intent_id=intent_id,
        event_type=event_type,
        path=AUDIT_LOG_PATH,
    )
    return {
        "audit_log_path": str(AUDIT_LOG_PATH),
        "limit": normalized_limit,
        "intent_id": intent_id,
        "event_type": event_type,
        "count": len(events),
        "events": events,
    }


@app.get("/audit/intent/{intent_id}")
async def audit_by_intent(intent_id: str, limit: int = 100):
    normalized_limit = normalize_audit_limit(limit)
    events = audit_events_for_intent(intent_id, limit=normalized_limit, path=AUDIT_LOG_PATH)
    return {
        "audit_log_path": str(AUDIT_LOG_PATH),
        "intent_id": intent_id,
        "limit": normalized_limit,
        "count": len(events),
        "events": events,
    }


@app.get("/audit/{audit_id}")
async def audit_by_id(audit_id: str):
    trace = audit_trace_for_id(audit_id, path=AUDIT_LOG_PATH)
    if not trace["matches"]:
        raise HTTPException(status_code=404, detail=f"Audit id not found: {audit_id}")
    return {
        "audit_log_path": str(AUDIT_LOG_PATH),
        "audit_id": audit_id,
        "match_count": len(trace["matches"]),
        "related_count": len(trace["related_events"]),
        "matches": trace["matches"],
        "related_events": trace["related_events"],
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("GUARD_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("GUARD_PROXY_PORT", "8002"))
    uvicorn.run(app, host=host, port=port)
