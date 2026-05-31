from __future__ import annotations

import json
import shlex
import subprocess
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, Any, List
import jwt
import uuid

app = FastAPI(title="MCP-like Server")
security = HTTPBearer()

ALGORITHM = "RS256"
ISSUER = "oauth-server"
AUDIENCE = "mcp-resource"
AUTHORIZATION_SERVER = "http://localhost:8001"
AUTH_JWKS_URL = os.getenv("AUTH_JWKS_URL", "http://localhost:8001/.well-known/jwks.json")
JWKS_CACHE_SECONDS = int(os.getenv("MCP_JWKS_CACHE_SECONDS", "300"))
MCP_SERVER_BASE_URL = "http://localhost:8000"
RESOURCE_METADATA_URL = f"{MCP_SERVER_BASE_URL}/.well-known/oauth-protected-resource"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_ROOT = PROJECT_ROOT / "sandbox"
PUBLIC_ROOT = SANDBOX_ROOT / "public"
SENSITIVE_ROOT = SANDBOX_ROOT / "sensitive"
OUTBOX_PATH = PROJECT_ROOT / "outbox.jsonl"
SHELL_TIMEOUT_SECONDS = 2
MAX_OUTPUT_CHARS = 4000

ALLOWED_SHELL_COMMANDS = {"pwd", "ls", "cat", "head", "tail", "wc"}
DANGEROUS_SHELL_FRAGMENTS = [
    "&&",
    "||",
    "|",
    ";",
    "`",
    "$(",
    ">",
    "<",
    "rm ",
    "curl",
    "wget",
    "ssh",
    "sudo",
    "chmod",
    "chown",
    "python",
]
JWKS_CACHE: dict[str, Any] = {"expires_at": 0.0, "keys": {}}

SUPPORTED_SCOPES = [
    "tools.list",
    "files.read.public",
    "files.read.sensitive",
    "mail.send",
    "shell.exec",
]

TOOL_SCOPES = {
    "tools/list": ["tools.list"],
    "files.read.public": ["files.read.public"],
    "files.read.sensitive": ["files.read.sensitive"],
    "mail.send": ["mail.send"],
    "shell.exec": ["shell.exec"]
}


class ToolSchema(BaseModel):
    type: str = "object"
    properties: Dict[str, Any]
    required: List[str] = Field(default_factory=list)


class Tool(BaseModel):
    name: str
    description: str
    inputSchema: ToolSchema


TOOLS = [
    Tool(
        name="files.read.public",
        description="Read a public file from sandbox/public",
        inputSchema=ToolSchema(
            properties={
                "path": {
                    "type": "string",
                    "description": "Path under sandbox/public"
                }
            },
            required=["path"]
        )
    ),
    Tool(
        name="files.read.sensitive",
        description="Read a sensitive file from sandbox/sensitive",
        inputSchema=ToolSchema(
            properties={
                "path": {
                    "type": "string",
                    "description": "Path under sandbox/sensitive"
                }
            },
            required=["path"]
        )
    ),
    Tool(
        name="mail.send",
        description="Send an email",
        inputSchema=ToolSchema(
            properties={
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"}
            },
            required=["to", "subject", "body"]
        )
    ),
    Tool(
        name="shell.exec",
        description="Execute a shell command",
        inputSchema=ToolSchema(
            properties={"command": {"type": "string"}},
            required=["command"]
        )
    )
]

TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}


def truncate_text(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n[output truncated]", True


def tool_success(tool_name: str, data: dict[str, Any], text: str):
    return {
        "decision": "allow",
        "audit_id": trace_id("mcp-allow"),
        "tool_name": tool_name,
        "content": [{"type": "text", "text": text}],
        "data": data,
        "isError": False,
    }


def tool_error(tool_name: str, reason: str, data: dict[str, Any] | None = None):
    return {
        "decision": "allow",
        "audit_id": trace_id("mcp-tool-error"),
        "tool_name": tool_name,
        "content": [{"type": "text", "text": reason}],
        "data": data or {},
        "isError": True,
    }


def ensure_runtime_dirs():
    PUBLIC_ROOT.mkdir(parents=True, exist_ok=True)
    SENSITIVE_ROOT.mkdir(parents=True, exist_ok=True)


def resolve_sandbox_path(path_value: Any, allowed_root: Path) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError("Missing or invalid path")
    if "\x00" in path_value or path_value.startswith("/") or path_value.startswith("~") or "\\" in path_value:
        raise ValueError("Unsafe path")
    requested = (SANDBOX_ROOT / path_value).resolve()
    allowed = allowed_root.resolve()
    try:
        requested.relative_to(allowed)
    except ValueError:
        raise ValueError("Path escapes the allowed sandbox area")
    if not requested.is_file():
        raise FileNotFoundError(f"File not found: {path_value}")
    return requested


def execute_file_read(tool_name: str, args: dict[str, Any]):
    allowed_root = PUBLIC_ROOT if tool_name == "files.read.public" else SENSITIVE_ROOT
    try:
        target = resolve_sandbox_path(args.get("path"), allowed_root)
        content = target.read_text(encoding="utf-8", errors="replace")
    except (ValueError, FileNotFoundError, OSError) as exc:
        return tool_error(tool_name, str(exc))
    content, truncated = truncate_text(content)
    relative_path = target.relative_to(SANDBOX_ROOT).as_posix()
    return tool_success(
        tool_name,
        {
            "path": relative_path,
            "bytes": target.stat().st_size,
            "truncated": truncated,
        },
        content,
    )


def execute_mail_send(tool_name: str, args: dict[str, Any]):
    to = args.get("to")
    subject = args.get("subject")
    body = args.get("body")
    if not isinstance(to, str) or not isinstance(subject, str) or not isinstance(body, str):
        return tool_error(tool_name, "Mail arguments must include string to, subject and body")

    record = {
        "id": trace_id("mail"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "to": to,
        "subject": subject,
        "body": body,
    }
    with OUTBOX_PATH.open("a", encoding="utf-8") as outbox:
        outbox.write(json.dumps(record, ensure_ascii=False) + "\n")
    return tool_success(
        tool_name,
        {
            "outbox": OUTBOX_PATH.name,
            "message_id": record["id"],
            "to": to,
        },
        f"Mock mail written to {OUTBOX_PATH.name}: {record['id']}",
    )


def shell_arg_is_safe(arg: str) -> bool:
    if arg.startswith("-"):
        return True
    if arg.startswith("/") or arg.startswith("~") or "\\" in arg or "\x00" in arg:
        return False
    candidate = (SANDBOX_ROOT / arg).resolve()
    try:
        candidate.relative_to(SANDBOX_ROOT.resolve())
    except ValueError:
        return False
    return True


def parse_safe_shell_command(command: Any) -> list[str]:
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Missing or invalid command")
    lowered = f" {command.lower()} "
    if any(fragment in lowered for fragment in DANGEROUS_SHELL_FRAGMENTS):
        raise ValueError("Command contains a dangerous fragment")
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"Command cannot be parsed safely: {exc}")
    if not parts:
        raise ValueError("Missing command")
    if parts[0] not in ALLOWED_SHELL_COMMANDS:
        raise ValueError(f"Command is not allowed: {parts[0]}")
    unsafe_args = [arg for arg in parts[1:] if not shell_arg_is_safe(arg)]
    if unsafe_args:
        raise ValueError(f"Command contains unsafe path arguments: {', '.join(unsafe_args)}")
    return parts


def execute_shell_command(tool_name: str, args: dict[str, Any]):
    try:
        command = parse_safe_shell_command(args.get("command"))
        completed = subprocess.run(
            command,
            cwd=SANDBOX_ROOT,
            env={"PATH": "/bin:/usr/bin"},
            text=True,
            capture_output=True,
            timeout=SHELL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return tool_error(
            tool_name,
            f"Command timed out after {SHELL_TIMEOUT_SECONDS} seconds",
            {"timeout_seconds": SHELL_TIMEOUT_SECONDS},
        )
    except (ValueError, OSError) as exc:
        return tool_error(tool_name, str(exc))

    stdout, stdout_truncated = truncate_text(completed.stdout)
    stderr, stderr_truncated = truncate_text(completed.stderr)
    text = stdout or stderr or f"Command exited with code {completed.returncode}"
    return {
        "decision": "allow",
        "audit_id": trace_id("mcp-allow"),
        "tool_name": tool_name,
        "content": [{"type": "text", "text": text}],
        "data": {
            "command": command,
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "timeout_seconds": SHELL_TIMEOUT_SECONDS,
        },
        "isError": completed.returncode != 0,
    }


def execute_tool(tool_name: str, args: dict[str, Any]):
    ensure_runtime_dirs()
    if tool_name in {"files.read.public", "files.read.sensitive"}:
        return execute_file_read(tool_name, args)
    if tool_name == "mail.send":
        return execute_mail_send(tool_name, args)
    if tool_name == "shell.exec":
        return execute_shell_command(tool_name, args)
    return tool_error(tool_name, f"Tool runtime not implemented: {tool_name}")


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
    except (urllib.error.URLError, json.JSONDecodeError):
        if JWKS_CACHE["keys"]:
            return JWKS_CACHE["keys"]
        raise HTTPException(status_code=401, detail="JWKS discovery failed")

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
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token header")
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


# Token 校验
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # 校验 token 并返回 payload
    token = credentials.credentials
    try:
        public_key = public_key_for_token(token)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def missing_scopes(payload: dict, required_scopes: List[str]) -> List[str]:
    token_scopes = set(payload.get("scope", "").split())
    return [scope for scope in required_scopes if scope not in token_scopes]


def trace_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "result": result, "id": req_id}


def scope_challenge(req_id: Any, tool_name: str, required_scopes: List[str], missing: List[str]):
    return jsonrpc_result(
        req_id,
        {
            "decision": "scope_challenge",
            "audit_id": trace_id("mcp-challenge"),
            "tool_name": tool_name,
            "required_scopes": required_scopes,
            "missing_scopes": missing,
            "resource_metadata_url": RESOURCE_METADATA_URL,
            "message": f"Token is valid but lacks the required scope for {tool_name}.",
            "isError": True,
        },
    )


def deny_result(req_id: Any, reason: str, failed_check: str, tool_name: str | None = None):
    return jsonrpc_result(
        req_id,
        {
            "decision": "deny",
            "audit_id": trace_id("mcp-deny"),
            "tool_name": tool_name,
            "reason": reason,
            "failed_check": failed_check,
            "isError": True,
        },
    )


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return {
        "resource": AUDIENCE,
        "resource_name": "GuardMCP MCP-like resource server",
        "authorization_servers": [AUTHORIZATION_SERVER],
        "jwks_uri": AUTH_JWKS_URL,
        "bearer_methods_supported": ["header"],
        "mcp_endpoint": f"{MCP_SERVER_BASE_URL}/mcp",
        "scopes_supported": SUPPORTED_SCOPES,
        "tools": [
            {"name": name, "required_scopes": scopes}
            for name, scopes in TOOL_SCOPES.items()
        ],
    }


# MCP JSON-RPC 入口
@app.post("/mcp")
async def mcp_endpoint(request: Request, token_payload: dict = Depends(verify_token)):
    # MCP 主入口，所有请求都需要 token
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")

    # initialize 只需要有效 token；tools/list 还需要 tools.list scope。
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "guardmcp", "version": "0.1"}
        }
    elif method == "tools/list":
        required_scopes = TOOL_SCOPES["tools/list"]
        missing = missing_scopes(token_payload, required_scopes)
        if missing:
            return scope_challenge(req_id, "tools/list", required_scopes, missing)
        result = {"tools": [t.model_dump() for t in TOOLS]}
    elif method == "tools/call":
        # 检查 scope
        tool_name = params.get("name")
        if not tool_name:
            return deny_result(req_id, "Missing params.name", "tool_exists")
        if tool_name not in TOOLS_BY_NAME:
            return deny_result(req_id, f"Unknown tool: {tool_name}", "tool_exists", tool_name)

        required_scopes = TOOL_SCOPES[tool_name]
        missing = missing_scopes(token_payload, required_scopes)
        if missing:
            return scope_challenge(req_id, tool_name, required_scopes, missing)

        # scope 足够，执行 mock 工具运行时。
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return deny_result(req_id, "Invalid params.arguments", "arguments", tool_name)
        result = execute_tool(tool_name, args)
    else:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": f"Method not found: {method}"},
            "id": req_id
        }

    return {"jsonrpc": "2.0", "result": result, "id": req_id}


@app.get("/health")
async def health():
    return {"status": "ok", "auth_jwks_url": AUTH_JWKS_URL}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
