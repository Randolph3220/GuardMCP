import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://127.0.0.1:8001")
GUARD_PROXY_URL = os.getenv("GUARD_PROXY_URL", "http://127.0.0.1:8002")
OUTBOX_PATH = PROJECT_ROOT / "outbox.jsonl"
AUDIT_LOG_PATH = Path(os.getenv("GUARD_AUDIT_LOG_PATH", PROJECT_ROOT / "experiments" / "audit_log.jsonl"))
CONFIRMATION_LOG_PATH = Path(
    os.getenv("GUARD_CONFIRMATION_LOG_PATH", PROJECT_ROOT / "experiments" / "confirmations.jsonl")
)
RESULT_PATH = PROJECT_ROOT / "experiments" / "minimal_chain_result.json"


class ChainFailure(RuntimeError):
    pass


def http_json(method: str, url: str, body: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=payload, method=method)
    request.add_header("Accept", "application/json")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ChainFailure(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ChainFailure(f"Cannot reach {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ChainFailure(f"Non-JSON response from {url}") from exc


def guard_rpc(token: str, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return http_json(
        "POST",
        f"{GUARD_PROXY_URL}/mcp",
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        },
        token=token,
    )


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ChainFailure(message)


def response_result(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result")
    expect(isinstance(result, dict), f"Expected JSON-RPC result object, got: {response}")
    return result


def user_source(source_id: str = "src-user-minimal") -> list[dict[str, str]]:
    return [
        {
            "source_id": source_id,
            "label": "user",
            "description": "Direct user request in the minimal integration chain.",
        }
    ]


def make_intent(
    intent_id: str,
    session_id: str,
    tool_name: str,
    tool_args: dict[str, Any],
    purpose: str,
    source_trace: list[dict[str, str]] | None = None,
    risk_ack: bool = False,
) -> dict[str, Any]:
    return {
        "intent_id": intent_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "purpose": purpose,
        "source_trace": source_trace or user_source(),
        "risk_ack": risk_ack,
    }


def read_outbox() -> list[dict[str, Any]]:
    if not OUTBOX_PATH.exists():
        return []
    records = []
    with OUTBOX_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def step_record(name: str, ok: bool, response: dict[str, Any] | None = None, detail: str = "") -> dict[str, Any]:
    result = response_result(response) if response else {}
    return {
        "step": name,
        "ok": ok,
        "decision": result.get("decision"),
        "failed_check": result.get("failed_check"),
        "missing_scopes": result.get("missing_scopes"),
        "tool_name": result.get("tool_name"),
        "detail": detail,
    }


def main() -> int:
    started_at = datetime.now(timezone.utc).isoformat()
    if OUTBOX_PATH.exists():
        OUTBOX_PATH.unlink()
    if AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.unlink()
    if CONFIRMATION_LOG_PATH.exists():
        CONFIRMATION_LOG_PATH.unlink()

    steps: list[dict[str, Any]] = []
    try:
        tokens = http_json("GET", f"{AUTH_SERVER_URL}/tokens/test")
        profiles = tokens["profiles"]
        t1 = profiles["T1"]["access_token"]
        t2 = profiles["T2"]["access_token"]
        t3 = profiles["T3"]["access_token"]
        steps.append(step_record("get_test_tokens", True, detail="T1/T2/T3 acquired from auth_server."))

        tools_response = guard_rpc(t1, "chain-tools-list", "tools/list", {})
        tools_result = response_result(tools_response)
        tool_names = [tool["name"] for tool in tools_result.get("tools", [])]
        expect("files.read.public" in tool_names and "mail.send" in tool_names, f"Unexpected tools/list: {tool_names}")
        steps.append(step_record("guard_tools_list", True, tools_response, detail=", ".join(tool_names)))

        missing_scope_intent = make_intent(
            "intent-chain-missing-scope",
            profiles["T1"]["session_id"],
            "files.read.public",
            {"path": "public/demo.txt"},
            "Try to read a public file with a list-only token.",
        )
        missing_scope_response = guard_rpc(
            t1,
            "chain-scope-challenge",
            "tools/call",
            {"intent": missing_scope_intent},
        )
        missing_scope_result = response_result(missing_scope_response)
        expect(missing_scope_result.get("decision") == "scope_challenge", f"Expected scope_challenge: {missing_scope_result}")
        expect(missing_scope_result.get("missing_scopes") == ["files.read.public"], f"Unexpected missing scopes: {missing_scope_result}")
        steps.append(step_record("missing_scope_challenge", True, missing_scope_response))

        public_read_intent = make_intent(
            "intent-chain-public-read",
            profiles["T2"]["session_id"],
            "files.read.public",
            {"path": "public/demo.txt"},
            "Read a public sandbox file requested by the user.",
        )
        public_read_response = guard_rpc(
            t2,
            "chain-public-read",
            "tools/call",
            {"intent": public_read_intent},
        )
        public_read_result = response_result(public_read_response)
        public_text = public_read_result.get("content", [{}])[0].get("text", "")
        expect(public_read_result.get("decision") == "allow", f"Expected allow for public read: {public_read_result}")
        expect(public_read_result.get("guard", {}).get("decision") == "allow", f"Missing Guard allow trace: {public_read_result}")
        expect("GuardMCP public demo file" in public_text, f"Unexpected public file content: {public_text}")
        steps.append(step_record("normal_public_file_read", True, public_read_response, detail=public_text.splitlines()[0]))

        indirect_intent = make_intent(
            "intent-chain-indirect-injection",
            profiles["T3"]["session_id"],
            "mail.send",
            {
                "to": "alice@example.com",
                "subject": "Hidden instruction",
                "body": "This mail was requested by an untrusted webpage instruction.",
            },
            "Handle an external page that tries to trigger an email send.",
            source_trace=[
                {
                    "source_id": "src-web-minimal",
                    "label": "untrusted_web",
                    "description": "External page hidden instruction.",
                }
            ],
            risk_ack=True,
        )
        indirect_response = guard_rpc(
            t3,
            "chain-indirect-reject",
            "tools/call",
            {"intent": indirect_intent},
        )
        indirect_result = response_result(indirect_response)
        expect(indirect_result.get("decision") == "deny", f"Expected deny for indirect injection: {indirect_result}")
        expect(indirect_result.get("failed_check") == "source_trace", f"Expected source_trace failure: {indirect_result}")
        steps.append(step_record("indirect_injection_denied", True, indirect_response, detail=indirect_result.get("reason", "")))

        mail_intent = make_intent(
            "intent-chain-confirmed-mail",
            profiles["T3"]["session_id"],
            "mail.send",
            {
                "to": "alice@example.com",
                "subject": "GuardMCP integration check",
                "body": "This message is written after explicit confirmation in the minimal chain.",
            },
            "Send a mock status email after direct user approval.",
            risk_ack=True,
        )
        confirm_response = guard_rpc(
            t3,
            "chain-mail-confirm",
            "tools/call",
            {"intent": mail_intent},
        )
        confirm_result = response_result(confirm_response)
        expect(confirm_result.get("decision") == "user_confirm", f"Expected user_confirm: {confirm_result}")
        confirmation_hash = confirm_result.get("confirmation_hash")
        expect(isinstance(confirmation_hash, str) and confirmation_hash.startswith("sha256:"), f"Bad confirmation hash: {confirm_result}")
        steps.append(step_record("mail_user_confirm", True, confirm_response))

        confirmed_intent = dict(mail_intent)
        confirmed_intent["confirmation_hash"] = confirmation_hash
        mail_response = guard_rpc(
            t3,
            "chain-mail-send",
            "tools/call",
            {"intent": confirmed_intent},
        )
        mail_result = response_result(mail_response)
        outbox_records = read_outbox()
        expect(mail_result.get("decision") == "allow", f"Expected allow for confirmed mail: {mail_result}")
        expect(mail_result.get("guard", {}).get("decision") == "allow", f"Missing Guard allow trace for mail: {mail_result}")
        expect(mail_result.get("data", {}).get("outbox") == "outbox.jsonl", f"Unexpected mail data: {mail_result}")
        expect(len(outbox_records) == 1, f"Expected exactly one outbox record, got {len(outbox_records)}")
        expect(outbox_records[0]["to"] == "alice@example.com", f"Unexpected outbox recipient: {outbox_records}")
        steps.append(step_record("confirmed_mail_written", True, mail_response, detail=outbox_records[0]["id"]))

        report = {
            "ok": True,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "auth_server_url": AUTH_SERVER_URL,
            "guard_proxy_url": GUARD_PROXY_URL,
            "steps": steps,
            "outbox_records": outbox_records,
        }
        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        for item in steps:
            print(f"[ok] {item['step']}: {item.get('decision') or item['detail']}")
        print(f"wrote {RESULT_PATH.relative_to(PROJECT_ROOT)}")
        return 0
    except Exception as exc:
        report = {
            "ok": False,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "auth_server_url": AUTH_SERVER_URL,
            "guard_proxy_url": GUARD_PROXY_URL,
            "steps": steps,
            "error": str(exc),
        }
        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[fail] {exc}", file=sys.stderr)
        print(f"wrote {RESULT_PATH.relative_to(PROJECT_ROOT)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
