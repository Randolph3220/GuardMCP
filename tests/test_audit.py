import asyncio
import json

import pytest
from fastapi import HTTPException

from guard_proxy import app as guard
from guard_proxy import audit


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_audit_events_write_jsonl(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", audit_path)
    claims = {
        "iss": "oauth-server",
        "sub": "alice",
        "aud": "mcp-resource",
        "scope": "tools.list files.read.public",
        "session_id": "session-test",
        "jti": "token-id",
    }
    intent = {
        "intent_id": "intent-audit",
        "session_id": "session-test",
        "tool_name": "files.read.public",
        "tool_args": {"path": "public/demo.txt"},
        "purpose": "pytest audit write",
        "source_trace": [{"source_id": "src-user", "label": "user"}],
        "risk_ack": False,
    }
    decision = {
        "decision": "allow",
        "audit_id": "guard-allow-test",
        "tool_name": "files.read.public",
    }
    mcp_response = {
        "jsonrpc": "2.0",
        "id": "req-audit",
        "result": {
            "decision": "allow",
            "audit_id": "mcp-allow-test",
            "tool_name": "files.read.public",
            "content": [{"type": "text", "text": "GuardMCP public demo file."}],
            "data": {"path": "public/demo.txt"},
            "isError": False,
        },
    }

    audit.log_intent("req-audit", "tools/call", claims, intent)
    audit.log_decision("req-audit", "tools/call", claims, intent, decision)
    audit.log_execution("req-audit", "tools/call", claims, intent, decision, mcp_response)

    records = read_jsonl(audit_path)
    assert [record["event_type"] for record in records] == ["intent", "decision", "execution"]
    assert records[0]["claims"]["sub"] == "alice"
    assert records[1]["decision"]["decision"] == "allow"
    assert records[2]["execution"]["content_preview"] == "GuardMCP public demo file."


def test_compact_intent_does_not_store_confirmation_hash():
    compact = audit.compact_intent(
        {
            "intent_id": "intent-confirm",
            "session_id": "session-test",
            "tool_name": "mail.send",
            "tool_args": {"to": "alice@example.com"},
            "purpose": "pytest",
            "source_trace": [{"source_id": "src-user", "label": "user"}],
            "risk_ack": True,
            "confirmation_hash": "sha256:secret",
        }
    )

    assert "confirmation_hash" not in compact
    assert compact["confirmation_hash_present"] is True


def write_query_fixture(path):
    audit.append_audit_event(
        "intent",
        {
            "request_id": "req-a",
            "method": "tools/call",
            "claims": {"sub": "alice"},
            "intent": {"intent_id": "intent-a", "tool_name": "files.read.public"},
        },
        path=path,
    )
    audit.append_audit_event(
        "decision",
        {
            "request_id": "req-a",
            "method": "tools/call",
            "claims": {"sub": "alice"},
            "intent": {"intent_id": "intent-a", "tool_name": "files.read.public"},
            "decision": {"decision": "allow", "audit_id": "guard-allow-a"},
        },
        path=path,
    )
    audit.append_audit_event(
        "execution",
        {
            "request_id": "req-a",
            "method": "tools/call",
            "claims": {"sub": "alice"},
            "intent": {"intent_id": "intent-a", "tool_name": "files.read.public"},
            "decision": {"decision": "allow", "audit_id": "guard-allow-a"},
            "execution": {"decision": "allow", "audit_id": "mcp-allow-a"},
        },
        path=path,
    )
    audit.append_audit_event(
        "decision",
        {
            "request_id": "req-b",
            "method": "tools/call",
            "claims": {"sub": "alice"},
            "intent": {"intent_id": "intent-b", "tool_name": "mail.send"},
            "decision": {"decision": "user_confirm", "audit_id": "guard-confirm-b"},
        },
        path=path,
    )


def test_audit_query_helpers_read_recent_intent_and_audit_id(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    write_query_fixture(audit_path)

    recent = audit.recent_audit_events(limit=2, path=audit_path)
    assert [record["request_id"] for record in recent] == ["req-b", "req-a"]
    assert [record["line_number"] for record in recent] == [4, 3]

    intent_events = audit.audit_events_for_intent("intent-a", path=audit_path)
    assert [record["event_type"] for record in intent_events] == ["execution", "decision", "intent"]

    trace = audit.audit_trace_for_id("guard-allow-a", path=audit_path)
    assert len(trace["matches"]) == 2
    assert [record["event_type"] for record in trace["related_events"]] == ["intent", "decision", "execution"]


def test_audit_query_endpoints_use_jsonl_store(tmp_path, monkeypatch):
    audit_path = tmp_path / "audit.jsonl"
    write_query_fixture(audit_path)
    monkeypatch.setattr(guard, "AUDIT_LOG_PATH", audit_path)

    recent = asyncio.run(guard.audit_recent(limit=10, intent_id="intent-a", event_type=None))
    assert recent["count"] == 3
    assert recent["events"][0]["event_type"] == "execution"

    by_intent = asyncio.run(guard.audit_by_intent("intent-b", limit=10))
    assert by_intent["count"] == 1
    assert by_intent["events"][0]["decision"]["audit_id"] == "guard-confirm-b"

    by_id = asyncio.run(guard.audit_by_id("mcp-allow-a"))
    assert by_id["match_count"] == 1
    assert by_id["related_count"] == 3

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(guard.audit_by_id("missing-audit-id"))
    assert exc_info.value.status_code == 404
