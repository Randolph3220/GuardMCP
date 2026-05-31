from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_LOG_PATH = PROJECT_ROOT / "experiments" / "audit_log.jsonl"
AUDIT_LOG_PATH = Path(os.getenv("GUARD_AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH))
CLAIM_KEYS = ("iss", "sub", "aud", "scope", "jti", "session_id", "exp", "iat")


def compact_claims(claims: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(claims, dict):
        return {}
    return {key: claims[key] for key in CLAIM_KEYS if key in claims}


def compact_intent(intent: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(intent, dict):
        return {}
    return {
        "intent_id": intent.get("intent_id"),
        "session_id": intent.get("session_id"),
        "tool_name": intent.get("tool_name"),
        "tool_args": intent.get("tool_args"),
        "purpose": intent.get("purpose"),
        "source_trace": intent.get("source_trace"),
        "risk_ack": intent.get("risk_ack"),
        "confirmation_hash_present": bool(intent.get("confirmation_hash")),
    }


def compact_decision(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    keys = (
        "decision",
        "audit_id",
        "tool_name",
        "intent_id",
        "failed_check",
        "reason",
        "original_tool",
        "degraded_tool",
        "degraded_args",
        "triggered_by_check",
        "alternatives",
        "expires_at",
        "expires_in_seconds",
        "missing_scopes",
        "required_scopes",
        "resource_metadata_url",
        "isError",
    )
    return {key: result[key] for key in keys if key in result}


def compact_execution(mcp_response: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(mcp_response, dict):
        return {}
    result = mcp_response.get("result")
    if not isinstance(result, dict):
        return {"jsonrpc_error": mcp_response.get("error")}

    content = result.get("content")
    preview = ""
    if isinstance(content, list) and content:
        first = content[0]
        if isinstance(first, dict):
            preview = str(first.get("text", ""))[:240]

    return {
        "decision": result.get("decision"),
        "audit_id": result.get("audit_id"),
        "tool_name": result.get("tool_name"),
        "original_tool": result.get("original_tool"),
        "degraded_tool": result.get("degraded_tool"),
        "isError": result.get("isError"),
        "data": result.get("data"),
        "content_preview": preview,
    }


def append_audit_event(event_type: str, payload: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    record = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    target = path or AUDIT_LOG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def log_intent(req_id: Any, method: str, claims: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    return append_audit_event(
        "intent",
        {
            "request_id": req_id,
            "method": method,
            "claims": compact_claims(claims),
            "intent": compact_intent(intent),
        },
    )


def log_decision(req_id: Any, method: str, claims: dict[str, Any], intent: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return append_audit_event(
        "decision",
        {
            "request_id": req_id,
            "method": method,
            "claims": compact_claims(claims),
            "intent": compact_intent(intent),
            "decision": compact_decision(result),
        },
    )


def log_execution(
    req_id: Any,
    method: str,
    claims: dict[str, Any],
    intent: dict[str, Any],
    decision: dict[str, Any],
    mcp_response: dict[str, Any],
) -> dict[str, Any]:
    return append_audit_event(
        "execution",
        {
            "request_id": req_id,
            "method": method,
            "claims": compact_claims(claims),
            "intent": compact_intent(intent),
            "decision": compact_decision(decision),
            "execution": compact_execution(mcp_response),
        },
    )


def read_audit_events(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or AUDIT_LOG_PATH
    if not target.exists():
        return []

    records: list[dict[str, Any]] = []
    with target.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append({"line_number": line_number, **record})
    return records


def audit_event_intent_id(record: dict[str, Any]) -> str | None:
    intent = record.get("intent")
    if isinstance(intent, dict) and isinstance(intent.get("intent_id"), str):
        return intent["intent_id"]
    decision = record.get("decision")
    if isinstance(decision, dict) and isinstance(decision.get("intent_id"), str):
        return decision["intent_id"]
    return None


def audit_event_has_audit_id(value: Any, audit_id: str) -> bool:
    if isinstance(value, dict):
        if value.get("audit_id") == audit_id:
            return True
        return any(audit_event_has_audit_id(item, audit_id) for item in value.values())
    if isinstance(value, list):
        return any(audit_event_has_audit_id(item, audit_id) for item in value)
    return False


def filter_audit_events(
    records: list[dict[str, Any]],
    intent_id: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    filtered = records
    if intent_id:
        filtered = [record for record in filtered if audit_event_intent_id(record) == intent_id]
    if event_type:
        filtered = [record for record in filtered if record.get("event_type") == event_type]
    return filtered


def recent_audit_events(
    limit: int = 50,
    intent_id: str | None = None,
    event_type: str | None = None,
    path: Path | None = None,
) -> list[dict[str, Any]]:
    records = filter_audit_events(read_audit_events(path), intent_id, event_type)
    if limit <= 0:
        return []
    return list(reversed(records[-limit:]))


def audit_events_for_intent(intent_id: str, limit: int = 100, path: Path | None = None) -> list[dict[str, Any]]:
    return recent_audit_events(limit=limit, intent_id=intent_id, path=path)


def audit_trace_for_id(audit_id: str, path: Path | None = None) -> dict[str, Any]:
    records = read_audit_events(path)
    matches = [record for record in records if audit_event_has_audit_id(record, audit_id)]
    related_request_ids = {record.get("request_id") for record in matches if record.get("request_id") is not None}
    related_intent_ids = {
        intent_id
        for intent_id in (audit_event_intent_id(record) for record in matches)
        if intent_id is not None
    }
    related_events = [
        record
        for record in records
        if record.get("request_id") in related_request_ids
        or audit_event_intent_id(record) in related_intent_ids
    ]
    return {
        "matches": matches,
        "related_events": related_events,
    }
