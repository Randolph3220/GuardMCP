from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIRMATION_LOG_PATH = PROJECT_ROOT / "experiments" / "confirmations.jsonl"
DEFAULT_CONFIRMATION_TTL_SECONDS = 300


def utc_now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def intent_fingerprint(intent: dict[str, Any]) -> str:
    payload = {
        "session_id": intent["session_id"],
        "intent_id": intent["intent_id"],
        "tool_name": intent["tool_name"],
        "tool_args": intent["tool_args"],
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def new_confirmation_hash(intent: dict[str, Any]) -> str:
    payload = {
        "intent_fingerprint": intent_fingerprint(intent),
        "nonce": str(uuid.uuid4()),
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class ConfirmationStore:
    def __init__(
        self,
        path: str | Path | None = None,
        ttl_seconds: int | None = None,
        now_fn: Callable[[], float] | None = None,
    ):
        self.path = Path(path or os.getenv("GUARD_CONFIRMATION_LOG_PATH", DEFAULT_CONFIRMATION_LOG_PATH))
        self.ttl_seconds = int(
            ttl_seconds
            if ttl_seconds is not None
            else os.getenv("GUARD_CONFIRMATION_TTL_SECONDS", str(DEFAULT_CONFIRMATION_TTL_SECONDS))
        )
        self.now_fn = now_fn or time.time

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def _append(self, record: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return record

    def _event(
        self,
        event_type: str,
        intent: dict[str, Any],
        confirmation_hash: str | None = None,
        reason: str | None = None,
        expires_at: float | None = None,
    ) -> dict[str, Any]:
        now = self.now_fn()
        record = {
            "event_type": event_type,
            "timestamp": utc_now_iso(now),
            "session_id": intent["session_id"],
            "intent_id": intent["intent_id"],
            "tool_name": intent["tool_name"],
            "intent_fingerprint": intent_fingerprint(intent),
        }
        if confirmation_hash is not None:
            record["confirmation_hash"] = confirmation_hash
        if expires_at is not None:
            record["expires_at"] = expires_at
            record["expires_at_iso"] = utc_now_iso(expires_at)
        if reason:
            record["reason"] = reason
        return record

    def _records_for(self, session_id: str, intent_id: str) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        records: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("session_id") == session_id and record.get("intent_id") == intent_id:
                    records.append(record)
        return records

    def state_for(self, session_id: str, intent_id: str) -> dict[str, Any] | None:
        state: dict[str, Any] | None = None
        for record in self._records_for(session_id, intent_id):
            event_type = record.get("event_type")
            if event_type == "issued":
                state = {
                    "confirmation_hash": record.get("confirmation_hash"),
                    "intent_fingerprint": record.get("intent_fingerprint"),
                    "tool_name": record.get("tool_name"),
                    "expires_at": float(record.get("expires_at", 0)),
                    "used": False,
                    "used_at": None,
                }
            elif event_type == "used" and state is not None:
                if record.get("confirmation_hash") == state.get("confirmation_hash"):
                    state["used"] = True
                    state["used_at"] = record.get("timestamp")
        return state

    def issue(self, intent: dict[str, Any]) -> dict[str, Any]:
        now = self.now_fn()
        current_fingerprint = intent_fingerprint(intent)
        state = self.state_for(intent["session_id"], intent["intent_id"])
        if state is not None:
            if state["used"]:
                return {
                    "ok": False,
                    "status": "used",
                    "reason": "Confirmation has already been used; create a new intent_id.",
                }
            if state["intent_fingerprint"] != current_fingerprint:
                return {
                    "ok": False,
                    "status": "mismatch",
                    "reason": "A confirmation is already pending for a different tool call.",
                }
            if state["expires_at"] > now:
                return {
                    "ok": True,
                    "status": "pending",
                    "confirmation_hash": state["confirmation_hash"],
                    "expires_at": state["expires_at"],
                    "expires_at_iso": utc_now_iso(state["expires_at"]),
                    "expires_in_seconds": max(0, int(state["expires_at"] - now)),
                }

        confirmation_hash = new_confirmation_hash(intent)
        expires_at = now + self.ttl_seconds
        self._append(self._event("issued", intent, confirmation_hash, expires_at=expires_at))
        return {
            "ok": True,
            "status": "issued",
            "confirmation_hash": confirmation_hash,
            "expires_at": expires_at,
            "expires_at_iso": utc_now_iso(expires_at),
            "expires_in_seconds": self.ttl_seconds,
        }

    def verify(self, intent: dict[str, Any], supplied_hash: str) -> dict[str, Any]:
        state = self.state_for(intent["session_id"], intent["intent_id"])
        if state is None:
            self._append(self._event("replay", intent, supplied_hash, reason="no_pending_confirmation"))
            return {"ok": False, "status": "missing", "reason": "No pending confirmation for this intent"}

        current_fingerprint = intent_fingerprint(intent)
        if state["intent_fingerprint"] != current_fingerprint:
            self._append(self._event("mismatch", intent, supplied_hash, reason="intent_fingerprint_mismatch"))
            return {
                "ok": False,
                "status": "mismatch",
                "reason": "Confirmation hash does not match this tool call",
            }

        if state["expires_at"] <= self.now_fn():
            self._append(self._event("expired", intent, supplied_hash, reason="confirmation_expired"))
            return {"ok": False, "status": "expired", "reason": "Confirmation has expired"}

        if state["used"]:
            self._append(self._event("replay", intent, supplied_hash, reason="confirmation_replay"))
            return {"ok": False, "status": "replay", "reason": "Confirmation has already been used"}

        if supplied_hash != state["confirmation_hash"]:
            self._append(self._event("mismatch", intent, supplied_hash, reason="hash_mismatch"))
            return {
                "ok": False,
                "status": "mismatch",
                "reason": "Confirmation hash does not match this tool call",
            }

        self._append(self._event("used", intent, supplied_hash))
        return {"ok": True, "status": "used"}
