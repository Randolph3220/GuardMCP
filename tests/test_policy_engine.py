from auth_server.app import build_access_token
from guard_proxy import app as guard
from guard_proxy.confirmations import ConfirmationStore


def claims_for(scopes: list[str], session_id: str = "session-test") -> dict:
    _token, payload = build_access_token("alice", session_id, scopes)
    return payload


def intent_for(
    tool_name: str,
    tool_args: dict,
    session_id: str = "session-test",
    source_label: str = "user",
    intent_id: str = "intent-test",
) -> dict:
    return {
        "intent_id": intent_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "tool_args": tool_args,
        "purpose": "pytest policy engine check",
        "source_trace": [
            {
                "source_id": f"src-{source_label}",
                "label": source_label,
                "description": "pytest source",
            }
        ],
        "risk_ack": False,
    }


def result_of(decision: dict) -> dict:
    return decision["result"] if "jsonrpc" in decision else decision


def setup_function():
    guard.CONFIRMATION_STORE.clear()


def test_missing_scope_returns_scope_challenge():
    claims = claims_for(["tools.list"])
    intent = intent_for("files.read.public", {"path": "public/demo.txt"})

    result = result_of(guard.policy_engine.evaluate("req-scope", {"intent": intent}, claims))

    assert result["decision"] == "scope_challenge"
    assert result["tool_name"] == "files.read.public"
    assert result["missing_scopes"] == ["files.read.public"]


def test_untrusted_source_denies_high_risk_mail():
    claims = claims_for(["tools.list", "mail.send"])
    intent = intent_for(
        "mail.send",
        {"to": "alice@example.com", "subject": "Hidden", "body": "Injected instruction."},
        source_label="untrusted_web",
    )

    result = result_of(guard.policy_engine.evaluate("req-source", {"intent": intent}, claims))

    assert result["decision"] == "deny"
    assert result["failed_check"] == "source_trace"
    assert "untrusted_web" in result["reason"]


def test_public_file_intent_allows_forwarding():
    claims = claims_for(["tools.list", "files.read.public"])
    intent = intent_for("files.read.public", {"path": "public/demo.txt"})

    result = result_of(guard.policy_engine.evaluate("req-allow", {"intent": intent}, claims))

    assert result["decision"] == "allow"
    assert result["forward_params"] == {
        "name": "files.read.public",
        "arguments": {"path": "public/demo.txt"},
    }


def test_sensitive_file_can_degrade_to_public_when_sensitive_scope_is_missing():
    claims = claims_for(["tools.list", "files.read.public"])
    intent = intent_for("files.read.sensitive", {"path": "sensitive/secret.txt"})

    result = result_of(guard.policy_engine.evaluate("req-degrade", {"intent": intent}, claims))

    assert result["decision"] == "degraded"
    assert result["original_tool"] == "files.read.sensitive"
    assert result["degraded_tool"] == "files.read.public"
    assert result["triggered_by_check"] == "scope"
    assert result["forward_params"] == {
        "name": "files.read.public",
        "arguments": {"path": "public/demo.txt"},
    }


def test_sensitive_file_returns_alternative_when_degrade_scope_is_missing():
    claims = claims_for(["tools.list"])
    intent = intent_for("files.read.sensitive", {"path": "sensitive/secret.txt"})

    result = result_of(guard.policy_engine.evaluate("req-degrade-suggest", {"intent": intent}, claims))

    assert result["decision"] == "scope_challenge"
    assert result["missing_scopes"] == ["files.read.sensitive"]
    assert result["alternatives"] == [
        {
            "tool_name": "files.read.public",
            "arguments": {"path": "public/demo.txt"},
            "required_scopes": ["files.read.public"],
            "reason": "Sensitive file access is not available for this request; returning the safe public demo file instead.",
        }
    ]


def test_sensitive_file_can_degrade_when_arguments_match_public_file():
    claims = claims_for(["tools.list", "files.read.public", "files.read.sensitive"])
    intent = intent_for("files.read.sensitive", {"path": "public/demo.txt"})

    result = result_of(guard.policy_engine.evaluate("req-degrade-args", {"intent": intent}, claims))

    assert result["decision"] == "degraded"
    assert result["triggered_by_check"] == "arguments"
    assert result["forward_params"] == {
        "name": "files.read.public",
        "arguments": {"path": "public/demo.txt"},
    }


def test_mail_confirmation_hash_allows_once():
    claims = claims_for(["tools.list", "mail.send"])
    intent = intent_for(
        "mail.send",
        {"to": "alice@example.com", "subject": "Approved", "body": "Mock message."},
        intent_id="intent-confirm",
    )

    first = result_of(guard.policy_engine.evaluate("req-confirm-1", {"intent": intent}, claims))
    assert first["decision"] == "user_confirm"
    assert first["confirmation_hash"].startswith("sha256:")

    confirmed_intent = {**intent, "confirmation_hash": first["confirmation_hash"]}
    second = result_of(guard.policy_engine.evaluate("req-confirm-2", {"intent": confirmed_intent}, claims))
    assert second["decision"] == "allow"

    replay = result_of(guard.policy_engine.evaluate("req-confirm-3", {"intent": confirmed_intent}, claims))
    assert replay["decision"] == "deny"
    assert replay["failed_check"] == "confirmation"


def test_mail_disallowed_recipient_is_denied_before_confirmation():
    claims = claims_for(["tools.list", "mail.send"])
    intent = intent_for(
        "mail.send",
        {"to": "attacker@example.com", "subject": "Leak", "body": "Do not send."},
        intent_id="intent-bad-recipient",
    )

    result = result_of(guard.policy_engine.evaluate("req-bad-recipient", {"intent": intent}, claims))

    assert result["decision"] == "deny"
    assert result["failed_check"] == "arguments"
    assert "Recipient is not allowed" in result["reason"]


def test_mail_confirmation_survives_store_reload_and_blocks_replay(tmp_path):
    old_store = guard.CONFIRMATION_STORE
    confirmation_log = tmp_path / "confirmations.jsonl"
    try:
        guard.CONFIRMATION_STORE = ConfirmationStore(confirmation_log, ttl_seconds=60, now_fn=lambda: 1000.0)
        claims = claims_for(["tools.list", "mail.send"])
        intent = intent_for(
            "mail.send",
            {"to": "alice@example.com", "subject": "Persisted", "body": "Mock message."},
            intent_id="intent-persisted-confirm",
        )

        first = result_of(guard.policy_engine.evaluate("req-persist-1", {"intent": intent}, claims))
        assert first["decision"] == "user_confirm"
        assert first["expires_at"]
        assert first["expires_in_seconds"] == 60

        guard.CONFIRMATION_STORE = ConfirmationStore(confirmation_log, ttl_seconds=60, now_fn=lambda: 1001.0)
        confirmed_intent = {**intent, "confirmation_hash": first["confirmation_hash"]}
        second = result_of(guard.policy_engine.evaluate("req-persist-2", {"intent": confirmed_intent}, claims))
        assert second["decision"] == "allow"

        guard.CONFIRMATION_STORE = ConfirmationStore(confirmation_log, ttl_seconds=60, now_fn=lambda: 1002.0)
        replay = result_of(guard.policy_engine.evaluate("req-persist-3", {"intent": confirmed_intent}, claims))
        assert replay["decision"] == "deny"
        assert replay["reason"] == "Confirmation has already been used"
        event_types = [line.split('"event_type": "', 1)[1].split('"', 1)[0] for line in confirmation_log.read_text().splitlines()]
        assert event_types == ["issued", "used", "replay"]
    finally:
        guard.CONFIRMATION_STORE = old_store


def test_mail_confirmation_expires(tmp_path):
    old_store = guard.CONFIRMATION_STORE
    now = [1000.0]
    try:
        guard.CONFIRMATION_STORE = ConfirmationStore(
            tmp_path / "confirmations.jsonl",
            ttl_seconds=5,
            now_fn=lambda: now[0],
        )
        claims = claims_for(["tools.list", "mail.send"])
        intent = intent_for(
            "mail.send",
            {"to": "alice@example.com", "subject": "Expired", "body": "Mock message."},
            intent_id="intent-expired-confirm",
        )

        first = result_of(guard.policy_engine.evaluate("req-expire-1", {"intent": intent}, claims))
        assert first["decision"] == "user_confirm"

        now[0] = 1006.0
        confirmed_intent = {**intent, "confirmation_hash": first["confirmation_hash"]}
        expired = result_of(guard.policy_engine.evaluate("req-expire-2", {"intent": confirmed_intent}, claims))

        assert expired["decision"] == "deny"
        assert expired["failed_check"] == "confirmation"
        assert expired["reason"] == "Confirmation has expired"
        assert '"event_type": "expired"' in guard.CONFIRMATION_STORE.path.read_text()
    finally:
        guard.CONFIRMATION_STORE = old_store
