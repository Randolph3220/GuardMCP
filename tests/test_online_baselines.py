from agent_host.generate_degraded_cases import build_degraded_cases
from agent_host.run_online_baselines import (
    TOKEN_SCOPES,
    classify_case_result,
    row_for_outcome,
    scope_only_baseline,
    summarize,
)
from auth_server.app import build_access_token
from guard_proxy import app as guard


def result_of(decision: dict) -> dict:
    return decision["result"] if "jsonrpc" in decision else decision


def claims_for_profile(profile: str) -> dict:
    _token, payload = build_access_token(
        "alice",
        "session-test",
        TOKEN_SCOPES[profile],
    )
    return payload


def test_scope_only_blocks_degraded_case_without_sensitive_scope():
    case = build_degraded_cases()[0]
    intent = dict(case["mock_intent"])

    outcome = scope_only_baseline(case, intent)

    assert outcome["decision"] == "scope_challenge"
    assert outcome["executed"] is False
    assert outcome["failed_check"] == "scope"


def test_degraded_outcome_counts_as_normal_completed():
    case = build_degraded_cases()[0]
    result = {
        "decision": "degraded",
        "isError": False,
        "degraded_tool": "files.read.public",
        "data": {"path": "public/demo.txt"},
        "content": [{"type": "text", "text": "GuardMCP public demo file."}],
    }

    attack_success, normal_completed, false_block = classify_case_result(
        case,
        case["mock_intent"],
        result,
        executed=True,
        runtime_error=False,
    )

    assert attack_success is False
    assert normal_completed is True
    assert false_block is False


def test_baseline_row_marks_degraded_result():
    case = build_degraded_cases()[0]
    outcome = {
        "decision": "degraded",
        "failed_check": "",
        "executed": True,
        "runtime_error": False,
        "confirmation_requested": False,
        "confirmation_replayed": False,
        "result": {
            "decision": "degraded",
            "isError": False,
            "data": {"path": "public/demo.txt"},
        },
    }

    row = row_for_outcome("Full GuardMCP", case, case["mock_intent"], outcome, 1.25)

    assert row["degraded"] == "True"
    assert row["normal_completed"] == "True"
    assert row["false_block"] == "False"


def test_online_baseline_summary_includes_degraded_rate():
    case = build_degraded_cases()[0]
    row = row_for_outcome(
        "Full GuardMCP",
        case,
        case["mock_intent"],
        {
            "decision": "degraded",
            "executed": True,
            "runtime_error": False,
            "confirmation_requested": False,
            "confirmation_replayed": False,
            "result": {"decision": "degraded", "isError": False},
        },
        1.0,
    )

    summary = summarize([row], ["baseline"])

    assert summary[0]["degraded_rate"] == "1.000"
    assert summary[0]["normal_completion_rate"] == "1.000"


def test_degraded_cases_trigger_full_guard_degraded_decision():
    guard.CONFIRMATION_STORE.clear()

    for case in build_degraded_cases():
        intent = dict(case["mock_intent"])
        intent["session_id"] = "session-test"
        claims = claims_for_profile(case["token_profile"])

        result = result_of(guard.policy_engine.evaluate(
            f"req-{case['case_id']}",
            {"intent": intent},
            claims,
        ))

        assert result["decision"] == "degraded"
        assert result["original_tool"] == "files.read.sensitive"
        assert result["degraded_tool"] == "files.read.public"
        assert result["forward_params"] == {
            "name": "files.read.public",
            "arguments": {"path": "public/demo.txt"},
        }
