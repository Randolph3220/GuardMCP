import csv
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auth_server.app import build_access_token, decode_access_token  # noqa: E402
from guard_proxy.app import CONFIRMATION_STORE, TOOL_POLICIES, policy_engine  # noqa: E402
from mcp_server.app import OUTBOX_PATH, execute_tool  # noqa: E402

CASES_PATH = PROJECT_ROOT / "attacks" / "cases.jsonl"
RESULTS_PATH = PROJECT_ROOT / "experiments" / "results.csv"
SUMMARY_PATH = PROJECT_ROOT / "experiments" / "summary.csv"
SUMMARY_BY_CATEGORY_PATH = PROJECT_ROOT / "experiments" / "summary_by_category.csv"

BASELINES = ["Direct", "Prompt-only", "Scope-only", "Full GuardMCP"]
TOKEN_SCOPES = {
    "T1": ["tools.list"],
    "T2": ["tools.list", "files.read.public"],
    "T3": ["tools.list", "mail.send"],
    "T4": ["tools.list", "files.read.sensitive", "mail.send"],
    "T5": ["tools.list", "files.read.public", "files.read.sensitive", "mail.send", "shell.exec"],
}


def load_cases() -> list[dict[str, Any]]:
    with CASES_PATH.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def token_claims(profile: str) -> dict[str, Any]:
    session_id = f"session-{profile.lower()}"
    token, _payload = build_access_token("alice", session_id, TOKEN_SCOPES[profile])
    return decode_access_token(token)


def classify(case: dict[str, Any], decision: str, executed: bool, tool_error: bool) -> tuple[bool, bool, bool]:
    attack_success = bool(case["is_attack"] and decision == "allow" and executed and not tool_error)
    normal_completed = bool((not case["is_attack"]) and decision in {"allow", "degraded"} and executed and not tool_error)
    false_block = bool((not case["is_attack"]) and not normal_completed)
    return attack_success, normal_completed, false_block


def execute_mock_tool(intent: dict[str, Any]) -> tuple[bool, bool, str]:
    result = execute_tool(intent["tool_name"], intent["tool_args"])
    text = result.get("content", [{}])[0].get("text", "")
    return True, bool(result.get("isError")), text[:180].replace("\n", " ")


def execute_forward_params(forward_params: dict[str, Any]) -> tuple[bool, bool, str]:
    result = execute_tool(forward_params["name"], forward_params["arguments"])
    text = result.get("content", [{}])[0].get("text", "")
    return True, bool(result.get("isError")), text[:180].replace("\n", " ")


def direct_run(case: dict[str, Any], baseline: str) -> dict[str, Any]:
    intent = case["mock_intent"]
    if baseline == "Prompt-only" and case["is_attack"] and case.get("prompt_detectable"):
        return {
            "decision": "deny",
            "executed": False,
            "tool_error": False,
            "audit_id": "prompt-filter",
            "error": "Prompt-only warning blocked an obvious malicious instruction.",
            "confirmation_requested": False,
        }
    executed, tool_error, output_preview = execute_mock_tool(intent)
    return {
        "decision": "allow",
        "executed": executed,
        "tool_error": tool_error,
        "audit_id": f"{baseline.lower()}-direct",
        "error": output_preview if tool_error else "",
        "confirmation_requested": False,
    }


def scope_only_run(case: dict[str, Any]) -> dict[str, Any]:
    intent = case["mock_intent"]
    policy = TOOL_POLICIES.get(intent["tool_name"])
    if policy is None:
        return {
            "decision": "deny",
            "executed": False,
            "tool_error": False,
            "audit_id": "scope-only-deny",
            "error": "Unknown tool",
            "confirmation_requested": False,
        }

    token_scopes = set(TOKEN_SCOPES[case["token_profile"]])
    missing_scopes = [scope for scope in policy["required_scopes"] if scope not in token_scopes]
    if missing_scopes:
        return {
            "decision": "scope_challenge",
            "executed": False,
            "tool_error": False,
            "audit_id": "scope-only-challenge",
            "error": f"Missing scopes: {' '.join(missing_scopes)}",
            "confirmation_requested": False,
        }
    executed, tool_error, output_preview = execute_mock_tool(intent)
    return {
        "decision": "allow",
        "executed": executed,
        "tool_error": tool_error,
        "audit_id": "scope-only-allow",
        "error": output_preview if tool_error else "",
        "confirmation_requested": False,
    }


def full_guard_run(case: dict[str, Any]) -> dict[str, Any]:
    claims = token_claims(case["token_profile"])
    intent = dict(case["mock_intent"])
    decision = policy_engine.evaluate(case["case_id"], {"intent": intent}, claims)
    result = decision.get("result") if "jsonrpc" in decision else decision
    confirmation_requested = result["decision"] == "user_confirm"

    if confirmation_requested and not case["is_attack"]:
        intent["confirmation_hash"] = result["confirmation_hash"]
        decision = policy_engine.evaluate(case["case_id"], {"intent": intent}, claims)
        result = decision.get("result") if "jsonrpc" in decision else decision

    if result["decision"] not in {"allow", "degraded"}:
        return {
            "decision": result["decision"],
            "executed": False,
            "tool_error": False,
            "audit_id": result.get("audit_id", ""),
            "error": result.get("reason") or result.get("message", ""),
            "confirmation_requested": confirmation_requested,
        }

    executed, tool_error, output_preview = execute_forward_params(result["forward_params"])
    return {
        "decision": result["decision"],
        "executed": executed,
        "tool_error": tool_error,
        "audit_id": result.get("audit_id", ""),
        "error": output_preview if tool_error else "",
        "confirmation_requested": confirmation_requested,
    }


def run_case(case: dict[str, Any], baseline: str) -> dict[str, Any]:
    start = time.perf_counter()
    if baseline in {"Direct", "Prompt-only"}:
        outcome = direct_run(case, baseline)
        token_profile = "T5"
    elif baseline == "Scope-only":
        outcome = scope_only_run(case)
        token_profile = case["token_profile"]
    elif baseline == "Full GuardMCP":
        outcome = full_guard_run(case)
        token_profile = case["token_profile"]
    else:
        raise ValueError(f"Unknown baseline: {baseline}")

    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    attack_success, normal_completed, false_block = classify(
        case,
        outcome["decision"],
        outcome["executed"],
        outcome["tool_error"],
    )
    return {
        "baseline": baseline,
        "case_id": case["case_id"],
        "category": case["category"],
        "is_attack": str(case["is_attack"]),
        "token_profile": token_profile,
        "tool_name": case["mock_intent"]["tool_name"],
        "decision": outcome["decision"],
        "executed": str(outcome["executed"]),
        "tool_error": str(outcome["tool_error"]),
        "attack_success": str(attack_success),
        "normal_completed": str(normal_completed),
        "false_block": str(false_block),
        "confirmation_requested": str(outcome["confirmation_requested"]),
        "latency_ms": latency_ms,
        "audit_id": outcome["audit_id"],
        "error": outcome["error"],
    }


def pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000"
    return f"{numerator / denominator:.3f}"


def summarize(rows: list[dict[str, Any]], group_fields: list[str]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = tuple(row[field] for field in group_fields)
        groups.setdefault(key, []).append(row)

    summary = []
    for key, group in sorted(groups.items()):
        attack_rows = [row for row in group if row["is_attack"] == "True"]
        normal_rows = [row for row in group if row["is_attack"] == "False"]
        latencies = [float(row["latency_ms"]) for row in group]
        item = {field: value for field, value in zip(group_fields, key)}
        item.update({
            "total_cases": len(group),
            "attack_cases": len(attack_rows),
            "normal_cases": len(normal_rows),
            "attack_success_rate": pct(sum(row["attack_success"] == "True" for row in attack_rows), len(attack_rows)),
            "normal_completion_rate": pct(sum(row["normal_completed"] == "True" for row in normal_rows), len(normal_rows)),
            "false_block_rate": pct(sum(row["false_block"] == "True" for row in normal_rows), len(normal_rows)),
            "dangerous_call_rate": pct(sum(row["executed"] == "True" and row["is_attack"] == "True" for row in group), len(attack_rows)),
            "confirmation_rate": pct(sum(row["confirmation_requested"] == "True" for row in group), len(group)),
            "median_latency_ms": f"{statistics.median(latencies):.3f}" if latencies else "0.000",
        })
        summary.append(item)
    return summary


def write_csv(path: Path, rows: list[dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    CONFIRMATION_STORE.clear()
    if OUTBOX_PATH.exists():
        OUTBOX_PATH.unlink()
    cases = load_cases()
    if len(cases) < 100:
        raise RuntimeError(f"Expected at least 100 cases, found {len(cases)}")

    rows = [run_case(case, baseline) for baseline in BASELINES for case in cases]
    write_csv(RESULTS_PATH, rows)
    write_csv(SUMMARY_PATH, summarize(rows, ["baseline"]))
    write_csv(SUMMARY_BY_CATEGORY_PATH, summarize(rows, ["baseline", "category"]))
    print(f"wrote {len(rows)} rows to {RESULTS_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote summary to {SUMMARY_PATH.relative_to(PROJECT_ROOT)}")
    print(f"wrote category summary to {SUMMARY_BY_CATEGORY_PATH.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
