import argparse
import csv
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_host.generate_degraded_cases import DEGRADED_CASES_PATH, build_degraded_cases  # noqa: E402
from agent_host.generate_large_attack_cases import LARGE_ATTACK_CASES_PATH  # noqa: E402
from agent_host.run_experiments import TOKEN_SCOPES  # noqa: E402
from agent_host.run_online_agent import (  # noqa: E402
    AUTH_SERVER_URL,
    DEEPSEEK_MODEL,
    GUARD_PROXY_URL,
    OnlineRunError,
    apply_case_constraints,
    attack_succeeded,
    build_messages,
    call_deepseek,
    display_path,
    guard_rpc,
    http_json,
    normalize_model_intent,
    parse_limit,
    response_result,
    resolve_project_path,
    safe_output_prefix,
    select_cases,
    should_auto_confirm,
)
from guard_proxy.app import TOOL_POLICIES  # noqa: E402
from mcp_server.app import OUTBOX_PATH, execute_tool  # noqa: E402


CASES_PATH = PROJECT_ROOT / "attacks" / "cases.jsonl"
RESULTS_PATH = PROJECT_ROOT / "experiments" / "online_baseline_results.csv"
TRACE_PATH = PROJECT_ROOT / "experiments" / "online_baseline_trace.jsonl"
SUMMARY_PATH = PROJECT_ROOT / "experiments" / "online_baseline_summary.csv"
SUMMARY_BY_CATEGORY_PATH = PROJECT_ROOT / "experiments" / "online_baseline_summary_by_category.csv"
DEGRADED_RESULTS_PATH = PROJECT_ROOT / "experiments" / "online_degraded_results.csv"
DEGRADED_TRACE_PATH = PROJECT_ROOT / "experiments" / "online_degraded_trace.jsonl"
DEGRADED_SUMMARY_PATH = PROJECT_ROOT / "experiments" / "online_degraded_summary.csv"
DEGRADED_SUMMARY_BY_CATEGORY_PATH = PROJECT_ROOT / "experiments" / "online_degraded_summary_by_category.csv"
LARGE_ATTACK_RESULTS_PATH = PROJECT_ROOT / "experiments" / "online_large_attack_results.csv"
LARGE_ATTACK_TRACE_PATH = PROJECT_ROOT / "experiments" / "online_large_attack_trace.jsonl"
LARGE_ATTACK_SUMMARY_PATH = PROJECT_ROOT / "experiments" / "online_large_attack_summary.csv"
LARGE_ATTACK_SUMMARY_BY_CATEGORY_PATH = PROJECT_ROOT / "experiments" / "online_large_attack_summary_by_category.csv"

BASELINES = ("Direct", "Prompt-only", "Scope-only", "Full GuardMCP")
EXECUTED_DECISIONS = {"allow", "degraded"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_selected_cases(suite: str, cases_file: str | None = None) -> tuple[list[dict[str, Any]], Path]:
    if cases_file:
        path = resolve_project_path(cases_file)
        return load_jsonl(path), path
    if suite == "main":
        return load_jsonl(CASES_PATH), CASES_PATH
    if suite == "degraded":
        if DEGRADED_CASES_PATH.exists():
            return load_jsonl(DEGRADED_CASES_PATH), DEGRADED_CASES_PATH
        return build_degraded_cases(), DEGRADED_CASES_PATH
    if suite == "large-attacks":
        return load_jsonl(LARGE_ATTACK_CASES_PATH), LARGE_ATTACK_CASES_PATH
    raise ValueError(f"Unknown suite: {suite}")


def supported_tool(tool_name: str) -> bool:
    return tool_name in {"files.read.public", "files.read.sensitive", "mail.send", "shell.exec"}


def tool_result_preview(result: dict[str, Any]) -> str:
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        return str(content[0].get("text", ""))[:180].replace("\n", " ")
    return ""


def direct_baseline(intent: dict[str, Any]) -> dict[str, Any]:
    tool_name = intent.get("tool_name", "")
    if not supported_tool(tool_name):
        return {
            "decision": "deny",
            "failed_check": "tool_exists",
            "executed": False,
            "runtime_error": False,
            "confirmation_requested": False,
            "confirmation_replayed": False,
            "result": {"decision": "deny", "isError": True, "reason": f"Unknown tool: {tool_name}"},
        }

    result = execute_tool(tool_name, intent.get("tool_args", {}))
    return {
        "decision": result.get("decision", "allow"),
        "failed_check": "",
        "executed": True,
        "runtime_error": bool(result.get("isError")),
        "confirmation_requested": False,
        "confirmation_replayed": False,
        "result": result,
        "error": tool_result_preview(result) if result.get("isError") else "",
    }


def prompt_only_baseline(case: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    if case.get("is_attack") and case.get("prompt_detectable"):
        return {
            "decision": "deny",
            "failed_check": "prompt_filter",
            "executed": False,
            "runtime_error": False,
            "confirmation_requested": False,
            "confirmation_replayed": False,
            "result": {
                "decision": "deny",
                "isError": True,
                "reason": "Prompt-only warning blocked an obvious malicious instruction.",
            },
            "error": "Prompt-only warning blocked an obvious malicious instruction.",
        }
    return direct_baseline(intent)


def scope_only_baseline(case: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    tool_name = intent.get("tool_name", "")
    policy = TOOL_POLICIES.get(tool_name)
    if policy is None:
        return {
            "decision": "deny",
            "failed_check": "tool_exists",
            "executed": False,
            "runtime_error": False,
            "confirmation_requested": False,
            "confirmation_replayed": False,
            "result": {"decision": "deny", "isError": True, "reason": f"Unknown tool: {tool_name}"},
        }

    token_scopes = set(TOKEN_SCOPES[case["token_profile"]])
    missing_scopes = [scope for scope in policy["required_scopes"] if scope not in token_scopes]
    if missing_scopes:
        return {
            "decision": "scope_challenge",
            "failed_check": "scope",
            "executed": False,
            "runtime_error": False,
            "confirmation_requested": False,
            "confirmation_replayed": False,
            "result": {
                "decision": "scope_challenge",
                "isError": True,
                "missing_scopes": missing_scopes,
                "required_scopes": policy["required_scopes"],
            },
            "error": f"Missing scopes: {' '.join(missing_scopes)}",
        }
    return direct_baseline(intent)


def full_guard_baseline(
    case: dict[str, Any],
    intent: dict[str, Any],
    token_info: dict[str, Any],
    auto_confirm: str,
) -> dict[str, Any]:
    token = token_info["access_token"]
    first_response = guard_rpc(
        token,
        f"online-baseline-call-{case['case_id']}",
        "tools/call",
        {"intent": intent},
    )
    first_result = response_result(first_response)
    final_result = first_result
    confirmation_requested = first_result.get("decision") == "user_confirm"
    confirmation_replayed = False

    if confirmation_requested and should_auto_confirm(auto_confirm, case):
        confirmed_intent = dict(intent)
        confirmed_intent["confirmation_hash"] = first_result.get("confirmation_hash")
        final_response = guard_rpc(
            token,
            f"online-baseline-confirm-{case['case_id']}",
            "tools/call",
            {"intent": confirmed_intent},
        )
        final_result = response_result(final_response)
        confirmation_replayed = True

    decision = final_result.get("decision", "")
    executed = decision in EXECUTED_DECISIONS
    runtime_error = bool(executed and final_result.get("isError"))
    return {
        "decision": decision,
        "failed_check": final_result.get("failed_check", ""),
        "executed": executed,
        "runtime_error": runtime_error,
        "confirmation_requested": confirmation_requested,
        "confirmation_replayed": confirmation_replayed,
        "result": final_result,
        "error": final_result.get("reason") or final_result.get("message") or (tool_result_preview(final_result) if runtime_error else ""),
    }


def classify_case_result(case: dict[str, Any], intent: dict[str, Any], result: dict[str, Any], executed: bool, runtime_error: bool) -> tuple[bool, bool, bool]:
    attack_success = attack_succeeded(case, intent, result)
    normal_completed = bool((not case.get("is_attack")) and executed and not runtime_error)
    false_block = bool((not case.get("is_attack")) and not normal_completed)
    return attack_success, normal_completed, false_block


def row_for_outcome(
    baseline: str,
    case: dict[str, Any],
    intent: dict[str, Any],
    outcome: dict[str, Any],
    latency_ms: float,
) -> dict[str, Any]:
    result = outcome.get("result", {})
    executed = bool(outcome.get("executed"))
    runtime_error = bool(outcome.get("runtime_error"))
    attack_success, normal_completed, false_block = classify_case_result(case, intent, result, executed, runtime_error)
    decision = outcome.get("decision", "")
    return {
        "baseline": baseline,
        "case_id": case["case_id"],
        "category": case["category"],
        "is_attack": str(case["is_attack"]),
        "token_profile": "T5" if baseline in {"Direct", "Prompt-only"} else case["token_profile"],
        "expected_tool": case["expected_tool"],
        "model_tool": intent.get("tool_name", ""),
        "decision": decision,
        "failed_check": outcome.get("failed_check", ""),
        "executed": str(executed),
        "guard_blocked": str(decision not in EXECUTED_DECISIONS),
        "runtime_error": str(runtime_error),
        "degraded": str(decision == "degraded"),
        "attack_success": str(attack_success),
        "normal_completed": str(normal_completed),
        "false_block": str(false_block),
        "confirmation_requested": str(bool(outcome.get("confirmation_requested"))),
        "confirmation_replayed": str(bool(outcome.get("confirmation_replayed"))),
        "latency_ms": round(latency_ms, 3),
        "error": outcome.get("error", ""),
    }


def run_case_online_baselines(
    case: dict[str, Any],
    token_info: dict[str, Any],
    api_key: str,
    model: str,
    timeout: int,
    max_tokens: int,
    auto_confirm: str,
    retries: int,
    retry_sleep: float,
    run_id: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    token = token_info["access_token"]
    session_id = token_info["session_id"]
    tools_response = guard_rpc(token, f"online-baseline-tools-{case['case_id']}", "tools/list", {})
    tools = response_result(tools_response).get("tools", [])

    messages = build_messages(case, session_id, tools)
    model_intent, model_raw = call_deepseek(api_key, messages, model, timeout, max_tokens, retries, retry_sleep)
    normalized_intent = normalize_model_intent(model_intent, case, session_id)
    normalized_intent["intent_id"] = f"online-baseline-{run_id}-{case['case_id']}"
    intent = apply_case_constraints(normalized_intent, case)

    rows: list[dict[str, Any]] = []
    trace_results: dict[str, Any] = {}
    for baseline in BASELINES:
        started = time.perf_counter()
        if baseline == "Direct":
            outcome = direct_baseline(intent)
        elif baseline == "Prompt-only":
            outcome = prompt_only_baseline(case, intent)
        elif baseline == "Scope-only":
            outcome = scope_only_baseline(case, intent)
        elif baseline == "Full GuardMCP":
            outcome = full_guard_baseline(case, intent, token_info, auto_confirm)
        else:
            raise ValueError(f"Unknown baseline: {baseline}")
        latency_ms = (time.perf_counter() - started) * 1000
        rows.append(row_for_outcome(baseline, case, intent, outcome, latency_ms))
        trace_results[baseline] = outcome.get("result", {})

    trace = {
        "case_id": case["case_id"],
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_raw": model_raw,
        "model_intent": normalized_intent,
        "case_constraints_applied": normalized_intent != intent,
        "intent": intent,
        "baseline_results": trace_results,
    }
    return rows, trace


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def completed_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["case_id"], []).append(row)

    complete_rows: list[dict[str, Any]] = []
    completed_case_ids: set[str] = set()
    expected = set(BASELINES)
    for case_id, case_rows in grouped.items():
        if {row["baseline"] for row in case_rows} == expected:
            completed_case_ids.add(case_id)
            complete_rows.extend(case_rows)
    return complete_rows, completed_case_ids


def pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000"
    return f"{numerator / denominator:.3f}"


def summarize(rows: list[dict[str, Any]], group_fields: list[str]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(tuple(row[field] for field in group_fields), []).append(row)

    summary_rows = []
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
            "degraded_rate": pct(sum(row["degraded"] == "True" for row in group), len(group)),
            "confirmation_rate": pct(sum(row["confirmation_requested"] == "True" for row in group), len(group)),
            "median_latency_ms": f"{statistics.median(latencies):.3f}" if latencies else "0.000",
        })
        summary_rows.append(item)
    return summary_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run online baselines with real model-generated intents.")
    parser.add_argument("--suite", choices=["main", "degraded", "large-attacks"], default="main")
    parser.add_argument("--cases-file", help="JSONL case file to run instead of a built-in suite file.")
    parser.add_argument("--output-prefix", help="Prefix for custom output files under experiments/.")
    parser.add_argument("--limit", type=parse_limit, default=10)
    parser.add_argument("--category")
    parser.add_argument("--case-id")
    parser.add_argument("--model", default=DEEPSEEK_MODEL)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-tokens", type=int, default=700)
    parser.add_argument("--retries", type=int, default=4)
    parser.add_argument("--retry-sleep", type=float, default=2.0)
    parser.add_argument("--auto-confirm", choices=["normal", "all", "none"], default="normal")
    parser.add_argument("--sleep", type=float, default=0.0)
    parser.add_argument("--resume", action="store_true", help="Skip case ids that already have all baseline rows.")
    parser.add_argument("--case-retries", type=int, default=3, help="Extra retries for a whole case after model/API failures.")
    parser.add_argument("--case-retry-sleep", type=float, default=60.0, help="Sleep seconds between whole-case retries.")
    return parser.parse_args()


def custom_output_paths(prefix: str) -> tuple[Path, Path, Path, Path]:
    safe_prefix = safe_output_prefix(prefix)
    experiments = PROJECT_ROOT / "experiments"
    return (
        experiments / f"online_{safe_prefix}_baseline_results.csv",
        experiments / f"online_{safe_prefix}_baseline_trace.jsonl",
        experiments / f"online_{safe_prefix}_baseline_summary.csv",
        experiments / f"online_{safe_prefix}_baseline_summary_by_category.csv",
    )


def output_paths(suite: str, output_prefix: str | None = None) -> tuple[Path, Path, Path, Path]:
    if output_prefix:
        return custom_output_paths(output_prefix)
    if suite == "degraded":
        return (
            DEGRADED_RESULTS_PATH,
            DEGRADED_TRACE_PATH,
            DEGRADED_SUMMARY_PATH,
            DEGRADED_SUMMARY_BY_CATEGORY_PATH,
        )
    if suite == "large-attacks":
        return (
            LARGE_ATTACK_RESULTS_PATH,
            LARGE_ATTACK_TRACE_PATH,
            LARGE_ATTACK_SUMMARY_PATH,
            LARGE_ATTACK_SUMMARY_BY_CATEGORY_PATH,
        )
    return (
        RESULTS_PATH,
        TRACE_PATH,
        SUMMARY_PATH,
        SUMMARY_BY_CATEGORY_PATH,
    )


def fetch_test_token_profiles() -> dict[str, Any]:
    tokens = http_json("GET", f"{AUTH_SERVER_URL}/tokens/test")
    return tokens["profiles"]


def is_token_expired_error(exc: OnlineRunError) -> bool:
    return "Token expired" in str(exc)


def main() -> int:
    args = parse_args()
    all_cases, cases_path = load_selected_cases(args.suite, args.cases_file)
    cases = select_cases(all_cases, args.category, args.case_id, args.limit)
    if not cases:
        raise OnlineRunError("No cases selected")

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("DEEPSEEK_API_KEY is not set. Export it in the shell before running this script.", file=sys.stderr)
        return 2

    if OUTBOX_PATH.exists():
        OUTBOX_PATH.unlink()

    profiles = fetch_test_token_profiles()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    output_prefix = args.output_prefix or (cases_path.stem if args.cases_file else None)
    results_path, trace_path, summary_path, summary_by_category_path = output_paths(args.suite, output_prefix)
    rows: list[dict[str, Any]] = []
    if args.resume:
        rows, completed_case_ids = completed_rows(read_csv(results_path))
        if completed_case_ids:
            cases = [case for case in cases if case["case_id"] not in completed_case_ids]
            write_csv(results_path, rows)
            write_csv(summary_path, summarize(rows, ["baseline"]))
            write_csv(summary_by_category_path, summarize(rows, ["baseline", "category"]))
            print(f"resuming from {len(completed_case_ids)} completed cases")

    trace_path.parent.mkdir(parents=True, exist_ok=True)
    trace_mode = "a" if args.resume and trace_path.exists() else "w"
    with trace_path.open(trace_mode, encoding="utf-8") as trace_handle:
        total = len(cases)
        if total == 0:
            print("no remaining cases to run")
            return 0
        for index, case in enumerate(cases, start=1):
            case_attempt = 0
            token_refreshes = 0
            while True:
                try:
                    case_rows, trace = run_case_online_baselines(
                        case,
                        profiles[case["token_profile"]],
                        api_key,
                        args.model,
                        args.timeout,
                        args.max_tokens,
                        args.auto_confirm,
                        args.retries,
                        args.retry_sleep,
                        run_id,
                    )
                    break
                except OnlineRunError as exc:
                    if is_token_expired_error(exc):
                        if token_refreshes >= 5:
                            raise
                        token_refreshes += 1
                        profiles = fetch_test_token_profiles()
                        print(
                            f"[token-refresh] refreshed test tokens after expiry while running {case['case_id']} "
                            f"({token_refreshes}/5)",
                            file=sys.stderr,
                        )
                        continue
                    if case_attempt >= args.case_retries:
                        raise
                    case_attempt += 1
                    delay = min(args.case_retry_sleep * case_attempt, 300)
                    print(
                        f"[case-retry] {case['case_id']} failed after request retries: {exc}; "
                        f"sleeping {delay:.1f}s ({case_attempt}/{args.case_retries})",
                        file=sys.stderr,
                    )
                    time.sleep(delay)
            rows.extend(case_rows)
            trace_handle.write(json.dumps(trace, ensure_ascii=False, sort_keys=True) + "\n")
            trace_handle.flush()
            write_csv(results_path, rows)
            write_csv(summary_path, summarize(rows, ["baseline"]))
            write_csv(summary_by_category_path, summarize(rows, ["baseline", "category"]))
            full = next(row for row in case_rows if row["baseline"] == "Full GuardMCP")
            print(f"[{index}/{total}] {case['case_id']} -> {full['decision']} ({full['model_tool']})")
            if args.sleep:
                time.sleep(args.sleep)

    print(f"wrote {len(rows)} rows to {display_path(results_path)}")
    print(f"wrote trace to {display_path(trace_path)}")
    print(f"wrote summary to {display_path(summary_path)}")
    print(f"wrote category summary to {display_path(summary_by_category_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
