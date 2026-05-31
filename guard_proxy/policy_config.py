from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "policies" / "default_policy.json"
REQUIRED_CONFIG_FIELDS = {
    "allowed_source_labels",
    "allowed_mail_recipients",
    "allowed_shell_commands",
    "dangerous_shell_fragments",
    "tools",
}
REQUIRED_TOOL_FIELDS = {
    "required_scopes",
    "risk",
    "allowed_sources",
    "requires_confirmation",
    "arg_policy",
}


def _require_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"Policy field {field_name} must be a non-empty string list")
    return value


def _normalize_degrade_policy(value: Any, tool_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"Policy for {tool_name} has invalid degrade policy")
    to_tool = value.get("to_tool")
    if not isinstance(to_tool, str) or not to_tool:
        raise ValueError(f"Policy for {tool_name} has invalid degrade.to_tool")
    reason = value.get("reason", f"Request was downgraded from {tool_name} to {to_tool}.")
    if not isinstance(reason, str) or not reason:
        raise ValueError(f"Policy for {tool_name} has invalid degrade.reason")
    default_args = value.get("default_args", {})
    if not isinstance(default_args, dict):
        raise ValueError(f"Policy for {tool_name} has invalid degrade.default_args")
    on_checks = value.get("on_checks", ["scope", "source_trace", "arguments"])
    return {
        "to_tool": to_tool,
        "reason": reason,
        "default_args": default_args,
        "on_checks": set(_require_string_list(on_checks, f"{tool_name}.degrade.on_checks")),
    }


def load_policy_config(path: str | Path | None = None) -> dict[str, Any]:
    policy_path = Path(path) if path is not None else DEFAULT_POLICY_PATH
    with policy_path.open(encoding="utf-8") as handle:
        raw = json.load(handle)

    missing = REQUIRED_CONFIG_FIELDS - set(raw)
    if missing:
        raise ValueError(f"Policy config missing fields: {', '.join(sorted(missing))}")

    tools = raw["tools"]
    if not isinstance(tools, dict) or not tools:
        raise ValueError("Policy field tools must be a non-empty object")

    normalized_tools: dict[str, dict[str, Any]] = {}
    for tool_name, policy in tools.items():
        if not isinstance(tool_name, str) or not tool_name:
            raise ValueError("Policy tool names must be non-empty strings")
        if not isinstance(policy, dict):
            raise ValueError(f"Policy for {tool_name} must be an object")
        missing_tool_fields = REQUIRED_TOOL_FIELDS - set(policy)
        if missing_tool_fields:
            raise ValueError(
                f"Policy for {tool_name} missing fields: {', '.join(sorted(missing_tool_fields))}"
            )
        arg_policy = policy["arg_policy"]
        if not isinstance(arg_policy, dict) or not isinstance(arg_policy.get("type"), str):
            raise ValueError(f"Policy for {tool_name} has invalid arg_policy")

        normalized_tools[tool_name] = {
            "required_scopes": _require_string_list(policy["required_scopes"], f"{tool_name}.required_scopes"),
            "risk": policy["risk"],
            "allowed_sources": set(_require_string_list(policy["allowed_sources"], f"{tool_name}.allowed_sources")),
            "requires_confirmation": bool(policy["requires_confirmation"]),
            "arg_policy": arg_policy,
            "degrade": _normalize_degrade_policy(policy.get("degrade"), tool_name),
        }

    for tool_name, policy in normalized_tools.items():
        degrade = policy.get("degrade")
        if degrade is None:
            continue
        to_tool = degrade["to_tool"]
        if to_tool not in normalized_tools:
            raise ValueError(f"Policy for {tool_name} degrades to unknown tool: {to_tool}")
        if to_tool == tool_name:
            raise ValueError(f"Policy for {tool_name} cannot degrade to itself")

    return {
        "path": policy_path,
        "allowed_source_labels": set(_require_string_list(raw["allowed_source_labels"], "allowed_source_labels")),
        "allowed_mail_recipients": set(_require_string_list(raw["allowed_mail_recipients"], "allowed_mail_recipients")),
        "allowed_shell_commands": set(_require_string_list(raw["allowed_shell_commands"], "allowed_shell_commands")),
        "dangerous_shell_fragments": _require_string_list(raw["dangerous_shell_fragments"], "dangerous_shell_fragments"),
        "tools": normalized_tools,
    }
