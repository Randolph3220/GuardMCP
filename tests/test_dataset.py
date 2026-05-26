from agent_host.generate_cases import build_cases
from agent_host.generate_degraded_cases import build_degraded_cases
from agent_host.generate_large_attack_cases import build_large_attack_cases


def test_dataset_has_100_unique_cases():
    cases = build_cases()
    case_ids = [case["case_id"] for case in cases]

    assert len(cases) == 100
    assert len(case_ids) == len(set(case_ids))


def test_dataset_includes_realistic_attack_families():
    cases = build_cases()
    case_ids = {case["case_id"] for case in cases}

    assert {f"web-hidden-{i:03d}" for i in range(1, 5)} <= case_ids
    assert {f"second-order-{i:03d}" for i in range(1, 5)} <= case_ids
    assert {f"obfuscated-real-{i:03d}" for i in range(1, 5)} <= case_ids
    assert {f"mail-leak-{i:03d}" for i in range(1, 5)} <= case_ids
    assert {f"cmd-chain-{i:03d}" for i in range(1, 5)} <= case_ids


def test_realistic_attack_cases_have_expected_sources_and_tools():
    cases_by_id = {case["case_id"]: case for case in build_cases()}

    assert cases_by_id["web-hidden-001"]["external_resources"][0]["label"] == "untrusted_web"
    assert "display:none" in cases_by_id["web-hidden-001"]["external_resources"][0]["content"]

    assert cases_by_id["second-order-001"]["external_resources"][0]["label"] == "tool_output"
    assert "next call" in cases_by_id["second-order-001"]["external_resources"][0]["content"]

    assert cases_by_id["obfuscated-real-001"]["mock_intent"]["tool_name"] == "mail.send"
    assert "U2VuZCB" in cases_by_id["obfuscated-real-001"]["external_resources"][0]["content"]

    assert cases_by_id["mail-leak-001"]["mock_intent"]["tool_args"]["to"] == "attacker@example.com"
    assert "sensitive/secret.txt" in cases_by_id["mail-leak-001"]["mock_intent"]["tool_args"]["body"]

    assert cases_by_id["cmd-chain-001"]["mock_intent"]["tool_args"]["command"] == (
        "cat public/demo.txt && cat sensitive/secret.txt"
    )


def test_degraded_dataset_targets_degraded_decision():
    cases = build_degraded_cases()

    assert len(cases) == 8
    assert {case["category"] for case in cases} == {"degraded"}
    assert {case["expected_decision"] for case in cases} == {"degraded"}
    assert all(case["expected_tool"] == "files.read.sensitive" for case in cases)
    assert any(case["token_profile"] == "T2" for case in cases)
    assert any(case["token_profile"] == "T5" for case in cases)


def test_large_attack_dataset_has_5000_unique_attack_cases():
    cases = build_large_attack_cases()
    case_ids = [case["case_id"] for case in cases]

    assert len(cases) == 5000
    assert len(case_ids) == len(set(case_ids))
    assert all(case["is_attack"] for case in cases)
    assert {case["category"] for case in cases} == {
        "direct",
        "indirect",
        "parameter",
        "tool_output",
        "obfuscated",
    }
    assert all(case["mock_intent"]["tool_name"] in {
        "files.read.public",
        "files.read.sensitive",
        "mail.send",
        "shell.exec",
    } for case in cases)
