import json

import pytest

from guard_proxy.policy_config import DEFAULT_POLICY_PATH, load_policy_config


def test_default_policy_config_loads_expected_tools():
    config = load_policy_config(DEFAULT_POLICY_PATH)

    assert "files.read.public" in config["tools"]
    assert "mail.send" in config["tools"]
    assert config["tools"]["files.read.public"]["allowed_sources"] == {"user", "trusted_resource"}
    assert config["tools"]["mail.send"]["requires_confirmation"] is True
    assert config["tools"]["files.read.sensitive"]["degrade"]["to_tool"] == "files.read.public"
    assert config["tools"]["files.read.sensitive"]["degrade"]["default_args"] == {"path": "public/demo.txt"}
    assert "attacker@example.com" not in config["allowed_mail_recipients"]


def test_policy_config_rejects_missing_required_fields(tmp_path):
    config_path = tmp_path / "bad_policy.json"
    config_path.write_text(json.dumps({"tools": {}}), encoding="utf-8")

    with pytest.raises(ValueError, match="missing fields"):
        load_policy_config(config_path)
