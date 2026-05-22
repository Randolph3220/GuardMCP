from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from auth_server import app as auth
from mcp_server import app as mcp


def configure_runtime_tmp(monkeypatch, tmp_path):
    sandbox = tmp_path / "sandbox"
    public = sandbox / "public"
    sensitive = sandbox / "sensitive"
    public.mkdir(parents=True)
    sensitive.mkdir(parents=True)
    (public / "demo.txt").write_text("public demo", encoding="utf-8")
    (sensitive / "secret.txt").write_text("secret demo", encoding="utf-8")

    monkeypatch.setattr(mcp, "SANDBOX_ROOT", sandbox)
    monkeypatch.setattr(mcp, "PUBLIC_ROOT", public)
    monkeypatch.setattr(mcp, "SENSITIVE_ROOT", sensitive)
    monkeypatch.setattr(mcp, "OUTBOX_PATH", tmp_path / "outbox.jsonl")
    return sandbox


def signed_token(overrides: dict):
    now = datetime.now(timezone.utc)
    payload = {
        "iss": auth.ISSUER,
        "sub": "alice",
        "aud": auth.AUDIENCE,
        "scope": "tools.list",
        "exp": now + timedelta(seconds=60),
        "iat": now,
        "jti": "pytest-token",
        "session_id": "session-mcp-test",
        **overrides,
    }
    return auth.jwt.encode(
        payload,
        auth.KEY_STORE.active_private_key(),
        algorithm=auth.ALGORITHM,
        headers={"kid": auth.KEY_STORE.active_kid},
    )


def credentials_for(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_mcp_verify_token_rejects_invalid_audience(monkeypatch):
    monkeypatch.setattr(mcp, "public_key_for_token", lambda _token: auth.KEY_STORE.active_public_key())
    token = signed_token({"aud": "wrong-resource"})

    with pytest.raises(HTTPException) as exc_info:
        mcp.verify_token(credentials_for(token))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token"


def test_mcp_verify_token_rejects_expired_token(monkeypatch):
    monkeypatch.setattr(mcp, "public_key_for_token", lambda _token: auth.KEY_STORE.active_public_key())
    token = signed_token({"exp": datetime.now(timezone.utc) - timedelta(seconds=1)})

    with pytest.raises(HTTPException) as exc_info:
        mcp.verify_token(credentials_for(token))

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token expired"


def test_file_read_rejects_path_traversal(monkeypatch, tmp_path):
    configure_runtime_tmp(monkeypatch, tmp_path)

    result = mcp.execute_tool("files.read.public", {"path": "public/../sensitive/secret.txt"})

    assert result["isError"] is True
    assert "Path escapes" in result["content"][0]["text"]


def test_mail_send_writes_outbox_for_valid_args(monkeypatch, tmp_path):
    configure_runtime_tmp(monkeypatch, tmp_path)

    result = mcp.execute_tool(
        "mail.send",
        {"to": "alice@example.com", "subject": "Hello", "body": "Approved message."},
    )

    assert result["isError"] is False
    assert result["data"]["to"] == "alice@example.com"
    assert mcp.OUTBOX_PATH.exists()
    assert "alice@example.com" in mcp.OUTBOX_PATH.read_text(encoding="utf-8")


def test_mail_send_rejects_invalid_args_without_writing_outbox(monkeypatch, tmp_path):
    configure_runtime_tmp(monkeypatch, tmp_path)

    result = mcp.execute_tool("mail.send", {"to": "alice@example.com", "body": "Missing subject."})

    assert result["isError"] is True
    assert "Mail arguments" in result["content"][0]["text"]
    assert not mcp.OUTBOX_PATH.exists()


def test_shell_exec_rejects_dangerous_command_fragment(monkeypatch, tmp_path):
    configure_runtime_tmp(monkeypatch, tmp_path)

    result = mcp.execute_tool("shell.exec", {"command": "cat public/demo.txt; rm -rf /"})

    assert result["isError"] is True
    assert "dangerous fragment" in result["content"][0]["text"]
