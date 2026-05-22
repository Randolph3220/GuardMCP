import asyncio
import urllib.error

import jwt
import pytest

from auth_server import app as auth
from auth_server.keys import RSAKeyStore
from guard_proxy import app as guard
from mcp_server import app as mcp


class FailingOpener:
    def open(self, *_args, **_kwargs):
        raise urllib.error.URLError("offline")


def test_access_token_is_rs256_with_kid_and_verifies_locally():
    token, _payload = auth.build_access_token(
        "alice",
        "session-jwks",
        ["tools.list"],
    )

    header = auth.jwt.get_unverified_header(token)
    claims = auth.decode_access_token(token)

    assert header["alg"] == "RS256"
    assert header["kid"] == auth.KEY_STORE.active_kid
    assert claims["sub"] == "alice"
    assert claims["session_id"] == "session-jwks"


def test_jwks_exposes_public_rsa_key_only():
    payload = auth.KEY_STORE.jwks()
    key = payload["keys"][0]

    assert key["kid"] == auth.KEY_STORE.active_kid
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert "n" in key
    assert "e" in key
    assert "d" not in key


def test_key_store_loads_private_key_file_without_replacing_it(tmp_path):
    path = tmp_path / "auth_keys.json"
    first = RSAKeyStore(path, retention_seconds=60, now_fn=lambda: 1000.0)
    first_kid = first.active_kid

    second = RSAKeyStore(path, retention_seconds=60, now_fn=lambda: 1001.0)

    assert second.active_kid == first_kid
    assert second.key_summary()["published_kids"] == [first_kid]
    assert path.exists()


def test_key_rotation_publishes_old_key_until_retention_window(tmp_path):
    now = [1000.0]
    store = RSAKeyStore(tmp_path / "auth_keys.json", retention_seconds=10, now_fn=lambda: now[0])
    old_kid = store.active_kid

    rotation = store.rotate()
    new_kid = store.active_kid

    assert rotation["previous_kid"] == old_kid
    assert new_kid != old_kid
    assert {key["kid"] for key in store.jwks()["keys"]} == {old_kid, new_kid}

    now[0] = 1009.0
    assert {key["kid"] for key in store.jwks()["keys"]} == {old_kid, new_kid}

    now[0] = 1011.0
    assert {key["kid"] for key in store.jwks()["keys"]} == {new_kid}
    assert store.public_key_by_kid(old_kid) is None


def test_auth_decode_uses_kid_and_rejects_old_key_after_retention(tmp_path, monkeypatch):
    now = [1000.0]
    store = RSAKeyStore(tmp_path / "auth_keys.json", retention_seconds=5, now_fn=lambda: now[0])
    monkeypatch.setattr(auth, "KEY_STORE", store)

    old_token, _payload = auth.build_access_token("alice", "session-old-key", ["tools.list"], expires_in=60)
    old_kid = auth.jwt.get_unverified_header(old_token)["kid"]

    store.rotate()
    assert auth.decode_access_token(old_token)["session_id"] == "session-old-key"

    now[0] = 1006.0
    with pytest.raises(jwt.InvalidTokenError):
        auth.decode_access_token(old_token)

    new_token, _payload = auth.build_access_token("alice", "session-new-key", ["tools.list"], expires_in=60)
    assert auth.jwt.get_unverified_header(new_token)["kid"] != old_kid


def test_key_metadata_and_rotation_endpoints(tmp_path, monkeypatch):
    store = RSAKeyStore(tmp_path / "auth_keys.json", retention_seconds=60, now_fn=lambda: 1000.0)
    monkeypatch.setattr(auth, "KEY_STORE", store)

    before = asyncio.run(auth.keys_metadata())
    rotation = asyncio.run(auth.rotate_signing_key(auth.RotateKeyRequest()))
    after = asyncio.run(auth.keys_metadata())

    assert before["active_kid"] == rotation["previous_kid"]
    assert after["active_kid"] == rotation["active_kid"]
    assert set(after["published_kids"]) == {rotation["previous_kid"], rotation["active_kid"]}
    assert rotation["jwks_uri"].endswith("/.well-known/jwks.json")


def test_guard_jwks_fetch_falls_back_to_stale_cache_on_network_failure(monkeypatch):
    cached_keys = {auth.KEY_STORE.active_kid: auth.KEY_STORE.jwks()["keys"][0]}
    monkeypatch.setitem(guard.JWKS_CACHE, "expires_at", 0.0)
    monkeypatch.setitem(guard.JWKS_CACHE, "keys", cached_keys)
    monkeypatch.setattr(guard.urllib.request, "build_opener", lambda *_args, **_kwargs: FailingOpener())

    assert guard.fetch_jwks() == cached_keys


def test_mcp_jwks_fetch_falls_back_to_stale_cache_on_network_failure(monkeypatch):
    cached_keys = {auth.KEY_STORE.active_kid: auth.KEY_STORE.jwks()["keys"][0]}
    monkeypatch.setitem(mcp.JWKS_CACHE, "expires_at", 0.0)
    monkeypatch.setitem(mcp.JWKS_CACHE, "keys", cached_keys)
    monkeypatch.setattr(mcp.urllib.request, "build_opener", lambda *_args, **_kwargs: FailingOpener())

    assert mcp.fetch_jwks() == cached_keys


def test_guard_jwks_fetch_without_cache_still_fails_on_network_failure(monkeypatch):
    monkeypatch.setitem(guard.JWKS_CACHE, "expires_at", 0.0)
    monkeypatch.setitem(guard.JWKS_CACHE, "keys", {})
    monkeypatch.setattr(guard.urllib.request, "build_opener", lambda *_args, **_kwargs: FailingOpener())

    with pytest.raises(guard.HTTPException) as exc_info:
        guard.fetch_jwks()
    assert exc_info.value.status_code == 401
