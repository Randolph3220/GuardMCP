from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY_STORE_PATH = PROJECT_ROOT / ".local" / "auth_keys.json"
DEFAULT_KEY_RETENTION_SECONDS = 86400


def utc_now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def private_key_from_pem(value: str) -> rsa.RSAPrivateKey:
    private_key = serialization.load_pem_private_key(value.encode("ascii"), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Auth key store contains a non-RSA private key")
    return private_key


def kid_for_key(private_key: rsa.RSAPrivateKey) -> str:
    numbers = private_key.public_key().public_numbers()
    return hashlib.sha256(f"{numbers.n}:{numbers.e}".encode("ascii")).hexdigest()[:16]


def public_jwk_for_key(kid: str, private_key: rsa.RSAPrivateKey) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": base64url_uint(numbers.n),
        "e": base64url_uint(numbers.e),
    }


@dataclass
class KeyRecord:
    kid: str
    private_key: rsa.RSAPrivateKey
    created_at: float
    retired_at: float | None = None

    @property
    def created_at_iso(self) -> str:
        return utc_now_iso(self.created_at)

    @property
    def retired_at_iso(self) -> str | None:
        if self.retired_at is None:
            return None
        return utc_now_iso(self.retired_at)

    @classmethod
    def generate(cls, now: float) -> "KeyRecord":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(kid=kid_for_key(private_key), private_key=private_key, created_at=now)

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "KeyRecord":
        private_key = private_key_from_pem(payload["private_key_pem"])
        kid = payload.get("kid") or kid_for_key(private_key)
        expected_kid = kid_for_key(private_key)
        if kid != expected_kid:
            raise ValueError(f"Auth key store kid mismatch for {kid}")
        return cls(
            kid=kid,
            private_key=private_key,
            created_at=float(payload["created_at"]),
            retired_at=float(payload["retired_at"]) if payload.get("retired_at") is not None else None,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "kid": self.kid,
            "private_key_pem": private_key_to_pem(self.private_key),
            "created_at": self.created_at,
            "created_at_iso": self.created_at_iso,
            "retired_at": self.retired_at,
            "retired_at_iso": self.retired_at_iso,
        }

    def is_published(self, now: float, retention_seconds: int) -> bool:
        return self.retired_at is None or self.retired_at + retention_seconds > now


class RSAKeyStore:
    def __init__(
        self,
        path: str | Path | None = None,
        retention_seconds: int | None = None,
        now_fn: Callable[[], float] | None = None,
    ):
        self.path = Path(path or os.getenv("AUTH_KEY_STORE_PATH", DEFAULT_KEY_STORE_PATH))
        self.retention_seconds = int(
            retention_seconds
            if retention_seconds is not None
            else os.getenv("AUTH_KEY_RETENTION_SECONDS", str(DEFAULT_KEY_RETENTION_SECONDS))
        )
        self.now_fn = now_fn or time.time
        self.active_kid = ""
        self.records: dict[str, KeyRecord] = {}
        self.load_or_initialize()

    def load_or_initialize(self) -> None:
        if self.path.exists():
            self.load()
            if self.active_kid not in self.records:
                raise ValueError("Auth key store active_kid does not match any stored key")
            return

        now = self.now_fn()
        record = KeyRecord.generate(now)
        self.active_kid = record.kid
        self.records = {record.kid: record}
        self.save()

    def load(self) -> None:
        with self.path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        records = [KeyRecord.from_json(item) for item in payload.get("keys", [])]
        if not records:
            raise ValueError("Auth key store has no keys")
        self.records = {record.kid: record for record in records}
        self.active_kid = payload.get("active_kid") or records[0].kid

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "active_kid": self.active_kid,
            "retention_seconds": self.retention_seconds,
            "keys": [self.records[kid].to_json() for kid in sorted(self.records)],
        }
        with self.path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(self.path, 0o600)

    def active_record(self) -> KeyRecord:
        return self.records[self.active_kid]

    def active_private_key(self) -> rsa.RSAPrivateKey:
        return self.active_record().private_key

    def active_public_key(self):
        return self.active_private_key().public_key()

    def published_records(self, now: float | None = None) -> list[KeyRecord]:
        current = self.now_fn() if now is None else now
        return [
            record
            for record in sorted(self.records.values(), key=lambda item: item.created_at, reverse=True)
            if record.is_published(current, self.retention_seconds)
        ]

    def public_key_by_kid(self, kid: str):
        current = self.now_fn()
        record = self.records.get(kid)
        if record is None or not record.is_published(current, self.retention_seconds):
            return None
        return record.private_key.public_key()

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [public_jwk_for_key(record.kid, record.private_key) for record in self.published_records()]}

    def key_summary(self) -> dict[str, Any]:
        current = self.now_fn()
        published = self.published_records(current)
        return {
            "active_kid": self.active_kid,
            "published_kids": [record.kid for record in published],
            "retired_kids": [record.kid for record in self.records.values() if record.retired_at is not None],
            "retention_seconds": self.retention_seconds,
            "key_store_path": str(self.path),
            "keys": [
                {
                    "kid": record.kid,
                    "status": "active" if record.kid == self.active_kid else "retired",
                    "published": record.is_published(current, self.retention_seconds),
                    "created_at": record.created_at_iso,
                    "retired_at": record.retired_at_iso,
                }
                for record in sorted(self.records.values(), key=lambda item: item.created_at, reverse=True)
            ],
        }

    def rotate(self, retire_old: bool = True) -> dict[str, Any]:
        now = self.now_fn()
        previous_kid = self.active_kid
        if retire_old and previous_kid in self.records:
            self.records[previous_kid].retired_at = now
        new_record = KeyRecord.generate(now)
        self.records[new_record.kid] = new_record
        self.active_kid = new_record.kid
        self.prune_retired(now)
        self.save()
        return {
            "previous_kid": previous_kid,
            "active_kid": self.active_kid,
            "published_kids": [record.kid for record in self.published_records(now)],
            "retention_seconds": self.retention_seconds,
        }

    def prune_retired(self, now: float | None = None) -> list[str]:
        current = self.now_fn() if now is None else now
        removed: list[str] = []
        for kid, record in list(self.records.items()):
            if kid == self.active_kid or record.retired_at is None:
                continue
            if record.retired_at + self.retention_seconds <= current:
                removed.append(kid)
                del self.records[kid]
        return removed


KEY_STORE = RSAKeyStore()

# Compatibility snapshots for older local imports. New code should use KEY_STORE.
KEY_ID = KEY_STORE.active_kid
PRIVATE_KEY = KEY_STORE.active_private_key()
PUBLIC_KEY = KEY_STORE.active_public_key()


def jwks() -> dict[str, list[dict[str, str]]]:
    return KEY_STORE.jwks()
