import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import jwt

try:
    from auth_server.keys import KEY_STORE
except ImportError:
    from keys import KEY_STORE

app = FastAPI(title="OAuth Authorization Server")

ALGORITHM = "RS256"
ISSUER = "oauth-server"
AUDIENCE = "mcp-resource"
AUTH_SERVER_BASE_URL = "http://localhost:8001"
MCP_RESOURCE_METADATA_URL = "http://localhost:8000/.well-known/oauth-protected-resource"
JWKS_URL = f"{AUTH_SERVER_BASE_URL}/.well-known/jwks.json"
DEFAULT_EXPIRES_IN = 3600

SUPPORTED_SCOPES = [
    "tools.list",
    "files.read.public",
    "files.read.sensitive",
    "mail.send",
    "shell.exec",
]

TEST_TOKEN_PROFILES = {
    "T1": {
        "description": "Only list tools; used to trigger scope challenges for concrete tools.",
        "scopes": ["tools.list"],
    },
    "T2": {
        "description": "List tools and read public files.",
        "scopes": ["tools.list", "files.read.public"],
    },
    "T3": {
        "description": "List tools and send mail.",
        "scopes": ["tools.list", "mail.send"],
    },
    "T4": {
        "description": "Sensitive-read plus mail combination for high-risk experiments.",
        "scopes": ["tools.list", "files.read.sensitive", "mail.send"],
    },
    "T5": {
        "description": "Full-permission direct baseline token; do not use as the default token.",
        "scopes": [
            "tools.list",
            "files.read.public",
            "files.read.sensitive",
            "mail.send",
            "shell.exec",
        ],
    },
}


class TokenRequest(BaseModel):
    user_id: str = "alice"
    session_id: str = "session-001"
    scopes: list[str] = Field(default_factory=lambda: ["tools.list"])
    expires_in: int = Field(default=DEFAULT_EXPIRES_IN, gt=0, le=86400)


class VerifyRequest(BaseModel):
    token: str


class RotateKeyRequest(BaseModel):
    retire_old: bool = True


def build_access_token(
    user_id: str,
    session_id: str,
    scopes: list[str],
    expires_in: int = DEFAULT_EXPIRES_IN,
) -> tuple[str, dict[str, Any]]:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "scope": " ".join(scopes),
        "exp": now + timedelta(seconds=expires_in),
        "iat": now,
        "jti": str(uuid.uuid4()),
        "session_id": session_id,
    }
    token = jwt.encode(
        payload,
        KEY_STORE.active_private_key(),
        algorithm=ALGORITHM,
        headers={"kid": KEY_STORE.active_kid},
    )
    return token, payload


def public_key_for_token(token: str):
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise jwt.InvalidTokenError("Invalid token header") from exc
    if header.get("alg") != ALGORITHM:
        raise jwt.InvalidTokenError("Unsupported token signing algorithm")
    kid = header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("Missing token key id")
    public_key = KEY_STORE.public_key_by_kid(kid)
    if public_key is None:
        raise jwt.InvalidTokenError("Unknown or expired token key id")
    return public_key


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        public_key_for_token(token),
        algorithms=[ALGORITHM],
        audience=AUDIENCE,
        issuer=ISSUER,
    )


def validate_scopes(scopes: list[str]) -> None:
    unsupported = [scope for scope in scopes if scope not in SUPPORTED_SCOPES]
    if unsupported:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_scope",
                "unsupported_scopes": unsupported,
                "scopes_supported": SUPPORTED_SCOPES,
            },
        )


@app.post("/token")
async def issue_token(req: TokenRequest):
    validate_scopes(req.scopes)
    token, payload = build_access_token(
        user_id=req.user_id,
        session_id=req.session_id,
        scopes=req.scopes,
        expires_in=req.expires_in,
    )
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": req.expires_in,
        "scope": payload["scope"],
        "audience": AUDIENCE,
        "issuer": ISSUER,
        "session_id": req.session_id,
    }


@app.post("/verify")
async def verify_token(req: VerifyRequest):
    try:
        claims = decode_access_token(req.token)
        return {"active": True, "claims": claims}
    except jwt.ExpiredSignatureError:
        return {"active": False, "error": "token_expired"}
    except jwt.InvalidAudienceError:
        return {"active": False, "error": "invalid_audience"}
    except jwt.InvalidIssuerError:
        return {"active": False, "error": "invalid_issuer"}
    except jwt.InvalidSignatureError:
        return {"active": False, "error": "invalid_signature"}
    except jwt.InvalidTokenError:
        return {"active": False, "error": "invalid_token"}


@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return {
        "issuer": ISSUER,
        "token_endpoint": f"{AUTH_SERVER_BASE_URL}/token",
        "token_verification_endpoint": f"{AUTH_SERVER_BASE_URL}/verify",
        "test_tokens_endpoint": f"{AUTH_SERVER_BASE_URL}/tokens/test",
        "jwks_uri": JWKS_URL,
        "key_rotation_endpoint": f"{AUTH_SERVER_BASE_URL}/keys/rotate",
        "protected_resources": [AUDIENCE],
        "protected_resource_metadata": MCP_RESOURCE_METADATA_URL,
        "scopes_supported": SUPPORTED_SCOPES,
        "grant_types_supported": ["urn:guardmcp:test-token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "token_signing_alg_values_supported": [ALGORITHM],
    }


@app.get("/metadata")
async def metadata_alias():
    return await authorization_server_metadata()


@app.get("/.well-known/jwks.json")
async def jwks_metadata():
    return KEY_STORE.jwks()


@app.get("/jwks")
async def jwks_alias():
    return KEY_STORE.jwks()


@app.get("/keys")
async def keys_metadata():
    return KEY_STORE.key_summary()


@app.post("/keys/rotate")
async def rotate_signing_key(req: RotateKeyRequest = RotateKeyRequest()):
    rotation = KEY_STORE.rotate(retire_old=req.retire_old)
    return {
        "rotated": True,
        "jwks_uri": JWKS_URL,
        **rotation,
    }


@app.get("/tokens/test")
async def issue_test_tokens():
    profiles = {}
    for name, profile in TEST_TOKEN_PROFILES.items():
        token, payload = build_access_token(
            user_id="alice",
            session_id=f"session-{name.lower()}",
            scopes=profile["scopes"],
            expires_in=DEFAULT_EXPIRES_IN,
        )
        profiles[name] = {
            "description": profile["description"],
            "scopes": profile["scopes"],
            "scope": payload["scope"],
            "session_id": payload["session_id"],
            "access_token": token,
        }
    return {
        "token_type": "Bearer",
        "expires_in": DEFAULT_EXPIRES_IN,
        "audience": AUDIENCE,
        "issuer": ISSUER,
        "profiles": profiles,
    }

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "algorithm": ALGORITHM,
        "jwks_uri": JWKS_URL,
        **KEY_STORE.key_summary(),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
