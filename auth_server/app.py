from fastapi import FastAPI
from pydantic import BaseModel
import jwt
import uuid
from datetime import datetime, timedelta

app = FastAPI(title="OAuth Authorization Server")

SECRET_KEY = "guardmcp-secret-key-2026"  # 共享密钥，简化版
ALGORITHM = "HS256"
AUDIENCE = "mcp-resource"

class TokenRequest(BaseModel):
    user_id: str = "alice"
    session_id: str = "session-001"
    scopes: list[str] = ["files.read"]

@app.post("/token")
async def issue_token(req: TokenRequest):
    # 签发 JWT token
    now = datetime.utcnow()
    payload = {
        "iss": "oauth-server",
        "sub": req.user_id,
        "aud": AUDIENCE,
        "scope": " ".join(req.scopes),
        "exp": now + timedelta(hours=1),
        "iat": now,
        "jti": str(uuid.uuid4()),
        "session_id": req.session_id
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)