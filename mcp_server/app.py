from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, List
import jwt

app = FastAPI(title="MCP-like Server")
security = HTTPBearer()

SECRET_KEY = "guardmcp-secret-key-2026"
ALGORITHM = "HS256"
AUDIENCE = "mcp-resource"

TOOL_SCOPES = {
    "files.read": ["files.read"],
    "mail.send": ["mail.send"],
    "shell.exec": ["shell.exec"]
}


class ToolSchema(BaseModel):
    type: str = "object"
    properties: Dict[str, Any]
    required: List[str] = []


class Tool(BaseModel):
    name: str
    description: str
    inputSchema: ToolSchema


TOOLS = [
    Tool(
        name="files.read",
        description="Read a file from sandbox",
        inputSchema=ToolSchema(
            properties={"path": {"type": "string", "description": "File path"}},
            required=["path"]
        )
    ),
    Tool(
        name="mail.send",
        description="Send an email",
        inputSchema=ToolSchema(
            properties={
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"}
            },
            required=["to", "subject", "body"]
        )
    ),
    Tool(
        name="shell.exec",
        description="Execute a shell command",
        inputSchema=ToolSchema(
            properties={"command": {"type": "string"}},
            required=["command"]
        )
    )
]


# Token 校验
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # 校验 token 并返回 payload
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=AUDIENCE)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def check_scope(payload: dict, required_scopes: List[str]) -> tuple[bool, str]:
    token_scopes = payload.get("scope", "").split()
    missing = [s for s in required_scopes if s not in token_scopes]
    if missing:
        return False, f"Missing scopes: {', '.join(missing)}"
    return True, ""


# MCP JSON-RPC 入口
@app.post("/mcp")
async def mcp_endpoint(request: Request, token_payload: dict = Depends(verify_token)):
    # MCP 主入口，所有请求都需要 token
    body = await request.json()
    method = body.get("method")
    params = body.get("params", {})
    req_id = body.get("id")

    # initialize 和 tools/list 不需要 scope 检查
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "guardmcp", "version": "0.1"}
        }
    elif method == "tools/list":
        result = {"tools": [t.dict() for t in TOOLS]}
    elif method == "tools/call":
        # 检查 scope
        tool_name = params.get("name")
        required_scopes = TOOL_SCOPES.get(tool_name, [])
        ok, msg = check_scope(token_payload, required_scopes)
        if not ok:
            # 返回 scope challenge
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32001,
                    "message": "Insufficient scope",
                    "data": {
                        "required_scopes": required_scopes,
                        "missing_scopes": [s for s in required_scopes if
                                           s not in token_payload.get("scope", "").split()]
                    }
                },
                "id": req_id
            }

        # scope 足够，执行工具（占位）
        args = params.get("arguments", {})
        result = {
            "content": [{"type": "text", "text": f"Executed {tool_name} with args: {args}"}],
            "isError": False
        }
    else:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": f"Method not found: {method}"},
            "id": req_id
        }

    return {"jsonrpc": "2.0", "result": result, "id": req_id}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)