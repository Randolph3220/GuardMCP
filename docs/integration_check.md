# 最小联调链路说明

本文档用于第八部分联调验收：跑通 `取 token -> 过 Guard -> 查工具列表 -> 缺 scope challenge -> 正常文件读取 -> 间接注入被拒 -> 邮件确认后写 outbox`。

## 启动三个服务

默认端口：

```bash
uvicorn auth_server.app:app --host 127.0.0.1 --port 8001
uvicorn mcp_server.app:app --host 127.0.0.1 --port 8000
uvicorn guard_proxy.app:app --host 127.0.0.1 --port 8002
```

如果 `8000` 被占用，可以把 MCP Server 放到 `8010`，并让 Guard Proxy 指向新的 MCP 地址：

```bash
uvicorn auth_server.app:app --host 127.0.0.1 --port 8001
uvicorn mcp_server.app:app --host 127.0.0.1 --port 8010
MCP_SERVER_URL=http://127.0.0.1:8010/mcp uvicorn guard_proxy.app:app --host 127.0.0.1 --port 8002
```

## 执行联调脚本

```bash
python agent_host/run_minimal_chain.py
```

脚本默认访问：

- Auth Server: `http://127.0.0.1:8001`
- Guard Proxy: `http://127.0.0.1:8002`

如需改地址：

```bash
AUTH_SERVER_URL=http://127.0.0.1:8001 GUARD_PROXY_URL=http://127.0.0.1:8002 python agent_host/run_minimal_chain.py
```

## 验收点

| 步骤 | 期望结果 | 说明 |
| --- | --- | --- |
| 取 token | 成功拿到 T1/T2/T3 | 通过 `auth_server` 的 `/tokens/test` 获取测试令牌。 |
| 过 Guard 查工具列表 | `tools/list` 成功 | T1 具备 `tools.list`，Guard 对该方法透传到 MCP Server。 |
| 缺 scope challenge | 返回 `scope_challenge` | T1 调 `files.read.public` 缺少 `files.read.public` scope。 |
| 正常文件读取 | 返回 `allow` | T2 读取 `sandbox/public/demo.txt`，响应中包含 Guard allow trace。 |
| 间接注入被拒 | 返回 `deny`，`failed_check=source_trace` | T3 试图基于 `untrusted_web` 来源发送邮件，Guard 在来源检查阶段拒绝。 |
| 邮件确认 | 先 `user_confirm`，再 `allow` | T3 对用户来源邮件先触发确认，携带 `confirmation_hash` 重放后写入 `outbox.jsonl`。 |

## 输出材料

脚本会重建 `outbox.jsonl`，并把完整联调摘要写入：

```text
experiments/minimal_chain_result.json
```

同时 Guard Proxy 会写入：

```text
experiments/audit_log.jsonl
```

结果文件中包含每一步的 `decision`、`failed_check`、缺失 scope、工具名和最终 outbox 记录。审计日志按 JSONL 记录 `intent`、`decision`、`execution` 三类事件，可直接用于报告或截图说明。
