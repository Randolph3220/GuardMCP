# GuardMCP

GuardMCP 是一个面向 MCP / OAuth 工具调用场景的课程原型项目，目标是验证“协议级最小权限 + Guard 策略检查”能否降低提示注入导致的高风险工具滥用。

当前仓库已经有几类核心模块：

- `auth_server/`：模拟 OAuth 授权服务，负责签发 JWT access token。
- `mcp_server/`：MCP-like 服务，提供初始化、工具列表和工具调用入口，并根据 token scope 做最小权限检查。
- `guard_proxy/`：Guard Proxy，负责拦截 `tools/call` 并按固定顺序执行策略检查。
- `agent_host/`：实验侧脚本，负责生成数据集、跑 baseline 和最小联调链路。

当前也已经补齐攻击数据集、实验结果目录、截图目录和接口契约文档。

## 目录责任

```
guardmcp/
├── auth_server/          # A 的 OAuth 服务
├── mcp_server/           # A 的 MCP 服务
├── guard_proxy/          # B 的目录
├── agent_host/           # C 的目录
├── attacks/              # C 的数据集
├── experiments/          # C 的实验结果
├── screenshots/          # 三人共享截图
└── docs/                 # 论文、PPT
```

## 运行环境

- 推荐 Python 版本：Python 3.12
- 当前依赖清单：`requirements.txt`
- 不要提交本地虚拟环境、密钥、日志、数据库或个人配置文件。

首次准备环境：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

如果本地已经有 `.venv`，只需要：

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## 当前启动方式

先启动授权服务：

```bash
python auth_server/app.py
```

默认监听：

```text
http://localhost:8001
```

再启动 MCP-like 服务：

```bash
python mcp_server/app.py
```

默认监听：

```text
http://localhost:8000
```

最后启动 Guard Proxy：

```bash
python guard_proxy/app.py
```

默认监听：

```text
http://localhost:8002
```

也可以用 `uvicorn` 启动：

```bash
uvicorn auth_server.app:app --host 0.0.0.0 --port 8001 --reload
uvicorn mcp_server.app:app --host 0.0.0.0 --port 8000 --reload
uvicorn guard_proxy.app:app --host 0.0.0.0 --port 8002 --reload
```

## 最小调用流程

1. 向授权服务申请 token：

```bash
curl -X POST http://localhost:8001/token \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","session_id":"session-001","scopes":["tools.list","files.read.public"]}'
```

2. 使用返回的 `access_token` 通过 Guard Proxy 初始化 MCP-like 服务：

```bash
curl -X POST http://localhost:8002/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

3. 查询工具列表：

```bash
curl -X POST http://localhost:8002/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

4. 调用文件读取工具：

```bash
curl -X POST http://localhost:8002/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files.read.public","arguments":{"path":"public/demo.txt"}}}'
```

当前 `tools/call` 会先进入 Guard Proxy 的 PolicyEngine，再转发给 MCP-like 服务。MCP Server 提供 mock runtime：文件读取限制在 `sandbox/`，邮件只写本地 `outbox.jsonl`，命令执行只允许只读白名单命令。

## 元数据和测试令牌

授权服务元数据：

```bash
curl http://localhost:8001/.well-known/oauth-authorization-server
```

JWKS 公钥发现：

```bash
curl http://localhost:8001/.well-known/jwks.json
```

授权服务会从 `.local/auth_keys.json` 加载/保存 RSA 私钥集合。可用 `AUTH_KEY_STORE_PATH` 指向自定义私钥文件，用 `AUTH_KEY_RETENTION_SECONDS` 配置旧 key 在 JWKS 中继续发布的保留窗口，默认 86400 秒。

查看当前 key 状态：

```bash
curl http://localhost:8001/keys
```

轮换签名 key：

```bash
curl -X POST http://localhost:8001/keys/rotate \
  -H "Content-Type: application/json" \
  -d '{"retire_old":true}'
```

授权服务 token 验证接口：

```bash
curl -X POST http://localhost:8001/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"<ACCESS_TOKEN>"}'
```

一次性生成 T1 到 T5 测试令牌：

```bash
curl http://localhost:8001/tokens/test
```

MCP 受保护资源元数据：

```bash
curl http://localhost:8000/.well-known/oauth-protected-resource
```

## 当前权限范围

| 工具名 | 当前 scope | 状态 |
| --- | --- | --- |
| `tools/list` | `tools.list` | 已注册，返回工具列表 |
| `files.read.public` | `files.read.public` | 读取 `sandbox/public/` 内文件 |
| `files.read.sensitive` | `files.read.sensitive` | 读取 `sandbox/sensitive/` 内文件，需要 Guard 确认 |
| `mail.send` | `mail.send` | 写入本地 `outbox.jsonl`，不发送真实邮件 |
| `shell.exec` | `shell.exec` | 只允许只读白名单命令，带超时和输出截断 |

如果 token 缺少目标工具所需 scope，Guard Proxy 或 MCP Server 会返回结构化 `scope_challenge`，并给出 `required_scopes`、`missing_scopes` 和 `resource_metadata_url`。

## Guard Proxy 当前行为

- `initialize` 和 `tools/list`：透传到 MCP Server。
- `tools/call`：必须先进入 `guard_proxy` 的 PolicyEngine。
- 当前 PolicyEngine 按固定顺序检查：intent 结构、工具存在、audience、scope、source_trace、参数、确认。
- Auth Server 当前使用 `RS256` 签发 token，私钥从文件加载，支持多 `kid` JWKS、key rotation 和旧 key 保留窗口；Guard Proxy 和 MCP Server 使用 JWKS 验证 token。
- 高风险工具会先返回 `user_confirm`，携带同一 `confirmation_hash` 在 TTL 内重放同一 intent 后才会继续执行。
- 确认状态持久化到 `experiments/confirmations.jsonl`，默认 TTL 为 300 秒；可用 `GUARD_CONFIRMATION_LOG_PATH` 和 `GUARD_CONFIRMATION_TTL_SECONDS` 改写。确认哈希一次性使用，过期、重复使用和参数变更都会被拒绝并记录。
- `files.read.sensitive` 在策略允许时可降级为 `files.read.public`，执行安全替代读取；无法降级执行时会返回 `alternatives` 建议。
- 策略配置从 `guard_proxy/policies/default_policy.json` 加载；可用 `GUARD_POLICY_PATH` 指向自定义策略文件。
- `tools/call` 会写入 JSONL 审计日志，默认路径是 `experiments/audit_log.jsonl`；可用 `GUARD_AUDIT_LOG_PATH` 改写。
- Guard Proxy 提供审计查询接口：`GET /audit/recent`、`GET /audit/{audit_id}`、`GET /audit/intent/{intent_id}`；`/audit/recent` 支持 `limit`、`intent_id` 和 `event_type` 查询参数。
- 兼容旧格式 `params.name` / `params.arguments`，也支持后续 Agent Host 使用 `params.intent` 传结构化 intent。

## Mock Runtime 当前行为

- 文件工具会把请求路径解析到 `sandbox/` 下，并二次确认最终路径没有逃出对应目录。
- `mail.send` 只追加写入 `outbox.jsonl`，该文件已在 `.gitignore` 中排除。
- `shell.exec` 使用 `subprocess.run(..., shell=False)`，工作目录固定为 `sandbox/`，只允许 `pwd`、`ls`、`cat`、`head`、`tail`、`wc`，超时为 2 秒，输出最多保留 4000 字符。

## 实验侧

数据集 schema 在 [`attacks/schema.md`](attacks/schema.md)，正式 case 文件是 `attacks/cases.jsonl`，共 100 条，覆盖正常任务、直接攻击、间接注入、参数攻击、工具输出二次注入和混淆攻击。重新生成数据集：

```bash
python agent_host/generate_cases.py
```

运行四类 baseline 并生成结果：

```bash
python agent_host/run_experiments.py
```

输出文件：

- `experiments/results.csv`
- `experiments/summary.csv`
- `experiments/summary_by_category.csv`

运行真实模型下的四类 baseline。该脚本对每条 case 只调用一次真实模型生成 intent，再把同一个 intent 分别送入 `Direct`、`Prompt-only`、`Scope-only`、`Full GuardMCP`：

```bash
export DEEPSEEK_API_KEY="<your-deepseek-api-key>"
python agent_host/run_online_baselines.py --limit 10
```

输出文件：

- `experiments/online_baseline_results.csv`
- `experiments/online_baseline_trace.jsonl`
- `experiments/online_baseline_summary.csv`
- `experiments/online_baseline_summary_by_category.csv`

生成并运行 degraded 专门实验：

```bash
python agent_host/generate_degraded_cases.py
export DEEPSEEK_API_KEY="<your-deepseek-api-key>"
python agent_host/run_online_baselines.py --suite degraded --limit all
```

输出文件：

- `experiments/online_degraded_results.csv`
- `experiments/online_degraded_trace.jsonl`
- `experiments/online_degraded_summary.csv`
- `experiments/online_degraded_summary_by_category.csv`

运行真实 DeepSeek 在线 Agent runner 前，先在当前 shell 设置 API key。不要把 key 写入代码或 README：

```bash
export DEEPSEEK_API_KEY="<your-deepseek-api-key>"
python agent_host/run_online_agent.py --limit 10
```

在线 runner 会调用真实模型生成结构化 intent，再通过 Guard Proxy 调用 MCP Server。默认模型为 `deepseek-v4-flash`，可用 `DEEPSEEK_MODEL` 或 `--model` 改写；默认输出：

- `experiments/online_agent_results.csv`
- `experiments/online_agent_trace.jsonl`
- `experiments/online_agent_summary.json`

为降低正常任务误拦截，online runner 会把 `is_attack=false` 的正常 case 对齐到数据集中的 `mock_intent`：邮件使用允许列表中的收件人，敏感文件固定为 `sensitive/secret.txt`，普通命令固定为 `cat public/demo.txt`。攻击 case 不做该改写。

## 前端展示控制台

`frontend/` 提供一个 Vite + React 的课程展示 UI，用于演示服务状态、最小链路场景、Guard 判定轨迹、策略矩阵、审计事件和真实模型实验结果。

先启动三个后端服务：

```bash
uvicorn auth_server.app:app --host 127.0.0.1 --port 8001
uvicorn mcp_server.app:app --host 127.0.0.1 --port 8000
uvicorn guard_proxy.app:app --host 127.0.0.1 --port 8002
```

再启动前端：

```bash
cd frontend
npm install
npm run dev
```

默认访问：

```text
http://127.0.0.1:5173
```

前端通过 Vite proxy 调用 `/auth`、`/mcp-server` 和 `/guard`，因此浏览器不会遇到 CORS 问题。演示台内置五个场景：公开文件读取、缺 scope challenge、间接注入拒绝、邮件确认后写入 outbox、敏感读取降级。

## 最小联调链路

第八部分的联调脚本会真实调用三个服务，覆盖：取 T1/T2/T3 token、通过 Guard 查工具列表、触发缺 scope challenge、正常读取公开文件、拒绝间接注入邮件、用户确认后写入 `outbox.jsonl`。

先启动服务。如果 `8000` 未被占用：

```bash
uvicorn auth_server.app:app --host 127.0.0.1 --port 8001
uvicorn mcp_server.app:app --host 127.0.0.1 --port 8000
uvicorn guard_proxy.app:app --host 127.0.0.1 --port 8002
```

如果 `8000` 被占用，可以把 MCP Server 放到 `8010`：

```bash
uvicorn auth_server.app:app --host 127.0.0.1 --port 8001
uvicorn mcp_server.app:app --host 127.0.0.1 --port 8010
MCP_SERVER_URL=http://127.0.0.1:8010/mcp uvicorn guard_proxy.app:app --host 127.0.0.1 --port 8002
```

然后运行：

```bash
python agent_host/run_minimal_chain.py
```

脚本会输出逐步 `[ok]` 状态，并写入：

- `experiments/minimal_chain_result.json`
- `experiments/audit_log.jsonl`，记录本次 `tools/call` 的 intent、decision 和 execution。
- `outbox.jsonl`，该文件是 mock 邮件运行时产物，已被 `.gitignore` 排除。

详细验收点见 [`docs/integration_check.md`](docs/integration_check.md)。

## 自动化测试

当前 pytest 覆盖策略配置加载、PolicyEngine 核心分支和审计日志写入：

```bash
python -m pytest
```

## 下一步开发目标

接口契约已经固定在 [`docs/interface_contract.md`](docs/interface_contract.md)，包括 token 字段表、intent 字段表、Guard 五类判定表、工具与权限表。A/B/C 后续开发都应优先对齐该文档。

1. 继续完善 B：补消融开关和更细的确认策略。
2. 扩展 C：用在线 Agent runner 跑完整 100 条真实模型实验，并补图表生成和论文评估段落。
3. 补联调截图和结果图表，用 `experiments/minimal_chain_result.json`、`experiments/audit_log.jsonl` 与三类 summary 表支持论文材料。
