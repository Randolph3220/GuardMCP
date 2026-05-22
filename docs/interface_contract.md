# GuardMCP Interface Contract

本文档固定 A/B/C 三条开发线共享的接口契约。后续代码、数据集、实验脚本、README 和论文说明都应优先对齐本文档；如果确实需要变更字段或枚举值，先修改本文档并通知另外两名成员。

## 基本常量

- OAuth issuer: `oauth-server`
- MCP resource audience: `mcp-resource`
- JWT algorithm: 当前原型为 `RS256`。
- JWKS URI: `http://localhost:8001/.well-known/jwks.json`
- JWKS key policy: 授权服务从私钥文件加载 key set，支持多个 `kid`、`POST /keys/rotate` 轮换和旧 key 保留窗口。
- Authorization header: `Authorization: Bearer <access_token>`
- JSON-RPC version: `2.0`
- Source labels: `system`、`user`、`trusted_resource`、`tool_output`、`untrusted_document`、`untrusted_web`
- Guard decisions: `allow`、`deny`、`scope_challenge`、`user_confirm`、`degraded`

## 1. Token 字段表

JWT 由 `auth_server` 签发，由 `guard_proxy` 验证。`mcp_server` 在直连调试阶段也可以验证 token，但完整链路中不应绕过 Guard。

| 字段 | 位置 | 类型 | 必填 | 固定值/示例 | 说明 | 使用方 |
| --- | --- | --- | --- | --- | --- | --- |
| `iss` | JWT claim | string | 是 | `oauth-server` | 签发方。Guard 必须校验，防止接受未知授权服务签发的 token。 | A 签发，B 验证 |
| `sub` | JWT claim | string | 是 | `alice` | 用户标识。审计日志和确认会话需要记录该值。 | A/B/C |
| `aud` | JWT claim | string | 是 | `mcp-resource` | 资源受众。必须绑定到 MCP 资源，避免 token 被挪用到其他服务。 | A 签发，B 验证 |
| `scope` | JWT claim | string | 是 | `tools.list files.read.public` | 空格分隔的权限范围。申请什么权限就签什么权限，不默认授予全权限。 | A 签发，B/C 使用 |
| `exp` | JWT claim | integer/datetime | 是 | `now + 3600s` | 过期时间。过期 token 返回认证失败，不进入策略引擎。 | A 签发，B 验证 |
| `iat` | JWT claim | integer/datetime | 是 | `now` | 签发时间。用于调试、审计和复现实验。 | A/B/C |
| `jti` | JWT claim | string | 是 | UUID | token 唯一编号。用于审计和排查重复 token。 | A/B |
| `session_id` | JWT claim | string | 是 | `session-001` | 会话编号。Guard 确认绑定机制必须使用该字段做会话键。 | A/B/C |
| `user_id` | `/token` request | string | 是 | `alice` | 签发请求中的用户标识，写入 JWT `sub`。 | A/C |
| `scopes` | `/token` request | string array | 是 | `["tools.list"]` | 申请的权限数组，签发后合并为 JWT `scope` 字符串。 | A/C |
| `expires_in` | `/token` response | integer | 是 | `3600` | access token 有效秒数。实验脚本需要据此刷新 token。 | A/C |
| `access_token` | `/token` response | string | 是 | JWT | Bearer token 本体。 | A/B/C |
| `token_type` | `/token` response | string | 是 | `Bearer` | token 使用方式。 | A/B/C |

认证失败不属于 Guard 五类策略判定。缺少 token、签名错误、受众错误、签发方错误、过期和格式错误应作为认证失败独立记录。

## 2. Intent 字段表

Intent 由 `agent_host` 生成，由 `guard_proxy` 校验。模型或 mock 生成器不能用自然语言直接驱动工具调用，必须输出结构化 intent。

| 字段 | 类型 | 必填 | 示例 | 说明 | 生成/使用方 |
| --- | --- | --- | --- | --- | --- |
| `intent_id` | string | 是 | `intent-0001` | 一次工具意图的唯一编号。需要写入审计日志，并与实验结果表关联。 | C 生成，B 使用 |
| `session_id` | string | 是 | `session-001` | 必须与 token 中的 `session_id` 一致，否则 Guard 拒绝。 | C 生成，B 校验 |
| `tool_name` | string | 是 | `files.read.public` | 目标工具名。必须出现在工具与权限表中，未知工具默认拒绝。 | C 生成，B 校验 |
| `tool_args` | object | 是 | `{"path":"public/demo.txt"}` | 工具参数。Guard 必须在执行前做 schema 和参数约束检查。 | C 生成，B/MCP 使用 |
| `purpose` | string | 是 | `Summarize a public file requested by the user.` | 调用目的。用于审计和人工分析，不作为绕过策略的依据。 | C 生成，B 记录 |
| `source_trace` | array | 是 | `[{"source_id":"src-user-1","label":"user"}]` | 来源追踪数组。高风险工具遇到不可信来源时必须拒绝或进入更严格流程。 | C 生成，B 校验 |
| `source_trace[].source_id` | string | 是 | `src-web-1` | 来源唯一编号。用于把 intent 与 case 中的外部资源关联。 | C/B |
| `source_trace[].label` | enum | 是 | `untrusted_web` | 来源标签，只能取基本常量中的六种值。不得临时创造新标签。 | C/B |
| `source_trace[].description` | string | 否 | `External webpage loaded by the agent.` | 来源说明，方便审计和论文案例解释。 | C/B |
| `risk_ack` | boolean | 是 | `false` | 模型是否承认存在风险。该字段只用于记录，不能替代用户确认。 | C 生成，B 记录 |
| `requested_at` | string | 否 | `2026-05-22T10:00:00Z` | intent 生成时间。实验脚本可用于延迟统计。 | C/B |
| `confirmation_hash` | string | 否 | `sha256:...` | 用户确认后的哈希。只能由 Guard 校验，不能由模型自称确认。 | B/C |

最小有效 intent 示例：

```json
{
  "intent_id": "intent-0001",
  "session_id": "session-001",
  "tool_name": "files.read.public",
  "tool_args": {"path": "public/demo.txt"},
  "purpose": "Read a public file explicitly requested by the user.",
  "source_trace": [
    {"source_id": "src-user-1", "label": "user", "description": "User prompt"}
  ],
  "risk_ack": false
}
```

## 3. Guard 五类判定表

`guard_proxy` 收到 `tools/call` 后必须按固定顺序检查：intent 结构、工具存在、资源受众、scope、来源、参数、确认。任何一步失败立即返回对应判定。`initialize` 和 `tools/list` 可以透传或做轻量鉴权，但真正的 `tools/call` 不允许绕过策略引擎。

| 判定值 | 中文名 | 触发条件 | 是否执行工具 | 必须返回字段 | 审计要求 |
| --- | --- | --- | --- | --- | --- |
| `allow` | 允许 | intent、token、scope、来源、参数和确认状态全部通过。 | 是 | `decision`、`audit_id`、`tool_name`、`result` | 写入 `intent`、`decision`、`execution` 三类记录。 |
| `deny` | 拒绝 | 结构无效、未知工具、受众错误、不可信来源、参数违规、确认哈希无效等不可通过重新授权解决的问题。 | 否 | `decision`、`audit_id`、`reason`、`failed_check` | 写入 `intent` 和 `decision`，不得写入 `execution`。 |
| `scope_challenge` | 权限挑战 | token 有效，但缺少目标工具所需 scope。 | 否 | `decision`、`audit_id`、`missing_scopes`、`required_scopes`、`resource_metadata_url`、`message` | 记录缺失 scope、工具名、用户和 intent 编号。 |
| `user_confirm` | 用户确认 | scope、来源和参数通过，但工具风险等级要求用户确认，且当前会话没有有效确认。 | 否 | `decision`、`audit_id`、`tool_name`、`display_args`、`confirmation_hash`、`expires_at`、`expires_in_seconds`、`message` | 记录确认哈希、会话、intent 编号和参数摘要。 |
| `degraded` | 降级执行 | 原始工具风险过高，但策略允许用更安全工具替代执行。 | 是，执行替代工具 | `decision`、`audit_id`、`original_tool`、`degraded_tool`、`result`、`reason` | 记录原始工具、替代工具和降级原因。 |

当前默认策略中，`files.read.sensitive` 可在 `scope`、`source_trace` 或 `arguments` 检查无法按原工具安全通过时，降级为 `files.read.public` 并读取 `public/demo.txt`。如果 token 连替代工具的 scope 也没有，Guard 返回原判定并附带 `alternatives` 建议，而不会执行工具。

推荐 JSON-RPC 响应形状：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "decision": "scope_challenge",
    "audit_id": "audit-0001",
    "missing_scopes": ["mail.send"],
    "required_scopes": ["mail.send"],
    "resource_metadata_url": "http://localhost:8000/.well-known/oauth-protected-resource",
    "message": "Token is valid but lacks the required scope for mail.send."
  }
}
```

## 4. 工具与权限表

工具名、scope、风险等级和参数约束必须三方一致。C 的数据集和 B 的策略配置都应直接使用本表中的规范名称。

| 名称 | 类型 | 用途 | 所需 scope | 风险等级 | 允许来源 | 是否需要确认 | 关键参数约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `initialize` | MCP method | 初始化 MCP-like 服务，返回协议版本和服务信息。 | 无，需有效 token | low | `system`、`user` | 否 | 不接受工具参数。 |
| `tools/list` | MCP method | 查询可用工具列表。 | `tools.list` | low | `system`、`user` | 否 | 只能返回工具 schema，不执行工具。 |
| `files.read.public` | tool | 读取 sandbox 中公开文件。 | `files.read.public` | low | `user`、`trusted_resource` | 否 | 路径必须位于 `sandbox/public/`，禁止路径穿越和系统目录。 |
| `files.read.sensitive` | tool | 读取 sandbox 中敏感文件，用于高风险实验。 | `files.read.sensitive` | high | `user` | 是 | 路径必须位于 `sandbox/sensitive/`，禁止路径穿越、私钥目录和系统目录。 |
| `mail.send` | tool | 模拟发送邮件，只写入本地 `outbox.jsonl`。 | `mail.send` | high | `user` | 是 | 收件人必须在允许列表中，正文长度受限，不能真实连接邮件服务器。 |
| `shell.exec` | tool | 执行极少数只读命令，用于命令执行风险实验。 | `shell.exec` | critical | `user` | 是，后续可升级为双重确认 | 命令第一个词必须在白名单中，禁止删除、下载、远程连接、提权、管道和命令拼接。 |

五类测试 token 应使用以下权限组合：

- T1: `tools.list`
- T2: `tools.list files.read.public`
- T3: `tools.list mail.send`
- T4: `tools.list files.read.sensitive mail.send`
- T5: `tools.list files.read.public files.read.sensitive mail.send shell.exec`

## 当前代码待对齐事项

- 当前原型已使用 `RS256` 非对称签名，授权服务从 `.local/auth_keys.json` 或 `AUTH_KEY_STORE_PATH` 加载私钥集合，通过 `/.well-known/jwks.json` 和 `/jwks` 发布保留窗口内的公钥；`guard_proxy` 与 `mcp_server` 通过 JWKS 验证 access token。
- 当前 Guard Proxy 已经保证 `tools/call` 进入 PolicyEngine，并按固定顺序完成 intent 结构、工具存在、audience、scope、source_trace、参数、确认检查。
- 当前 Guard Proxy 策略已拆到 `guard_proxy/policies/default_policy.json`，运行时可用 `GUARD_POLICY_PATH` 指向自定义策略文件。
- 当前 Guard Proxy 已将 `tools/call` 的 `intent`、`decision`、`execution` 三类审计事件写入 JSONL，默认路径为 `experiments/audit_log.jsonl`，运行时可用 `GUARD_AUDIT_LOG_PATH` 改写；查询接口包括 `GET /audit/recent`、`GET /audit/{audit_id}`、`GET /audit/intent/{intent_id}`。
- 当前确认状态已持久化到 `experiments/confirmations.jsonl`，默认 TTL 为 300 秒，可用 `GUARD_CONFIRMATION_LOG_PATH` 和 `GUARD_CONFIRMATION_TTL_SECONDS` 改写；过期、一次性使用和重放检测均已落地。
- 当前 Agent Host 已有 mock/offline runner 和 DeepSeek 在线 runner；在线 runner 会用真实模型生成结构化 intent 后调用 Guard Proxy。
- 当前 MCP Server 已接入文件、邮件和命令 mock runtime；后续还需要补更完整的消融开关。
- 当前 `guard_proxy` 和 `mcp_server` 返回的 `audit_id` 已可用于审计日志关联，`GET /audit/{audit_id}` 会返回命中事件和同一 request/intent 的关联事件。
