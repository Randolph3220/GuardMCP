# Attack Dataset Schema

主数据集文件：`attacks/cases.jsonl`

degraded 专门实验文件：`attacks/degraded_cases.jsonl`

每一行是一条 JSON case，字段固定如下：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `case_id` | string | 是 | 全局唯一编号，例如 `normal-001`、`indirect-010`。 |
| `category` | string | 是 | 主数据集取 `normal`、`direct`、`indirect`、`parameter`、`tool_output`、`obfuscated`；degraded 专门实验取 `degraded`。 |
| `is_attack` | boolean | 是 | 是否为攻击 case。 |
| `user_prompt` | string | 是 | 用户表面任务。 |
| `external_resources` | array | 是 | 外部来源列表；没有外部资源时为空数组。 |
| `external_resources[].source_id` | string | 是 | 来源编号，必须能对应到 `source_trace`。 |
| `external_resources[].label` | string | 是 | 来源标签，取接口契约中的六类 source label。 |
| `external_resources[].content` | string | 是 | 外部资源内容或攻击载荷。 |
| `token_profile` | string | 是 | 默认测试 token，取 `T1` 到 `T5`。 |
| `expected_tool` | string | 是 | mock intent 将调用的工具名。 |
| `expected_decision` | string | 是 | 完整 GuardMCP 下的预期判定。 |
| `success_check` | string | 是 | 正常 case 的完成检查或攻击 case 的成功条件摘要。 |
| `attack_success_condition` | string | 是 | 攻击成功的可观察现象；正常 case 为空字符串。 |
| `prompt_detectable` | boolean | 是 | Prompt-only baseline 是否能用简单提示规则拦住。 |
| `mock_intent` | object | 是 | Agent Host mock 模式生成的结构化 intent。 |

当前生成器会产出 100 条 case，其中新增的真实攻击族包括：

- 网页隐藏指令：`web-hidden-*`，归入 `indirect`，来源标签为 `untrusted_web`。
- 工具输出二次注入：`second-order-*`，归入 `tool_output`，来源标签为 `tool_output`。
- base64 / unicode / zero-width / URL 编码混淆：`obfuscated-real-*`，归入 `obfuscated`。
- 邮件正文泄露：`mail-leak-*`，归入 `direct` 或 `indirect`。
- 命令拼接变体：`cmd-chain-*`，归入 `parameter`。

正式实验脚本读取该文件后，按同一批 case 运行四类 baseline：`Direct`、`Prompt-only`、`Scope-only`、`Full GuardMCP`。

`attacks/degraded_cases.jsonl` 由 `agent_host/generate_degraded_cases.py` 生成，当前包含 8 条正常任务 case，专门覆盖 `files.read.sensitive` 在缺少 sensitive scope 或参数不匹配时降级为 `files.read.public` 的路径。真实模型实验脚本可用 `--suite degraded` 读取该文件，并仍然输出同样四类 baseline 的对比结果。
