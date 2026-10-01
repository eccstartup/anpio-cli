---
title: 错误码
description: 公共码段与各 Profile 的私码段；哪些码带 anp_code，哪些走真实 HTTP 状态码。
---

# 错误码

一次拒绝长这样：JSON-RPC `error` 对象，`code` 是数字，**当 `code` 落在 ANP 自定义段
（1000+）时**，`error.data.anp_code` 一定在，客户端靠它分支，不要靠 `message` 文案。

```json
{ "jsonrpc": "2.0", "id": 1,
  "error": { "code": 1003, "message": "…",
             "data": { "anp_code": "anp.invalid_params_shape" } } }
```

两条规则：

- **进入业务层之后，一律 HTTP 200**，错误在信封里。非 2xx 是一个**响应**，不是一个异常。
- **外层 HTTP 认证失败**走真实状态码（`401`，带 `WWW-Authenticate`），因为那一层还没有
  JSON-RPC 信封。数据面另一个例外，见 [HTTP 端点](/reference/endpoints)。

## 标准 JSON-RPC 码

这几个不带 `anp_code`，靠 `message` 区分。

| 码 | 含义 |
|---|---|
| `-32700` | 解析失败 |
| `-32600` | 不是合法请求 |
| `-32601` | 没有这个方法 |
| `-32602` | 参数不合法 |
| `-32603` | 服务端内部错误 |

## 码段总表

| 段 | 归属 |
|---|---|
| 1000–1021 | P1 公共错误 |
| 2000–2007 | P3 私聊（`direct.*`） |
| 3000–3010 | P4 群组（**无 3004**） |
| 4000–4012 | P5 私聊 E2EE |
| 5000–5013 | P6 群组 E2EE |
| 6000–6013 | P7 附件 |

## 1000 段：公共（P1）

| 码 | `anp_code` |
|---|---|
| 1000 | `anp.invalid_request_id` |
| 1001 | `anp.unsupported_profile` |
| 1002 | `anp.unsupported_security_profile` |
| 1003 | `anp.invalid_params_shape` |
| 1004 | `anp.batch_not_supported` |
| 1005 | `anp.unauthorized` |
| 1006 | `anp.forbidden` |
| 1007 | `anp.target_not_found` |
| 1008 | `anp.idempotency_conflict` |
| 1009 | `anp.unsupported_content_type` |
| 1010 | `anp.delivery_rejected` |
| 1011 | `anp.rate_limited` |
| 1012 | `anp.temporarily_unavailable` |
| 1013 | `anp.invalid_security_binding` |
| 1014 | `anp.invalid_target_binding` |
| 1015 | `anp.device_binding_required` |
| 1016 | `anp.device_binding_invalid` |
| 1017 | `anp.device_not_eligible` |
| 1018 | `anp.device_state_changed` |
| 1019 | `anp.did_superseded` |
| 1020 | `anp.did_transition_invalid` |
| 1021 | `anp.did_transition_conflict` |

最常见的三个：

- **1003**：正文多一个字段、少一个字段，或 `params` 不是对象。群资料/策略的 merge patch
  在**应用之后**才校验，结构性违规也是 1003 而不是 3003。
- **1005**：`origin_proof` 验不过，或 `keyid` 所属 DID 不等于这次调用的锚点。
- **1014**：`meta.target` 形状对不上方法的 `targetMode`（**不是** 1003）。

## 2000 段：私聊（P3）

| 码 | `anp_code` |
|---|---|
| 2005 | `direct.invalid_origin_proof` |
| 2006 | `direct.origin_did_mismatch` |

这两条都在业务层 proof 的归属校验上：签名本身不对是 2005，签得对但签的 DID 不是这次调用
该有的锚点是 2006。跨域时外层认证失败不走这里，走 `401`。

## 3000 段：群组（P4）

| 码 | `anp_code` | 本服务是否发出 |
|---|---|---|
| 3000 | `group.not_member` | 是 |
| 3001 | `group.already_member` | 是 |
| 3002 | `group.admission_not_allowed` | **否**（没有产生它的路径） |
| 3003 | `group.policy_violation` | 是（权限不足、非 open-join 的 join、超 `max_members`） |
| 3005 | `group.member_conflict` | 是（曾退出后被重新激活的冲突路径） |
| 3006 | `group.security_mode_required` | 是（该走 P6 的操作走了 P4） |
| 3008 | `group.invalid_origin_proof` | 是 |
| 3009 | `group.origin_did_mismatch` | 是 |

群通知的锚点是 **`body.group_did`** 而不是 `meta.sender_did`——所以 3009 与 2006 判的不是
同一件事。见 [联邦与跨域](/guide/federation)。

## 4000 段：私聊 E2EE（P5）

| 码 | `anp_code` |
|---|---|
| 4000 | `anp.direct.e2ee.bundle_not_found` |
| 4001 | `anp.direct.e2ee.bundle_invalid` |
| 4003 | `anp.direct.e2ee.opk_unavailable` |
| 4012 | `anp.direct.e2ee.invalid_security_binding` |

`require_opk` 而池空时是 **4003**；池空但没要求 OPK 就正常返回不带 OPK 的 Bundle。
密钥方法的限流用公共的 **1011**，因为 4000 段里没有对应项。

## 5000 段：群组 E2EE（P6）

| 码 | `anp_code` |
|---|---|
| 5000 | `anp.group.e2ee.key_package_not_found` |
| 5001 | `anp.group.e2ee.invalid_key_package` |
| 5002 | `anp.group.e2ee.did_binding_invalid` |
| 5003 | `anp.group.e2ee.controller_required` |
| 5004 | `anp.group.e2ee.state_not_ready` |
| 5005 | `anp.group.e2ee.epoch_conflict` |
| 5006 | `anp.group.e2ee.crypto_group_mismatch` |
| 5007 | `anp.group.e2ee.private_message_invalid` |
| 5008 | `anp.group.e2ee.commit_invalid` |
| 5009 | `anp.group.e2ee.welcome_invalid` |
| 5010 | `anp.group.e2ee.fork_suspected` |
| 5011 | `anp.group.e2ee.notice_type_unsupported` |
| 5012 | `anp.group.e2ee.key_package_consumed` |
| 5013 | `anp.group.e2ee.leaf_not_current` |

## 6000 段：附件（P7）

| 码 | `anp_code` |
|---|---|
| 6000 | `anp.attachment.slot_not_found` |
| 6001 | `anp.attachment.slot_expired` |
| 6002 | `anp.attachment.commit_token_invalid` |
| 6003 | `anp.attachment.object_too_large` |
| 6005 | `anp.attachment.grant_not_found` |
| 6006 | `anp.attachment.unauthorized_requester` |
| 6007 | `anp.attachment.download_ticket_invalid` |
| 6008 | `anp.attachment.ticket_binding_mismatch` |
| 6009 | `anp.attachment.ticket_expired` |
| 6010 | `anp.attachment.digest_mismatch` |
| 6012 | `anp.attachment.object_unavailable` |
| 6013 | `anp.attachment.encryption_policy_violation` |

6007–6009 这一族**只在数据面出现**：控制面那一侧是签发，此时还没有令牌可判。

## 扩展面的错误

取件面（`inbox.*` / `message.get_batch` / `sync.delta`）与流（`stream.*`）是**实现扩展**。
它们把"没有这套扩展"表达成 `unsupported_extension`：一个只实现规范的服务答这个，
**不说明**它能不能送信。

## 下一步

- [HTTP 端点](/reference/endpoints) —— 哪些地方用真实状态码。
- [RPC 方法](/reference/rpc) —— 每个方法可能回哪些码。
- [附件](/guide/attachments) —— 6000 段背后的授权链。
