---
title: RPC 方法
description: POST /anp-im/rpc 认得的 27 个方法，按 Profile 分段，附目标类型与通知清单。
---

# RPC 方法

控制面是 `POST /anp-im/rpc`，载荷是一份 JSON-RPC 2.0 信封。**请求**（带 `id`）打到这张
方法表上；服务端推给客户端的是**通知**（不带 `id`）。流上另有两个传输方法，见
[实时订阅](/reference/stream)。

信封的键固定为 `{meta, auth, body}`：`meta` 放寻址与签名上下文，`auth` 放 `origin_proof`，
`body` 放这个方法自己的字段。**规范没有定义的 body 字段一个都不许出现**，多一个就是
`anp.invalid_params_shape`（1003）。

## 目标类型

`meta.target` 的形状由方法决定，给错是 `anp.invalid_target_binding`（1014），不是 1003：

| `targetMode` | `meta.target` | 例子 |
|---|---|---|
| `endpoint-local` | 可省略 | `anp.get_capabilities` |
| `agent-addressed` | `{kind:"agent", did}` | `direct.send` |
| `group-addressed` | `{kind:"group", did}` | `group.send` |
| `service-scoped` | `{kind:"service", did: <serviceDid>}` | `attachment.*`、钥匙柜 |
| `self-addressed` | `{kind:"agent", did: <自己>}` | 取件面扩展方法 |

## 方法表（27 个）

### P1 核心绑定

| 方法 | 目标 | 说明 |
|---|---|---|
| `anp.get_capabilities` | `endpoint-local` | 能力探测。**唯一可以匿名调用**的方法，无 `target`、无 `operation_id`、无正文规则 |

### P3 私聊

| 方法 | 目标 | 说明 |
|---|---|---|
| `direct.send` | `agent-addressed` | 投递一条私聊消息。必带 `sender_did`、`operation_id`、`message_id`、`content_type` |

### P4 群组

| 方法 | 目标 | 说明 |
|---|---|---|
| `group.create` | `service-scoped` | 建群；必须带 `body.group_policy` |
| `group.get_info` | `group-addressed` | 群资料；**可匿名**（`private` 群按身份裁剪） |
| `group.join` | `group-addressed` | 加入 |
| `group.add` | `group-addressed` | 拉人（`left` / `removed` 会被重新激活） |
| `group.remove` | `group-addressed` | 移除 |
| `group.leave` | `group-addressed` | 退出 |
| `group.update_profile` | `group-addressed` | RFC 7386 merge patch，应用后校验 |
| `group.update_policy` | `group-addressed` | 同上 |
| `group.send` | `group-addressed` | 群消息；只推进 `group_event_seq` |

### P5 私聊端到端加密

| 方法 | 目标 | 说明 |
|---|---|---|
| `direct.e2ee.publish_prekey_bundle` | `service-scoped` | 发布设备预共享钥束 |
| `direct.e2ee.get_prekey_bundle` | `service-scoped` | 领取；目标设备写在 `body.target_device_id`，每次消耗一个 OPK |

这两条的幂等键不同：`get` 比 `publish` 多带 `target_did` / `target_device_id`；"幂等记录 +
OPK 分配"必须原子，同一键重试拿回**同一个** OPK。

### P6 群组端到端加密（候选）

| 方法 | 目标 | 说明 |
|---|---|---|
| `group.e2ee.publish_key_package` | `service-scoped` | 发布 KeyPackage |
| `group.e2ee.get_key_package` | `service-scoped` | 领取；三态 `available → reserved → consumed` |
| `group.e2ee.create` | `service-scoped` | 建加密群（Host 只记公开投影） |
| `group.e2ee.add` | `group-addressed` | 成员变更；`commit_b64u` / `welcome_b64u` / `ratchet_tree_b64u` 原样转发 |
| `group.e2ee.remove` | `group-addressed` | 同上 |
| `group.e2ee.send` | `group-addressed` | 加密群消息；入 Device Delivery Queue |

> [!NOTE]
> P6 目前是**候选**：整段能力不会出现在 `anp.get_capabilities` 的稳定 Profile 列表里，
> 直到 MLS 的 `ExtensionType` code point 注册落地。

### P7 附件

| 方法 | 目标 | 说明 |
|---|---|---|
| `attachment.create_slot` | `service-scoped` | 开上传槽位，给 `upload_uri` + `commit_token` |
| `attachment.commit_object` | `service-scoped` | 校验 size + digest，落 `object_uri` |
| `attachment.abort_object` | `service-scoped` | 放弃槽位（终态） |
| `attachment.get_download_ticket` | `service-scoped` | 签发短时下载票据，跑七条检查 |

前三个都**不**授予下载权；Grant 只在承载清单的消息被受理时产生。

### 取件面（实现扩展 `x_agentx.inbox.v1`）

| 方法 | 目标 | 说明 |
|---|---|---|
| `inbox.get` | `self-addressed` | 列出待收消息（`limit`、`skip`、`include_read`、`device_id`） |
| `inbox.mark_read` | `self-addressed` | 标记已读 |
| `message.get_batch` | `self-addressed` | 按 id 批量取，一次最多 100 个 |
| `sync.delta` | `self-addressed` | 按设备游标补齐，是订阅握手的一部分 |

这一组**不是规范**：规范刻意不管历史与已读状态，只实现规范的服务会答
`unsupported_extension`。它也不是规范能力，所以不进 `anp.get_capabilities`。

## 通知（服务端 → 客户端，无 `id`）

| 通知 | 何时 |
|---|---|
| `direct.incoming` | 一条私聊消息落进收件人队列 |
| `group.incoming` | 一条群消息落进成员队列 |
| `group.state_changed` | 成员变更 / 资料或策略变更，可重放来源是 `group_events` |
| `group.e2ee.notice` | P6 的密码学通告 |

`direct.incoming` **不是**跨域传输——它是同域内"入口服务 → 收件人端点"的最后一跳。跨域
转发的一律是原始业务方法。见 [联邦与跨域](/guide/federation)。

## 幂等

按 `(sender_did, target_scope, method, operation_id)` 记账：

- 同一个键重放，返回**同一次**的结果，不重复落库。
- 同一个键、不同内容 → `anp.idempotency_conflict`（1008）。
- 不改状态的方法（如 `anp.get_capabilities`）没有 `targetScope`，不进台账。

## 下一步

- [错误码](/reference/errors) —— 各 Profile 的码段。
- [HTTP 端点](/reference/endpoints) —— 路由、状态码与能力清单。
- [实时订阅](/reference/stream) —— 通知从哪条连接出去。
