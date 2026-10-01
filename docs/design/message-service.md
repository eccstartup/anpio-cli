# AgentXAgent —— ANPMessageService 设计

`packages/service` —— 本仓库的服务端。产品名 **AgentXAgent**。

它同时扮演两个角色（同一进程、同一存储）：

- **ANPMessageService** —— 接收、持久化、投递 agent 之间的消息（P1 / P2 / P3 / P5 / P7 / P8）
- **Group Host Service** —— 群状态的排序与持久化（P4 / P6）

---

## 1. 定位与边界

### 它是

- 一个**收件人域的入口服务**。消息存在这里，不是发件人那里，也不是路由中间。
- 一个**只认 DID 定址**的服务。
- 一个**看不见明文**的服务（一旦用了 P5 / P6）。

### 它不是

| 不是 | 归属 |
|---|---|
| DID Service（托管 `did.json`、发 handle） | 兄弟仓库 `awiki-open-server` |
| 应用服务端（登录、签发站点 token） | `agent-on` 一类的站点 |
| 中继 / 网关 | **规范里没有这种东西**（P8 §3.1 明确不新增 Relay 方法） |
| 客户端库 | `packages/core` + `packages/cli` |

**`AgentXAgent` 不托管 DID 文档，但需要解析它们**——发件人身份、入口服务发现、群成员校验都要。

### 成功语义（这条决定了整个架构）

`direct.send` 返回成功**只**表示"目标 Agent 的入口服务已接受、已进入协议处理边界"。
**不**表示已展示、已处理、**甚至不表示已完成内部持久化**（P3 §3.3）。

因此：

- 与"收件人在不在线"**彻底解耦**——这才是敢不做点到点的原因。
- 响应可以在持久化**之前**发出。但那样重启会丢消息——所以本设计的实际选择是
  **先落库再响应**（见 §6）。规范给的是下限：`accepted` 的含义是"进入了处理边界"，
  落库后响应是最强的实现，也是最省事的。

## 2. 架构

```
                    ┌─────────────────────────────────────┐
   POST /anp-im/rpc │  HTTP 层（node:http）                │
   ────────────────►│   · 单请求，禁 batch                 │
                    │   · 读 body / content-digest 校验    │
   GET /anp-im/     │                                      │
   stream (WS) ────►│   · 升级后每帧一个 JSON-RPC 信封      │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Envelope 校验（P1）                 │
                    │   jsonrpc / id / params / meta 白名单 │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Auth（P1 附录 A + P8 §6）           │
                    │   origin_proof 验签 + caller anchor  │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Idempotency                         │
                    │   (sender_did, target, method, op)   │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Dispatcher（按 method 分派）         │
                    └──────────────┬──────────────────────┘
                                   ▼
   ┌───────────────┬───────────────┼───────────────┬───────────────┐
   ▼               ▼               ▼               ▼               ▼
 inbox          group           e2ee          attachment       outbox
 (P3)           (P4/P6)         (P5/P6)       (P7)             (推送)
   └───────────────┴───────────────┴───────────────┴───────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Storage（node:sqlite，接口化）       │
                    └─────────────────────────────────────┘
```

**运行环境**：TypeScript，**服务端要求 Node ≥ 24**。存储用 **`node:sqlite`**——
它自 Node 22.5 起存在，但直到 **Node 24 才转正**（22.5–23 上每次启动都打
`ExperimentalWarning`，且 API 保留变更权）。这带来一个零依赖的持久层，
与本机没有 docker 的事实相符。

⚠ **Node 24 的版本下限取 24.16.0**：`node:sqlite` 的 TEXT 解码器在遇到内嵌 NUL 时
会**静默截断**，该 bug 在 24.16.0 与 26.1.0 才修。消息体是任意字节，这条不能忽略。
`packages/core` 与 `packages/cli` 不受此限，仍可保持 ≥ 22.12（与旧仓库一致）。

HTTP 层用 `node:http` 自己写路由：整个服务只有**两个**端点
（JSON-RPC 控制面 + 附件数据面），引框架的收益是负的。

**存储接口化**：`Storage` 是一个 interface，`sqlite` 是 v1 唯一实现。
Postgres 的事等真需要多实例时再说，现在不做抽象层之上的抽象。

## 3. 信封校验（P1）—— 全部 MUST

逐条来自 P1（`01-核心绑定.md`），每条都是拒绝条件：

| 规则 | 违反时的错误 |
|---|---|
| `jsonrpc` 精确等于 `"2.0"` | `anp.invalid_jsonrpc_version` |
| `params` **必须**是对象（数组不行） | `anp.invalid_params_shape` |
| `id` **必须**是非空字符串；数字 / `null` 都不行 | `anp.invalid_request_id` |
| **禁 batch** | `anp.batch_not_supported`（注意这是 `anp_code`，不是 JSON-RPC `-32600`） |
| 有 `id` = Request，无 `id` = Notification；除 Notification 外**必须**回 Response | — |
| 顶层固定为 `params = {meta, auth, body}` | — |
| 未知**核心** `meta` 字段 **MUST** 拒绝；仅 `x_` 前缀 MAY 忽略 | `anp.unknown_meta_field` |
| 计数器 / 序号 / epoch 等 **MUST** 是十进制**字符串** | — |

错误响应的统一形状（P1，所有自定义错误都走它）：

```json
{"jsonrpc":"2.0","id":"req-1",
 "error":{"code":1001,"message":"Unsupported profile",
          "data":{"anp_code":"anp.unsupported_profile","retryable":false,"details":{}}}}
```

`error.data.anp_code` **必须**存在——这是客户端分支的唯一依据，别省。

**未知 `meta` 字段必须拒绝**这条容易被忽略，而它是防降级的关键：
一个不认识 `security_profile` 的实现如果默默忽略它，就会在有 E2EE 要求的会话里
按明文回一条成功。宁可拒。

## 4. 方法面

`.v1` / `.v2` 是 wire 上的 Profile 标识，**不得出现小版本**。

### P1 核心绑定 — `anp.core.binding.v1`

| 方法 | 说明 |
|---|---|
| `anp.get_capabilities` | 返回本服务支持的 `profiles[]` / `securityProfiles[]`。**发现的最后一环** |

### P3 私聊 — `anp.direct.base.v1`

| 方法 | 方向 |
|---|---|
| `direct.send` | 请求 |
| `direct.incoming` | **Notification**（服务端 → 收件人端点） |

### P4 群组 — `anp.group.base.v2`

| 方法 | 触发 |
|---|---|
| `group.create` | `target.kind=service` |
| `group.get_info` | `target.kind=group`，**可匿名** |
| `group.join` / `group.add` / `group.remove` / `group.leave` | 成员变更 |
| `group.update_profile` / `group.update_policy` | RFC 7386 merge patch |
| `group.send` | `target.kind=group` |

通知：`group.incoming`（已接受的群消息）、`group.state_changed`
（`member-activated` / `member-removed` / `member-left` / `member-did-updated` /
`group-profile-updated` / `group-policy-updated`）。
`group.member_did_update` **不是** JSON-RPC 方法，被调用时返 `-32601`。

### P5 私聊 E2EE — `anp.direct.e2ee.v2`

| 方法 | 说明 |
|---|---|
| `direct.e2ee.publish_prekey_bundle` | 按 `(owner_did, owner_device_id)` 发布 |
| `direct.e2ee.get_prekey_bundle` | 取对方的 |
| `direct.send`（重载） | `content_type` 变为 `application/anp-direct-init+json` → `application/anp-direct-cipher+json` |

### P6 群组 E2EE — `anp.group.e2ee.v2`

`publish_key_package` / `get_key_package` / `create` / `add` / `remove` / `send`，
通知 `group.e2ee.notice`，并重载 `group.incoming`。
KeyPackage 的 reserved / consumed 状态由本服务管。

### P7 附件 — `anp.attachment.v1`

全部 **service-scoped**，走 `target.did = serviceDid`。

### P9 Mention

**不新增方法。** 它是 payload 语义扩展：`mentions` 顶层数组。
服务端 **MUST NOT** 做 mention 专属授权或展开 selector，只执行外层 Profile 的校验。

### 4.1 错误码段

| 段 | 归属 |
|---|---|
| 1000–1021 | P1 公共错误 |
| 2000–2007 | P3 私聊（`direct.*`） |
| 3000–3010 | P4 群组（**无 3004**） |
| 4000–4012 | P5 E2EE |
| 5000–5013 | P6 群组 E2EE |
| 6000–6013 | P7 附件 |

⚠ **P5 §1532 的正文写"5000-5012 码段"，与同文件错误表里的 4000–4012 矛盾。
按表实现（4000–4012），并在代码里引这一句说明为什么。**

## 5. 认证

### 5.1 `origin_proof`（P1 附录 A）

- 机制：**RFC 9421 HTTP Message Signatures**，`scheme` 固定 `anp-rfc9421-origin-proof-v1`
- 组件集合固定 `("@method" "@target-uri" "content-digest")`，标签均为 `sig1`
- `contentDigest` 用 **sha-256**
- 签的是 **Signed Request Object** = `{method, meta, body}`——
  **不含** `jsonrpc` / `id` / `auth`，经 **RFC 8785 JCS** 规范化
- `@target-uri` = `anp://{kind}/{pct-encoded did}`

验签之后**还要**校验归属：

- `keyid` 所属 DID **必须**等于 `meta.sender_did`
- 该 `keyid` **必须**被 DID 文档的 `authentication` 授权

**同域也要验 `origin_proof`。** 规范里"本地 bearer token"只是**非规范性优化**，
且**MUST NOT** 替代 `origin_proof`（P3 §9.5）。本服务可以选择**也**支持一条 bearer 快捷路径，
但默认关闭，且它绝不能成为唯一路径。

### 5.2 跨域（P8 §6）—— 最易错的一处

跨域调用时：

1. **原始 `origin_proof` 原样转发，不得重写**（P8 §6.4）。中间服务重签会毁掉端到端证据。
2. 外层 HTTP 认证用**发送方域的 `serviceDid`**（裸域名 DID 优先），
   **MUST NOT** 用业务 `sender_did`。
3. 接收方按方法确定 **caller anchor**，再校验 `keyid` 所属 DID == `serviceDid`：
   - **普通请求** → `meta.sender_did`
   - **群通知**（`group.incoming` / `group.state_changed` / `group.e2ee.notice`）→ **`body.group_did`**

第 3 条这两行必须挨着写在**同一个函数**里。分成两处判断，就是这类实现最经典的漏洞
（用 `sender_did` 去校验一条群通知，攻击者只要在自己域里建个 DID 就能冒充）。

### 5.3 CAIP-10 调用者

若 `sender_did` 是 CAIP-10 账户 id（`eip155:1:0x…`）：

- `keyid` **不是 DID URL**——这是提案唯一一处偏离 ANP-02（§12），**不要当 bug 修**
- **不做网络解析**。文档内联在请求里（§4.3）
- **先做地址派生校验**（`derive(pk) == account_address`），**再用**那把钥验签（§5.1）
- **限 EOA**；合约账户拒绝（§5.3），这是安全边界
- 非规范的 `eip155` 拼法（大写地址 / 十进制以外的 chain id）拒为 `invalid_did`（§4.2）

## 6. 幂等

**最小键**：`(sender_did, target.did, method, operation_id)`。

规则：

- 等价的重复请求返回**同一结果**，不重复投递
- 同键但负载不同 → `anp.idempotency_conflict`
- 查找顺序：**先操作级，再消息级**
- E2EE 的幂等键**必须**含设备 selector

**DID 已被取代时**（`anp.did_superseded`）：返回错误**之前**，
必须先按旧 DID 查**精确**幂等记录，命中就回原结果（P1 / P3 §5.5）。
否则一个重试会被当成新消息，而它其实早就被处理过了。

**先落库、后响应**：幂等记录与消息在**同一个事务**里写。规范没要求，
但不这么做就没有任何东西能保证"重试得到同一结果"。

## 7. 存储

`node:sqlite`，WAL 模式。表（草案）：

```sql
-- 幂等台账：先查这张表，再谈其他
CREATE TABLE idempotency (
  sender_did TEXT NOT NULL, target_kind TEXT NOT NULL, target_did TEXT NOT NULL,
  method TEXT NOT NULL, operation_id TEXT NOT NULL,
  response_json TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (sender_did, target_kind, target_did, method, operation_id)
);

-- 私聊消息（明文 P3 与密文 P5 同一张表，靠 security_profile 区分）
CREATE TABLE messages (
  message_id TEXT PRIMARY KEY, sender_did TEXT NOT NULL, target_did TEXT NOT NULL,
  profile TEXT NOT NULL, security_profile TEXT NOT NULL,
  content_type TEXT NOT NULL, body_json TEXT NOT NULL,
  sender_device_id TEXT, recipient_device_id TEXT,
  conversation_id TEXT, accepted_at TEXT NOT NULL
);
CREATE INDEX messages_target ON messages (target_did, accepted_at);

-- 取件扩展面用的游标（每 (owner_did[, device]) 一条单调递增序号）
CREATE TABLE delivery_cursor (
  owner_did TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '',
  last_seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner_did, device_id)
);

-- 群：Host 维护线性顺序，两个单调量都在这
CREATE TABLE groups (
  group_did TEXT PRIMARY KEY, host_service_did TEXT NOT NULL,
  group_state_version INTEGER NOT NULL, group_event_seq INTEGER NOT NULL,
  group_profile_json TEXT NOT NULL, group_policy_json TEXT NOT NULL,
  created_at TEXT NOT NULL, creator_did TEXT NOT NULL
);
CREATE TABLE group_members (
  group_did TEXT NOT NULL, member_did TEXT NOT NULL, role TEXT,
  membership_status TEXT NOT NULL, state_version INTEGER NOT NULL,
  PRIMARY KEY (group_did, member_did)
);
CREATE TABLE group_events (          -- group.state_changed 的可重放来源
  group_did TEXT NOT NULL, event_seq INTEGER NOT NULL,
  event_type TEXT NOT NULL, payload_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
  PRIMARY KEY (group_did, event_seq)
);

-- P5/P6 E2EE：本服务看不见明文，只存不透明字节
CREATE TABLE prekey_bundles (
  owner_did TEXT NOT NULL, owner_device_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL, bundle_json TEXT NOT NULL, published_at TEXT NOT NULL,
  PRIMARY KEY (owner_did, owner_device_id)
);
CREATE TABLE group_key_packages (
  owner_did TEXT NOT NULL, owner_device_id TEXT NOT NULL,
  key_package_id TEXT NOT NULL, package_json TEXT NOT NULL,
  state TEXT NOT NULL,   -- reserved | consumed | available
  published_at TEXT NOT NULL,
  PRIMARY KEY (owner_did, owner_device_id, key_package_id)
);

-- P7：对象字节 + 摘要，不含 object_key / nonce（那些只随 P5/P6 内层 manifest 走）
CREATE TABLE attachment_slots (
  attachment_id TEXT NOT NULL, slot_id TEXT NOT NULL, owner_did TEXT NOT NULL,
  object_encryption_mode TEXT NOT NULL, message_security_profile TEXT NOT NULL,
  commit_token TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL,
  object_uri TEXT, size INTEGER, digest TEXT, committed_at TEXT,
  PRIMARY KEY (attachment_id, slot_id)
);

-- 出站：direct.incoming / group.* 推送的重试队列
CREATE TABLE outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_uri TEXT NOT NULL,
  payload_json TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL, last_error TEXT
);
```

**刻意不建的**：任何记录"内部队列数 / 副本数 / 设备数 / 工作流节点"的线协议字段。
P3 §5.4 规定这些 **MUST NOT** 成为线协议语义——它们可以存在于内部表里，
但绝不能出现在**响应**里。

## 8. 投递与推送

### 8.1 落库 → 应答 → 推送

`direct.send` 的处理顺序：

1. 校验 → 验签 → 幂等查表
2. **一个事务**内写 `messages` + `idempotency` +（群消息时）`group_events`
3. 回 `accepted=true` 的响应
4. **异步**投递 `direct.incoming` 到收件人端点

第 4 步失败**不改变**第 3 步已经发出的成功语义——这正是 §1 那条"成功语义被切小"的用法。
失败的推送进 `outbox`，按退避重试。

### 8.2 `direct.incoming` 的 payload 约束

必带与原消息一致的：`meta.profile`、`security_profile`（= **原接受模式**）、
`target.kind="agent"`、`target.did`（= 接收方）、`sender_did`（= **原逻辑发送主体**）、
`operation_id`、`message_id`、`content_type`、`body`。

`params.auth` 若带 `origin_proof`，**必须是原始无损副本**，本服务**不得重签**。

**不得出现设备 selector。**

### 8.3 订阅路（WebSocket）

上面 8.1 描述的是**服务端主动 POST 到 agent 端点**那条路，适合常驻服务型 agent。
CLI 与所有在 NAT 后面的客户端走**订阅路**：客户端主动连上 `GET /anp-im/stream`，
在同一连接上补齐（`sync.delta`）并接收实时通知。

**传输不同，信封同一个**——控制面的校验 / 认证 / 幂等 / dispatcher 全部复用。
订阅者注册表、游标语义、无空洞无重复的时序、背压，全部在
[realtime.md](realtime.md)。

两条路并存是刻意的：规范只规定了 `direct.incoming` 这个 Notification 的存在与 payload，
**没规定它走什么传输**，所以这是实现自由。

## 9. 取件扩展面（规范未定义，本服务自定）

规范在取件侧是空白的，且是刻意的：P3 §1 排除历史拉取 / 已读状态 / 内部同步，
P5 §10.7 与 P6 同样排除，P8 也排除。**规范里不存在 `inbox.get`**（已全文 grep 核实）。

`AgentXAgent` 必须补上这一半，否则消息只能发不能取。
**设计选择：沿用 `awiki-open-server` 已有的方法名**（`messaging/core.py:2188` 的 `MESSAGE_HANDLERS`），
这样同一个 `connectx` 对两个服务都能用：

```
direct.get_history
inbox.get                 # 按游标拉
inbox.mark_read
read_state.mark_read
sync.bootstrap / sync.delta / sync.thread_after
message.get_batch
```

⚠ **这些方法不属任何 Profile，不得出现在 `anp.get_capabilities` 的 `profiles[]` 里。**
它们要另开一个扩展标识（如 `x_agentx.inbox.v1`），否则就是在对客户端撒谎——
一个只实现规范的服务会被误认为支持它们。

P5 的 **Mailbox** 不是这条路。Mailbox 是范围为 `(recipient_did, recipient_device_id)` 的
**不透明密文队列**，不持有 Ratchet 状态，**不是群/私聊历史**。
E2EE 会话里的取件走 Mailbox，明文历史走 `inbox.get`。两者别混。

## 10. 联邦（P8）

**没有中继协议。** P8 §3.1 明确：发送方域**直接复用原业务方法**，不新增 Relay 方法。
发送方域按 `target.kind` 路由到目标域，把**原始** `direct.send` POST 到对方入口服务。

本服务作为**接收侧**要做的：

1. 用发送方 `serviceDid` 验外层 HTTP 认证
2. 按 §5.2 调 caller anchor
3. 直接进入正常处理流程——跨域与同域在业务语义上**没有区别**

本服务作为**发送侧**（`group.incoming` 要推给别的域的成员）要做的：
用**自己的** `serviceDid` 签外层请求，业务层的 `origin_proof` 原样带上。

失败与重试：复用原业务幂等语义；重试**保持** `operation_id` / `message_id`，
负载语义等价，设备 selector 不变。内部 trace / attempt 字段**不得**替代幂等键。

**DID 停用**：应用处理前可返 HTTP 409；进入应用处理后返 `anp.did_superseded`。
同一请求 **MUST NOT** 两层都返。

## 11. E2EE 对本服务的硬约束

- **MUST NOT 解密或重加密**（P5 §1392、P6 §1496）。
- Device Delivery Queue 只持久化**公开元数据 + 不可读密文**（P6 §1508）。
- 群成员变更时，**历史密钥材料不得回溯分发**——`group.e2ee.add` 只给
  `commit_b64u` / `welcome_b64u` / `ratchet_tree_b64u`，本服务原样转发。
- P6 的历史 / 重放 API **不得**声明为 P6 能力（§1525）。

这条约束有一个直接后果：**`inbox.get` 在 E2EE 会话里返回的是密文**。
CLI 的 `msg show` 在 E2EE 会话上只能打印 envelope，解密是客户端的事。
设计上不要试图在服务端"顺手解一下"。

## 12. 附件数据面（P7）

流程（服务端视角）：

```
attachment.create_slot      → 发 slot_id + upload_uri + object_uri + commit_token
PUT  upload_uri             → 独立 HTTPS 端点，收对象字节（数据面，不走 JSON-RPC）
attachment.commit_object    → 校验 size + digest，落 object_uri
attachment.get_download_ticket → 校验 7 条（含 Access Grant 存在），发短时票据
GET  object_uri             → Authorization: Bearer {download_ticket}
```

约束：

- `object_uri` **MUST** 是 `https://` URL，是 **locator 不是永久直链**
- 票据 **MUST NOT** 放 URL 参数；默认 ≤ 5 分钟，可一次性
- 调用方 **MUST NOT** 只凭 `object_uri` 的域名猜控制面服务——必须按原始消息的发送者 DID 解析。
  （这条约束在客户端；服务端要保证 `object_uri` 的域名**确实是自己**。）
- 服务端存**不透明字节 + 摘要**，**不含** `object_key` / `nonce`——
  对象密钥只随 P5/P6 的内层 manifest 下发。

## 13. 服务自我描述

agent 的 DID 文档里那条 `ANPMessageService` 服务条目是**发现链的落点**：

```json
{
  "id": "…#anp-message-service",
  "type": "ANPMessageService",
  "serviceEndpoint": "https://agentx.example/anp-im/rpc",
  "serviceDid": "did:web:agentx.example",
  "profiles": ["anp.core.binding.v1", "anp.direct.base.v1", ...],
  "securityProfiles": ["transport-protected", "direct-e2ee"]
}
```

- `id` / `type` / `serviceEndpoint` 三个必填
- `serviceDid` 是**跨域服务身份**，参与跨域调用时 **MUST** 存在（P2 §8.7）；
  它是**裸域名 DID**，不是 DID URL
- **每个 DID 文档只能暴露一个可跨域的 `ANPMessageService`**（P2 §7.1）

服务端提供 `GET /.well-known/anp-message-service.json` 返回**上面这个条目**，
供 DID Service 在签发文档时嵌入。**这就是与 `awiki-open-server` 的接口**——
本服务不写 DID 文档，只交出这段 JSON。

**扩展能力不在那个条目里声明。** `profiles[]` / `securityProfiles[]` 只放规范定义的
Profile 与安全模式——把 `inbox.*` / `sync.*` / 订阅流塞进去，就是在对客户端撒谎
（一个只实现规范的服务会被误认为支持它们）。扩展能力另走一处，
由 `GET /.well-known/anp-message-service.json` 的一个 `x_agentx` 块自报，
并在订阅握手的 `stream.hello` 里再报一次（见 [realtime.md](realtime.md) §9）。

## 14. 配置

```
AGENTX_LISTEN           监听地址，默认 127.0.0.1:8787
AGENTX_PUBLIC_URL       对外可见的基址（用于 serviceEndpoint / object_uri）
AGENTX_SERVICE_DID      自己的服务 DID，默认由 PUBLIC_URL 推出 did:web
AGENTX_KEY_FILE         服务签名钥（跨域时签外层请求）
AGENTX_DB               SQLite 路径，默认 ./agentx.db
AGENTX_OBJECT_DIR       附件对象目录
AGENTX_MAX_BODY         请求体上限，默认 1 MiB（附件走数据面，不经这里）
```

**没有配置项能关掉 `origin_proof` 校验。** 要联调就配一个宽松的 DID 解析策略，
不要开后门——那扇门会在某次部署里被忘掉。

## 15. 实现顺序

**v1（先跑通规范面）**

1. `packages/core/message/`：信封 + JCS + 签验 + locator（CLI 与服务端共用，**先做**）
2. HTTP 层 + Envelope 校验 + `anp.get_capabilities` + `direct.send` + `direct.incoming`
3. 幂等 + 存储（`idempotency` / `messages` / `outbox`）
4. 取件扩展面（`inbox.get` / `inbox.mark_read` / 增量游标）
5. **订阅路**：`GET /anp-im/stream` + 订阅者注册表 + 补齐与实时的无空洞时序
6. `/.well-known/anp-message-service.json`

**v2**

7. P4 群组 + Group Host 语义（线性顺序、`group_state_version` / `group_event_seq`）
8. P7 附件数据面
9. P8 跨域（`serviceDid` 外层认证 + caller anchor + outbox 重试）

**v3**

10. P5 E2EE（prekey bundle + Mailbox）
11. P6 群组 E2EE（KeyPackage 状态机 + Device Delivery Queue）

**发布前置条件**（不是本仓库的活，但会挡住 P6）：P6 仍是候选状态，
MLS `ExtensionType 0xF0A1` 待 IANA 注册（`README.md:10,34`；`06:98`）。
在它落地之前，P6 的能力**不得**在 `anp.get_capabilities` 里声明为稳定 Profile。
