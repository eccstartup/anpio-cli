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

**`AgentXAgent` 不托管别人的 DID 文档，但需要解析它们**——发件人身份、入口服务发现、群成员
校验都要。**一处例外**：它**自己名下**的群 DID 文档由它自己发布（§13、[groups.md](groups.md)
§2.2）：群 DID 就住在它的命名空间里（`<serviceDid>:g:<id>`），而按 P8 §5.2 L215–221，别的域
必须先解析到这份文档才能把群调用送进来。

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
                    │  方法表（MethodSpec）                 │
                    │   profile / 必填字段 / target.kind    │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Auth（P1 附录 A + P8 §6）           │
                    │   origin_proof 验签 + caller anchor  │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  正文形状（按 method）                │
                    └──────────────┬──────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Idempotency + Dispatcher            │
                    │   (sender_did, target, method, op)   │
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

**这个图只画了受理那一条路**。另一条是出站：`outbox` 里的行由 `delivery/worker.ts`
的轮询取走，重新解析收件人的 `ANPMessageService` 并把 `direct.incoming` POST 过去。
它与受理路径**不共享任何顺序**，只共享同一个 `Storage`，理由见 §8.4（事务里不能有
网络往返）。

**运行环境**：TypeScript，**服务端要求 Node ≥ 24**。存储用 **`node:sqlite`**——
它自 Node 22.5 起存在，但直到 **Node 24 才转正**（22.5–23 上每次启动都打
`ExperimentalWarning`，且 API 保留变更权）。这带来一个零依赖的持久层，
与本机没有 docker 的事实相符。

⚠ **Node 24 的版本下限取 24.16.0**：`node:sqlite` 的 TEXT 解码器在遇到内嵌 NUL 时
会**静默截断**，该 bug 在 24.16.0 与 26.1.0 才修。消息体是任意字节，这条不能忽略。
`packages/core` 与 `packages/cli` 不受此限，仍可保持 ≥ 22.12（与旧仓库一致）。

HTTP 层用 `node:http` 自己写路由：服务一共只有**四条**路由（控制面、取件流、两段附件
数据面），引框架的收益是负的。

### 2.1 路由与 HTTP 状态码

| 请求 | 应答 |
|---|---|
| `POST /anp-im/rpc` | `200`，体是 JSON-RPC 响应（**成功与失败都是 200**） |
| `GET /anp-im/stream` | `101` 升级为 WebSocket |
| `GET /anp-im/stream`，**不是**升级请求 | `426` + `Upgrade: websocket` |
| `GET /.well-known/anp-message-service.json` | `200`，体是 §13 那个条目 |
| `PUT /anp-im/upload/{token}` | 数据面，附件对象字节（P7，[attachments.md](attachments.md) §3） |
| `GET /anp-im/objects/{object_id}` | 数据面，凭票据取对象字节（P7，同上） |
| 其余路径 | `404` |
| 已知路径、方法不对 | `405` + `Allow` |

数据面那两行**不**走 §2.1 的"一律 200"：它们没有 JSON-RPC 信封、客户端是普通 HTTP
客户端，用真的是非 2xx 状态码；理由与那张码表在 [attachments.md](attachments.md) §3.1。

`426` 那一行是给"方法对了、但没带升级头"的请求的：`405` 会去怪方法，而方法正是它唯一
做对的地方（`http/server.ts` 的 `route()` 里写着同一句）。它由升级监听器拒绝后落到普通
路由上回答，响应里 `Upgrade: websocket` 是 426 要求的头。

**协议错误不换 HTTP 状态码**：`anp.*` 与 JSON-RPC 标准错误一律走 `200`，客户端按
`error.data.anp_code` 分支。**规范没有规定 HTTP 状态码**（P1 全文未提，已 grep 核实），
这条是**本仓库自己的选择**，理由是客户端那边：`core` 的 `postMessage` 走
`fetchControlledJson`，它对非 2xx 直接抛 `message_send_failed`（`resolveDid.ts:860`）。
把 `anp.did_superseded` 放进 4xx，调用方就再也拿不到那个 `anp_code`——
而它正是 P1 §10.2 L695 用来分支的唯一依据。

只有"连 JSON-RPC 对象都还不是"的传输层失败才用非 2xx：
`413`（体超过 `AGENTX_MAX_BODY`）、`415`（`Content-Type` 不是 JSON）、
`426`（流路径上的非升级 GET）以及上表的 `404` / `405`。**流一旦升级，状态码这套就不
适用了**：连接上的每一次失败都是 `200` 里的一份 JSON-RPC 响应，只有握手认证失败才关连接
（[realtime.md](realtime.md) §4.1）。

**数据面是这条规则的一个例外，而且是有意的**：它没有 JSON-RPC 信封、没有 `id` 可答，
客户端是普通 HTTP 客户端，读的就是状态码——所以那两条路由用真的 4xx/5xx，同时把
`anp_code` 放进 JSON 体里。理由与逐条对照见 [attachments.md](attachments.md) §3.1。

**存储接口化**：`Storage` 是一个 interface，`sqlite` 是 v1 唯一实现。
Postgres 的事等真需要多实例时再说，现在不做抽象层之上的抽象。

**上图的层序就是实现里的顺序**（`rpc/dispatch.ts` 的 `createDispatch()`），而且顺序本身
是设计：方法表在认证**之前**（能判的自己判掉，省一次出站 DID 解析），正文校验在认证
**之后**（正文要读调用方自带、又尚未验签的 `content_type`）。理由写在 §8.1。

## 3. 信封校验（P1）—— 全部 MUST

逐条来自 P1（`01-核心绑定.md`），每条都是拒绝条件：

| 规则 | 违反时的错误 |
|---|---|
| `jsonrpc` 精确等于 `"2.0"`（§4.1 L127） | `-32600`（§10.1 L672「非法 JSON-RPC 对象」） |
| `params` **必须**是对象，数组不行（§5.1 L151） | `anp.invalid_params_shape`（1003，§10.3 L704） |
| `id` **必须**是非空字符串；数字 / `null` 都不行（§5.2 L157–159） | `anp.invalid_request_id`（1000，§10.3 L701） |
| **禁 batch**（§5.4 L177–179） | `anp.batch_not_supported`（1004，§10.3 L705）。注意这是 `anp_code`，不是 `-32600` |
| 有 `id` = Request，无 `id` = Notification；除 Notification 外**必须**回 Response（§5.6 L201） | — |
| 顶层固定为 `params = {meta, auth, body}`；除这三个之外的顶层成员只有 Profile 明确定义时才允许（§6.1 L224–230） | — |
| 未知**核心** `meta` 字段 **MUST** 拒绝；仅 `x_` 前缀 MAY 忽略（§12.1 L776–777） | `-32600` |
| 未知 `auth` 字段 **MUST** 拒绝；未知 `body` 字段只有 Profile 声明可忽略时才 MAY 忽略（§12.1 L778–780） | `-32600` |
| `meta.target.kind` 与方法声明的目标建模模式不一致（§6.2.5.1 L382） | `anp.invalid_target_binding`（1014，§10.3 L715） |
| 计数器 / 序号 / epoch 等 **MUST** 是十进制**字符串**（§7.3 L491–499） | — |

⚠ **规范里没有 `anp.invalid_jsonrpc_version`，也没有 `anp.unknown_meta_field`**（已全文 grep 核实，
2026-10-01）。§4.1 与 §12.1 只写 MUST，不指定码；§10.1 L667–677 把这些形状指向 JSON-RPC 标准码。
§10.2 L695 规定只有 `code` 落在 ANP 自定义段（1000+）时才强制 `error.data.anp_code`，
所以 `-32600` 那条**不带** `anp_code` 是合规的——客户端在标准码上用 `message` 分支。

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

背后的 Group Host 语义（两个单调量各由什么推进、`group_did` 的形状、成员状态机、权限判定、
群消息如何落进收件箱、回执为什么在 v1 里没有签名）单开一份 [groups.md](groups.md)。

### P5 私聊 E2EE — `anp.direct.e2ee.v2`

| 方法 | 说明 |
|---|---|
| `direct.e2ee.publish_prekey_bundle` | 按 `(owner_did, owner_device_id)` 发布 |
| `direct.e2ee.get_prekey_bundle` | 取对方的 |
| `direct.send`（重载） | `content_type` 变为 `application/anp-direct-init+json` → `application/anp-direct-cipher+json` |

两条 Key 方法都是 **service-scoped**（§7.1 L465、§7.2 L520），且**幂等键不同**：`get`
比 `publish` 多出 `target_did` / `target_device_id`（§7.2 L579），并要求"幂等记录写入 +
OPK 分配"**原子**完成（§7.2 L581），同一键重试 **MUST** 拿回同一 OPK（§7.2 L580）。
本层不碰任何密码学——见 [e2ee-direct.md](e2ee-direct.md)。

### P6 群组 E2EE — `anp.group.e2ee.v2`

`publish_key_package` / `get_key_package` / `create` / `add` / `remove` / `send`，
通知 `group.e2ee.notice`，并重载 `group.incoming`。
KeyPackage 的 reserved / consumed 状态由本服务管。

目标建模**三档**（§4.4）：前三条与 `create` 是 service-scoped，`add`/`remove`/`send` 是
group-addressed，两条通知是 agent-addressed（**不定义** `target.kind = "device"`，§4.4.3 L320）。
本服务在这条链上**只当见证者**：排序、持有一份 `(DID, device)`→leaf 的**公开投影**、
以及两台柜子；MLS 的 create/add/remove 全在 owner 客户端，见 [e2ee-group.md](e2ee-group.md)。

### P7 附件 — `anp.attachment.v1`

全部 **service-scoped**，走 `target.did = serviceDid`：
`create_slot` / `commit_object` / `abort_object` / `get_download_ticket`。

四个方法都**不验 `origin_proof`**（§10.1 L799–800：跨域那一跳由外层服务身份保证），
是本服务里唯一一组这样的非匿名方法；同域那一侧的取舍、授权链（Grant 在承载消息被接受
时才出现）、数据面两条路由与票据形状，单开一份 [attachments.md](attachments.md)。

### P9 Mention

**不新增方法。** 它是 payload 语义扩展：`mentions` 顶层数组。
服务端 **MUST NOT** 做 mention 专属授权或展开 selector，只执行外层 Profile 的校验。

### P8 联邦

**同样不新增方法**（§3.1 L61–68：**SHOULD** 直接复用原业务方法，不新增 Relay 包装方法）。
它约束的是上面那些方法**跨域时**怎么走：外层 `serviceDid` 身份、caller anchor、
以及发送侧到底转发什么。见 [federation.md](federation.md)。

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

码在代码里有两条路：P1 那一段（1000–1021）走 core 的 `anpRejection`，它按表把 `code`
填好；Profile 自己的段走 `profileRejection(code, anpCode, …)`，因为 P1 那张表里**没有**
这些码——`ANP_ERRORS` 只覆盖公共段，`AnpRejection.anpCode` 因此是开放的字符串
（`AnpErrorName`），不是封闭联合。默认的 1005 / 2005 见 §5.1。

## 5. 认证

### 5.1 `origin_proof`（P1 附录 A）

- 机制：**RFC 9421 HTTP Message Signatures**，`scheme` 固定 `anp-rfc9421-origin-proof-v1`
- 组件集合固定 `("@method" "@target-uri" "content-digest")`，标签均为 `sig1`
- `contentDigest` 用 **sha-256**
- 签的是 **Signed Request Object** = `{method, meta, body}`——
  **不含** `jsonrpc` / `id` / `auth`，经 **RFC 8785 JCS** 规范化
- `@target-uri` = `anp://{kind}/{pct-encoded did}`

验签之后**还要**校验归属：

- `keyid` 所属 DID **必须**等于这次调用的**锚点**（P3 §9.2 L515 的 `meta.sender_did` 是
  普通请求那一栏；群通知那一栏见下）
- 该 `keyid` **必须**被 DID 文档的 `authentication` 授权（P2 §5.2 L208；
  `resolveDid.ts:1120` 查的就是这一条）

**锚点由同一个函数按方法算出**（`rpc/auth.ts` 的 `callerAnchor`）：普通方法取
`meta.sender_did`，群通知取 `body.group_did`。取 `body` 那一栏的理由是**不一致时**仍然
拿群身份去校验——`meta.sender_did == body.group_did` 是 P4 §8.11 L922 要求处理器另查的
一条 MUST，不是认证层可以假定的前提。缺了群身份就该报"没有锚点"，**绝不能回落到**
`meta.sender_did`：攻击者在自己的域里建个 DID 就能冒充任何群。

**失败报哪个码由方法表给出**，不由认证层写死。同一件事在各 Profile 里的码不一样：
P1 §10.3 L706 只有 `anp.unauthorized`（1005），P3 §11 L599–600 把它拆成
`direct.invalid_origin_proof`（2005）与 `direct.origin_did_mismatch`（2006）。
所以 `authenticate()` 收一对码（`AuthErrorCodes`），默认是 P1 那对。

**时间窗在认证这一步一起判**，但只认 proof 自己带来的 `expires`、以及明显跑在前面的
`created`（默认 60 秒时钟偏斜）。**不加**年龄上限：P1 附录 A 只规定摘要与签名怎么算，
§13.2 L816 更是明确"`created_at` 不得作为唯一防重放机制，防重放由后续 Profile 在会话态、
消息态或群态中定义"——那在本服务里就是 C4 的幂等记录。年龄上限是替 Profile 立规矩。

**失败分类不进线上错误对象。** `digest_mismatch` / `key_unresolved` / `signature_invalid`
逐条答出去，就成了"这个 keyid 被授权了吗"的 oracle（core 的 `verify.ts` 写了这条）。
分类回给服务自己记日志，对端只看到一句"证明没通过"。

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

这个函数就是 §5.1 的 `callerAnchor`——同一份判断服务两处检查：业务层的 proof 归属
（§5.1）与这里跨域外层服务的 `serviceDid` 归属。两处各写一遍，就回来了。

外层那一路要做到什么程度（§6.2.2 的八步、重放缓存、以及"什么算跨域"的判断），
见 [federation.md](federation.md) §2。

### 5.3 CAIP-10 调用者

若 `sender_did` 是 CAIP-10 账户 id（`eip155:1:0x…`）：

- `keyid` **不是 DID URL**——这是提案唯一一处偏离 ANP-02（§12），**不要当 bug 修**
- **不做网络解析**。文档内联在请求里（§4.3）
- **先做地址派生校验**（`derive(pk) == account_address`），**再用**那把钥验签（§5.1）
- **限 EOA**；合约账户拒绝（§5.3），这是安全边界
- 非规范的 `eip155` 拼法（大写地址 / 十进制以外的 chain id）拒为 `invalid_did`（§4.2）

## 6. 幂等

**最小键**：`(sender_did, target_scope, method, operation_id)`（P1 §9.1 L628）。

`target_scope` 由 Profile 定义（Direct 类通常是 `target.did`，Group 类是 `group_did`，
§9.1 L635–637），设备定址的 E2EE Overlay 还要把每个设备 selector 并进去（§9.1 L639）。
所以它不是一组固定列——**键由 `core` 的 `idempotencyKey()` 生成**，服务端只存这个字符串。
两侧各算一遍就会出现"重试看起来像新消息"。

规则：

- 等价的重复请求返回**同一结果**，不重复投递
- 同键但负载不同 → `anp.idempotency_conflict`
- 查找顺序：**先操作级，再消息级**
- E2EE 的幂等键**必须**含设备 selector

**DID 已被取代时**（`anp.did_superseded`）：返回错误**之前**，
必须先按旧 DID 查**精确**幂等记录，命中就回原结果。P1 §9.1 L641 是那条通则
（"以 DID 已被替代为由拒绝之前"），P3 §5.5 L208 是这条拒绝本身（`meta.target.did`
已被替代 → **MUST** 返回 `anp.did_superseded`，不得静默改写目标）。
否则一个重试会被当成新消息，而它其实早就被处理过了。
L641 同行还划了另一半：**后继 DID 签的请求不是旧 DID 请求的精确重放**，跨 DID 去重要由
Profile 另行定义，本服务不做。

这条规则的落地方式是**结构性**的，不靠调用方记性：`acceptOperation()` 只在**查表未命中**
时才调用它的 `perform()`。想"拒掉"就写在 `perform` 里抛出来，于是拒绝必然发生在查表
之后；任何在调用 `acceptOperation()` **之前**就返回错误的写法都会让这条失效。测试里
"旧 DID 的精确重放不会被取代检查拦掉"钉的就是这一点（`perform` 断言没被调用）。

**先落库、后响应**：幂等记录与消息在**同一个事务**里写。规范没要求，
但不这么做就没有任何东西能保证"重试得到同一结果"——一半落库的中间态会让这句话落空。
事务边界落在 `Storage.transaction()`，`acceptOperation()` 是它唯一的组装者。

**存的是操作的结果，不是 JSON-RPC 信封**：重试是**另一次请求**、带自己的 `id`，
回放一个存下来的信封会把首个请求的 `id` 答给重试。§9.1 L630 说"返回同一结果或等价
结果"，说的是结果；信封由调用方拿这次请求的 `id` 重新包。

## 7. 存储

`node:sqlite`，WAL 模式。表（v2，已建；建表语句是 `storage/schema.ts` 里的
`SCHEMA`，改动要一起改两处）：

```sql
-- 幂等台账：先查这张表，再谈其他
-- 键是 core `idempotencyKey()` 的字符串，不是列的分解——§9.1 的 scope 里含
-- Profile 定义的 target_scope 与可变长的设备 selector 列表，拆成固定列就表达不了。
-- `response_json` 存的是**操作的结果**，不是 JSON-RPC 信封：重试带自己的 id。
CREATE TABLE idempotency (
  key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
  response_json TEXT NOT NULL, created_at TEXT NOT NULL
);

-- 私聊消息（明文 P3 与密文 P5 同一张表，靠 security_profile 区分）
--
-- 主键是 §8.2 L444–450 给消息级重复识别定义的三元组，**不是** `message_id` 单列：
-- 那个标识是发送方自己起的（P1 §6.2.7 L402），两个发送方撞上同一个是合法的，P5
-- L1398 更让一条逻辑消息对每台接收设备各带一个外层 `message_id`。只拿它当主键，
-- 第二次插入会被约束拒掉——一个本该正常受理的请求变成 500。
CREATE TABLE messages (
  message_id TEXT NOT NULL, sender_did TEXT NOT NULL, target_did TEXT NOT NULL,
  profile TEXT NOT NULL, security_profile TEXT NOT NULL,
  content_type TEXT NOT NULL, body_json TEXT NOT NULL,
  sender_device_id TEXT, recipient_device_id TEXT,
  conversation_id TEXT, accepted_at TEXT NOT NULL,
  PRIMARY KEY (sender_did, target_did, message_id)
);
CREATE INDEX messages_target ON messages (target_did, accepted_at);

-- 每个收件人一份的投递记录，带它在那个人自己序号里的位置。
-- `delivery_cursor` 的游标是每 (owner, device) 单调递增的，而 `messages` 上没有任何
-- 序号列——一条群消息是一个 `message_id` 投给 N 个成员，序号放不到消息行上。
-- `sync.delta` 重放的是这张表，`inbox.get` 翻的也是它。
CREATE TABLE deliveries (
  owner_did TEXT NOT NULL, seq INTEGER NOT NULL, message_id TEXT NOT NULL,
  method TEXT NOT NULL, params_json TEXT NOT NULL, accepted_at TEXT NOT NULL,
  PRIMARY KEY (owner_did, seq)
);
CREATE INDEX deliveries_message ON deliveries (message_id);

-- 取件扩展面用的游标（每 (owner_did[, device]) 一条单调递增序号）
CREATE TABLE delivery_cursor (
  owner_did TEXT NOT NULL, device_id TEXT NOT NULL DEFAULT '',
  last_seq INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner_did, device_id)
);

-- 群：Host 维护线性顺序，两个单调量都在这（谁推进谁见 groups.md §1）
CREATE TABLE groups (
  group_did TEXT PRIMARY KEY, host_service_did TEXT NOT NULL,
  group_state_version INTEGER NOT NULL, group_event_seq INTEGER NOT NULL,
  group_profile_json TEXT NOT NULL, group_policy_json TEXT NOT NULL,
  created_at TEXT NOT NULL, creator_did TEXT NOT NULL
);
-- joined_at / added_by 是 P4 §7.2 L379–380 的 `group_member` 字段，v3 随 C9 补上
-- last_did_checked_at 是 v10 随 A3c-4 补上的定时刷新游标（见 §14）
CREATE TABLE group_members (
  group_did TEXT NOT NULL, member_did TEXT NOT NULL, role TEXT NOT NULL,
  membership_status TEXT NOT NULL, state_version INTEGER NOT NULL,
  joined_at TEXT, added_by TEXT, last_did_checked_at TEXT,
  PRIMARY KEY (group_did, member_did)
);
CREATE TABLE group_events (          -- group.state_changed 的可重放来源
  group_did TEXT NOT NULL, event_seq INTEGER NOT NULL,
  event_type TEXT NOT NULL, payload_json TEXT NOT NULL, occurred_at TEXT NOT NULL,
  PRIMARY KEY (group_did, event_seq)
);
-- v11 随 B1b-A1 补上：群自己的 Ed25519 私钥，hex 的 32 字节种子。**这张表里每一行都是
-- 密钥**，所以数据库文件与它的备份按密钥对待（groups.md §2.1）。单独一张表而不是
-- `groups` 上的一列，是因为 `group()` 是 `SELECT *`——加一列会让私钥跟着每个 `StoredGroup`
-- 走。没有公钥列：它是可推导的，存两份同一个事实只会有一份先变。
CREATE TABLE group_keys (
  group_did TEXT PRIMARY KEY, private_key TEXT NOT NULL, created_at TEXT NOT NULL
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
-- 这张表随 C10 定稿（加 upload_token 一列），另三张表——attachment_objects /
-- attachment_grants / download_tickets——见 [attachments.md](attachments.md) §8，schema 到 v4
CREATE TABLE attachment_slots (
  attachment_id TEXT NOT NULL, slot_id TEXT NOT NULL, owner_did TEXT NOT NULL,
  object_encryption_mode TEXT NOT NULL, message_security_profile TEXT NOT NULL,
  commit_token TEXT NOT NULL, state TEXT NOT NULL, expires_at TEXT NOT NULL,
  object_uri TEXT, size INTEGER, digest TEXT, committed_at TEXT,
  PRIMARY KEY (attachment_id, slot_id)
);

-- 出站：direct.incoming / group.* 推送的重试队列
--
-- 存收件人的 **DID**，不是解析出来的 endpoint：endpoint 由 locator 从 DID 现推，而
-- 重试必须重新推一遍（域可能已经换了入口服务），把写入那一刻的答案钉在行里，就是往
-- 一个可能早就失效的地址重发。
CREATE TABLE outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, recipient_did TEXT NOT NULL,
  payload_json TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL, last_error TEXT
);
```

**版本**：版本号记在 SQLite 自己的 `user_version` 上（`SCHEMA_VERSION`），**比本构建新
的文件直接拒开**——本构建会读到它认识的表、静默忽略新版本依赖的列。上表是 v3；v2→v3
只是给 `group_members` 加两个可空列（`ALTER TABLE ADD COLUMN` 才是 SQLite 原位能做的
那一种），没有数据搬运。此后每加一列都是同一条路：`addColumnIfMissing` 与版本号一起前进
（v4 的 `joined_at` / `added_by`、v10 的 `last_did_checked_at`），新表则由 `SCHEMA` 的
`IF NOT EXISTS` 补建——但因为 `applySchema` 见到相同版本号就早退，**新表也照样要让版本号
前进**，否则旧文件永远补不上它。从 v1
（`messages` 单列主键 + `outbox.endpoint_uri`）升级的两步都是 SQLite 无法原位改的，
所以走一次迁移：主键变宽是**严格超集**，行照抄不会撞；`outbox` 只有重试状态，直接丢弃
重建。两个 `IF NOT EXISTS` 之外的语句与 `user_version` 落在同一个事务里，成功之后才盖章。

**事务**：`Storage` 上有一个 `transaction()`，**可重入**——已经在事务里再进来就是加入
外层，只有最外层提交。理由是两个粒度的错位：§8.1 要求的原子单位是**一次操作**
（`messages` + `deliveries` + `idempotency`），而每个访问器被单独调用时也要自己成事务
（`appendDelivery` 要读 `MAX(seq)` 再写，不能裸着）。SQLite 不允许嵌套 `BEGIN`
（实测报 `cannot start a transaction within a transaction`），所以深度只能在这一层记。

`BEGIN IMMEDIATE` 在**开始**就拿写锁，这才是并发下"两个发送方不能拿到同一个序号"的依据。
`node:sqlite` 的 `busy_timeout` 默认是 **0**（实测），也就是抢不到锁立刻 `SQLITE_BUSY`
而不等待——串行化只有在失败方肯等的时候才成立，所以打开时设成 5 秒。

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

第 1、2 步已经是现成的接缝：`parseRequestText`（§3）→ `authenticate`（§5）→
`acceptOperation`（§6），第 2 步的写入即 `acceptOperation` 的 `perform()`。
C5 要做的只剩下方法表（`target_scope`、要哪一对错误码、要不要 `origin_proof`）
与第 4 步。

C5 落地的受理路径是 `createDispatch()`，各层的**顺序**本身是设计的一部分：

```
parseRequestText → 是 Notification？→ lookupMethod → checkMethod → authenticate
  → 正文形状 → acceptOperation（幂等查表 + perform 写库）
```

- **`checkMethod` 在认证之前**：方法表能判的（Profile / security_profile / 必填字段 /
  `target.kind`）不需要钥，先判掉就少一次 DID 解析，也少一次可以被填爆的解析。
- **认证在正文之前**：正文校验要读 `content_type`，而那是**调用方自己带来**的字段。
  没验签就拿它做判断，等于让未认证的一方指挥本服务，所以顺序反过来。
- 方法表是**数据**（`MethodSpec`）不是 `switch`：`targetMode` 一个字段同时给出
  `target.kind` 该是什么、`target` 可不可以省、以及 §6.2.5.1 L381–382 的
  `anp.invalid_target_binding` 从哪来。
- `requiresOriginProof(meta)` 是**按方法按 Profile** 的函数而不是布尔：`direct.send`
  在 Base 下要证明，在 `anp.direct.e2ee.v2` 下不要（P3 §4.3 L161，那个 overlay 用自己的
  钥材料认证发送方）。C5 的表里这个分支还走不到——`profiles` 先一步拒掉那个 overlay——
  C12 把它加进 `profiles` 时这一行必须一起生效。

**C5 明确没做的两件 MUST**，各有理由，都留给拥有那份信息的那一步：

- **P1 §7.3 L491–499**（计数器 / 序号 / 逻辑时钟 / epoch / generation 必须编成十进制
  字符串）是**按字段种类**立的规矩，不是字段名清单，而 `direct.send` 没有这类字段——
  第一个实例是 C9 的 `group_state_version` / `group_event_seq`，那时才落。
- **P3 §5.5 L208**（`meta.target.did` 已被替代时回 `anp.did_superseded`）要有**连续性
  的来源**：本服务不是 DID 权威（那是 DID 服务的事），手上没有更新链。现在做，等于在
  每次受理上挂一次不缓存的出站链查询。C4 已经留好了位置——`perform` 抛出即可——等
  连续性知识从哪来定下来再接。

两处**本实现的取舍**（规范列了拒绝、没给码），写在这里而不是散在代码里：
`meta.target` 缺失按 §6.2.5.1 L379–380 判 **1003** 而不是 1014（1014 说的是 `kind`
与方法的建模模式**不符**，缺 target 是形状问题）；正文三个载荷字段违反互斥（P3 §7.1.4
L386–387）也按 **1003**，而 1009 留给真正不支持的 content type。

第 4 步失败**不改变**第 3 步已经发出的成功语义——这正是 §1 那条"成功语义被切小"的用法。
受理路径只在 `outbox` 里落一行就结束，推送与重试全部在 §8.4。

### 8.2 `direct.incoming` 的 payload 约束

必带与原消息一致的：`meta.profile`、`security_profile`（= **原接受模式**）、
`target.kind="agent"`、`target.did`（= 接收方）、`sender_did`（= **原逻辑发送主体**）、
`operation_id`、`message_id`、`content_type`、`body`。

`params.auth` 若带 `origin_proof`，**必须是原始无损副本**，本服务**不得重签**。

**不得出现设备 selector。**

这条字段表只有一处实现：`rpc/direct.ts` 的 `incomingParams()`。投递行与出站通知用的是
**同一份** `params`——两处各拼一次，就是将来某次改动只改了一边的入口。

**一处规范内部的张力，记在这里，不去改上游**：A.3 L1046 规定 Signed Request Object
**只含** `method` / `meta` / `body`，所以原发者那份证明的 `@method` 是 `direct.send`
（A.4 L1061）。而 §7.2.3 要求转发的 `meta` 与 `body` 与原消息**逐字段相同**，于是到了
收件人手上，唯一与签名时不符的就是 `method` 变成了 `direct.incoming`。而 A.6 L1136 的
最小验证第 3 步恰恰是"使用**当前请求的** `method` 重建 Signed Request Object"——收件人
按字面重建，算出来的 `contentDigest` 不可能与传来的一致。

本服务的处理是**照 §7.2.3 与 A.8/A.9 L1161–1180 转发逐字节不变的原证明**，不重签、不
替换、也不用自己的服务身份签一份（A.8 L1167 明确禁止）。能不能验、怎么验，是收件人的
判断；把它在这里改掉，则连"原发者是谁"都不再可考。

### 8.3 订阅路（WebSocket）

上面 8.1 描述的是**服务端主动 POST 到 agent 端点**那条路，适合常驻服务型 agent。
CLI 与所有在 NAT 后面的客户端走**订阅路**：客户端主动连上 `GET /anp-im/stream`，
在同一连接上补齐（`sync.delta`）并接收实时通知。

**传输不同，信封同一个**——控制面的校验 / 认证 / 幂等 / dispatcher 全部复用。
订阅者注册表、游标语义、无空洞无重复的时序、背压，全部在
[realtime.md](realtime.md)。

两条路并存是刻意的：规范只规定了 `direct.incoming` 这个 Notification 的存在与 payload，
**没规定它走什么传输**，所以这是实现自由。

### 8.4 出站推送与退避

受理路径**不发起**任何网络请求，只在 `outbox` 落一行；推送与重试全在
`delivery/worker.ts` 的 `createDeliveryWorker()`。分家的理由只有一条：受理的整个操作
（消息 + 投递 + 幂等记录）必须在**一个事务**里，而事务里不能有网络往返——一次慢连接
会让所有并发受理在锁上等。

**载荷**：`outbox.payload_json` 存**整个通知信封**（`jsonrpc` / `method` / `params`，
没有 `id`），由 core 的 `buildMessageNotification()` 装配。存整个而不是只存 `params`，
是为了让 worker 重试时不必知道 §7.2.3 的字段表——它到那时手上只有这一行。

**推送目标**：每次尝试都**重新**解析收件人的 `ANPMessageService`
（`discoverMessageService()`，P2 §7.1），不复用受理那一刻的答案。域名可以在两次重试
之间换入口服务，钉住第一次的地址就会把重试打到一个可能已经不属于任何人的地方——这也
正是 `outbox` 存 `recipient_did` 而不是 `endpoint_uri` 的理由（§7）。

**本地投递**：解析出来的端点若**就是本服务的 `/anp-im/rpc`**，不作 HTTP 调用，直接丢掉
那一行。收件人就住在这里，`deliveries` 那一行已经是持久的，C7 的订阅路会把它交出去。
绕一次回环不但多余，还会要求运营商把自己的公网地址写进 `AGENTX_ALLOWED_DID_HOSTS`
才发得动自己。

**失败与退避**：P3 §8.4 L477 把这件事明确交给本地策略——"发送失败后是否自动重发，
**MAY** 由服务按本地策略自行决定；本 Profile **MUST NOT** 要求必须重发、固定重发次数或
固定退避算法"。本实现取：5 秒起、每次翻倍、单次上限 5 分钟、最多 8 次，之后丢弃并把次数
与最后的错误写进日志。等待取 `[0.5, 1] × 退避值` 的抖动——**不用全抖动**，因为它会让
等待趋近于 0，而在同一个 tick 里一起失败的那批条目恰好需要一个能错开的量。

**重发不改变语义**：重试用的是同一份载荷，也就是同一份 `operation_id` / `message_id` /
`body`，收件人按 P3 §8.2 L444–450 的消息级重复识别会把它认出来。§8.4 L471–477 允许这
一档，与本服务"宁可重发也不丢"的取向一致。到达次数上限的丢弃是**有意的放弃**，不是成功。

**解析策略与推送共用一套闸门**：`config.didResolution` 同时喂给定位器与
`postNotification()`。两个地址（对端的文档、对端的入口服务）都由对端选定，没有理由
一个走白名单、另一个走裸 `fetch`。默认空清单意味着**出站推送在运营商点名主机之前一律
解析不了**——失败进退避、到顶丢弃，这是与 §14 的 fail-closed 一致的后果，不是缺陷。

## 9. 取件扩展面（规范未定义，本服务自定）

规范在取件侧是空白的，且是刻意的：P3 §1 排除历史拉取 / 已读状态 / 内部同步，
P5 §10.7 与 P6 同样排除，P8 也排除。**规范里不存在 `inbox.get`**（已全文 grep 核实）。

`AgentXAgent` 必须补上这一半，否则消息只能发不能取。
**设计选择：沿用 `awiki-open-server` 已有的方法名**（`messaging/core.py:2188` 的 `MESSAGE_HANDLERS`），
自造一套只会让客户端多一个兼容分支：

```
direct.get_history
inbox.get                 # 按游标拉
inbox.mark_read
read_state.mark_read
sync.bootstrap / sync.delta / sync.thread_after
message.get_batch
```

### 9.1 扩展面自己的 Profile：`x_agentx.inbox.v1`

**这六个方法不是"没有 Profile"的，而是有它们自己的一个。** P1 §6.2.2 L277 把
`meta.profile` 定成 **MUST**，且说它是"本次请求的**唯一解释** Profile"——所以一个
扩展方法在线上必须给出一个能解释它的 Profile 值，而这个值不可能是任何一个规范 Profile
（那才是对客户端撒谎）。取值就是**扩展自己的标识符**，`x_` 前缀正是 P1 §12 给扩展留的命名空间。

**这个扩展面今天有**三**个 Profile**：取件面 `x_agentx.inbox.v1`（本节所写）、
订阅握手 `x_agentx.stream.v1`（§9.3 末段与 [realtime.md](realtime.md) §4）、
通讯录 `x_agentx.contacts.v1`（§9.4）。**按方法**取 Profile，不是一个面一个——
P1 §6.2.2 那句"唯一解释"要求 Profile 能把这条方法解释清楚，一个 Profile 罩住互不相干
的几组方法就做不到这一点。三条共用的形状（`meta.profile`、目标建模、`origin_proof`、
不进 `profiles[]`）在本节写一次，§9.4 与 [realtime.md](realtime.md) 只写各自不同的那部分。

于是同一条扩展方法在线上长这样：

```
meta.profile            = "x_agentx.inbox.v1"
meta.security_profile   = "transport-protected"
meta.sender_did         = <读自己的收件箱的那个 DID>
meta.target             = { kind: "agent", did: <同一个 DID> }
meta.operation_id       = <随机>
meta.created_at         = <ISO 8601>
body                    = <下面的参数>
```

#### 9.1.1 目标建模：`{kind: "agent", did: <收件箱主人>}`

**这一行不能省。** P1 附录 A.4 L1068：`当某方法要求 auth.origin_proof 时，meta.target MUST 存在`
——这六个方法每一个都要求。P1 A.4 L1069 又限定 `kind` 只能取 `agent` / `group` / `service`。
而 P1 A.4 L1070 把剩下的问题指名交给本 Profile：
`endpoint-local 方法若未来需要引入 auth.origin_proof，MUST 由对应 Profile 显式定义其目标建模与重建规则`
——取件面正是一组 endpoint-local 方法，所以**建模规则写在下面，服务端按它实现校验，不算实现细节**。

**建模：`kind` 取 `agent`，`did` 取收件箱主人，与 `meta.sender_did` 同值。**

- 不取 `group`：群消息也进同一个收件箱（§9.3 的 `inbox.get` 一次返回两种），
  而 `kind` 描述的是**这次请求作用在谁的身份上**，不是里面装了哪些消息。
  群自己的 `kind: "group"` 出现在**投递帧自己的** `meta.target` 里（§8.2），那是另一个信封，不是请求的。
- 不取 `service`：`service` 是"服务自身"这一类目标（如 §13 自述），
  而读收件箱是**代理某个身份的数据**，不是服务的数据。
- 不取 `peer_did`：`direct.get_history`（见下面那张表，v1 未实现）的 `peer_did` 在 `body` 里，
  它是**筛选条件**，不是签名绑定的对象。

**重建规则：服务端只从收到的 `meta.target` 重建 `@target-uri`**，即
`anp://agent/{pct-encoded meta.target.did}`（P1 A.4 L1062、L1067），
并且 **MUST NOT** 从 `body` 的任何字段去推它——`peer_did` / `message_ids` 都是调用方给的，
拿它们拼签名基准等于让调用方决定自己签的是什么。
校验时另加一条本服务自己的约束：`meta.target.did` **MUST** 等于 `meta.sender_did`，
否则拒绝，回 P1 公共错误 **1014 `anp.invalid_target_binding`**（P1 §10.3 错误表 L715；
L734 把 "目标绑定错误、service-scoped / endpoint-local 误用" 一并指向这个码）
——本扩展面没有"代别人读收件箱"这种操作，
把这一点做成显式校验，而不是留给"反正也读不到"的隐式结果。

跨服务转发下这条也稳：`@target-uri` 由 `meta.target` 重建，
而 `meta.target` 进了 `contentDigest`（P1 A.4 L1074），所以联邦转发时签名不因中间域改写而失效。

**不得出现在 `anp.get_capabilities` 的 `profiles[]` 里**——那是"这个服务实现了哪些规范
Profile"的答案，混进一个 `x_` 值就把它变成另一个问题了。扩展能力的自报位置见 §13
（well-known 的 `x_agentx` 块）与 [realtime.md](realtime.md) §9（`stream.hello`）。
客户端据此判定对端支不支持扩展；判不出来时按"不支持"处理（[cli.md](cli.md) §5）。

### 9.2 认证：`origin_proof`，不是 bearer

扩展面的读请求**和规范面的写请求走同一套认证**：`origin_proof` 签
`{method, meta, body}`，`meta.sender_did` 是**被读的那个收件箱的主人**。
服务端据 `origin_proof` 的 `keyid` 认人，不需要 bearer。

这条是与 `awiki-open-server` 的**唯一实质分歧**，且它是必须的：awiki 的取件面
（`protocol/registry.py` 里 `surfaces=("local",)` + `principal="local_bearer"`）要的是
`Authorization: Bearer`，由 `user_compat/core.py:222` 的 `current_did(request)` 取出，
缺了直接 `Unauthorized("missing_bearer_token")`；而且这些方法只挂在
`POST /im/rpc` 上，那条路由（`app/routes.py`）以 `strict_anp=False` 直接
`dispatch`，**不做任何信封校验**。

结论：**`connectx` 的取件命令够不着 awiki 的取件面。** CLI 不持 bearer（见
[cli.md](cli.md) §6：规范里 bearer 只是可选优化，且 MUST NOT 替代 `origin_proof`，
所以 CLI 始终签名），而 awiki 只看 bearer。**沿用方法名的收益因此只剩"名字一致"**，
不能再说成"同一个 `connectx` 对两个服务都能用"。方法名与参数形状以本文为准。

### 9.3 方法与参数形状

写在这里是因为两边都要实现它：`packages/service` 实现它，
`packages/cli` 的 `msg inbox` / `show` / `read` 调用它。`params.body` 就是下表那一列。

| 方法 | `body` | 结果 |
|---|---|---|
| `inbox.get` | `{limit?, skip?, include_read?, device_id?}`，`limit` 默认 20 | `{messages: [...], total, has_more}` |
| `inbox.mark_read` | `{message_ids: [...]}` | `{updated_count, message_ids, read_at}` |
| `message.get_batch` | `{message_ids: [...], device_id?}`，≤ 100 且不重复 | `{items: [{message_id, message}], unavailable: [...]}` |
| `direct.get_history` | `{peer_did, since_seq?, limit?}` | `{messages: [...], has_more}` |
| `sync.delta` | `{since, limit?, device_id?}` | `{messages: [{seq, method, params}], next_since, has_more}` |

`device_id` 是 P5 之后加的第三列，**选填**，语义见 [e2ee-direct.md](e2ee-direct.md) §4：
一台设备只能读到账号级那一批加上**投给它的**那一批（§10.7.1 L1407 的读侧）。**缺席不是
"没有限制"**，是"没声明自己是谁"——那样就只有账号级的那批。订阅路的 `stream.auth` 早
就是按这个规则推的，拉取这一侧跟上之后，同一条信箱的两半才说得出一致的答案。
`inbox.mark_read` 没有这一项：已读状态是账号级的，它不是交付。

表里是 `POST /anp-im/rpc` 上**可达**的那几个。流自己的两个方法
（`stream.auth` / `stream.ack`，各自的 Profile 是 `x_agentx.stream.v1`）不在其中，因为
它们离开了连接就没有意义——`stream.auth` 在 HTTP 上没有订阅可注册，`stream.ack` 在 HTTP
上不知道是哪台设备（游标按 `(owner_did, device_id)` 分片）。形状见
[realtime.md](realtime.md) §4 与 §6。它们与上表走**同一条**校验与认证路径，不是另一套。

**`direct.get_history` v1 不实现。** 它不是"没人要"，而是它的 `since_seq` 没有定义：
出站消息**不带序号**——`direct.send` 的 `body` 里没有这个字段，服务也从不给它分配，
因为序号是**收件箱级**的交付计数器（`deliveries.seq` 按 `(owner_did)` 递增，§7 与
[realtime.md](realtime.md) §5.1），而 `peer_did` 问的是**一个会话里**的历史。
"会话内第 N 条"这个数本服务手上没有，造一个（按 `created_at` 排名？）会得到一个
在不同实现间对不上的私有游标，正是 `sync.delta` 的 `seq` 已经做对的事。
所以 v1 不发这个方法，也**不用 `inbox.get` 的 `skip` 顶替**：`skip` 是**时间序偏移**，
会话之外的新消息落进来会让它错位——那不是游标，是页码。
实现一个还在犹豫用的东西，不如先让 `inbox.get` + `message.get_batch` 把这一半跑顺。

`sync.delta` 的每一项就是订阅路会推的那一帧，原样（`method` 是
`direct.incoming` / `group.incoming` / `group.state_changed` / `group.e2ee.notice`，
`params` 是 §8.2 那个形状），外加它被分配的**交付序号** `seq`。这样补齐与实时两条路
在客户端汇成同一个渲染器——[realtime.md](realtime.md) §5.5 说明为什么实时帧上不需要带 `seq`。

`inbox.get` 的每一行就是 `direct.send` 的 `body` 加上投递元数据，并**必须**带：

```
message_id         # 与 `id` 同值；`message.get_batch` 收的就是它
sender_did / recipient_did
content_type
direction          # "incoming" / "outgoing"，按 sender_did 与会话主人的关系算
created_at
read_at            # 未读为 null
```

**`message.get_batch` 收 `message_ids`，不是 awiki 的 `event_ids`。** 这一处是**故意**偏离：
`event_id` 是服务端同步日志的内部标识符，`inbox.get` 从不返回它，于是
`connectx msg show <id>` 拿 `msg inbox` 打印出来的 id 根本调不动 awiki 那个形状——
一个命令的第一个参数取不到第二个命令给的输出，这不是兼容性差异，是断链。
改收 `message_id` 之后，`msg show` 的参数就是 `msg inbox` 打出来的那个 `id`。

**`--all` 不是一个新的参数形状。** `connectx msg read --all` 的语义是"把此刻未读的全部
标为已读"，实现是先 `inbox.get`（`include_read=false`）翻页取齐，再把这些 id 交给
`inbox.mark_read`。这样"标记"这一步永远作用在**明确列举过的 id** 上，
落在两次调用之间的新消息不会被静默吞掉。

P5 的 **Mailbox** 不是这条路。Mailbox 是范围为 `(recipient_did, recipient_device_id)` 的
**不透明密文队列**，不持有 Ratchet 状态，**不是群/私聊历史**。
E2EE 会话里的取件走 Mailbox，明文历史走 `inbox.get`。两者别混。

### 9.4 通讯录扩展面：`x_agentx.contacts.v1`

**这是第三个扩展 Profile**（前两个是取件的 `x_agentx.inbox.v1` 与订阅握手的
`x_agentx.stream.v1`），它答的是一个取件面不管的问题：**"这个名字对我来说是谁"**。
ANP 按 DID 寻址，而人（以及转述人话的 agent）手里拿的是名字——"给 Alice 捎个话"
里的人名，线上无人可达。名字到 DID 的这一层规范没有定义，也不该定义：
它是**调用者自己的记忆**，不是任何一份 DID 文档里的事实。

**为什么它落在服务端，而不是客户端的一个文件。** 备注是"我**给**他起的名字"，
而"我"在服务端已经有一个确定答案了——就是这条请求的 **已验证签名者**。
所以行由 `owner_did`（`meta.sender_did`）分行：一个身份的备注对另一个身份
**天然不可见**，这是结构上的，不靠文件权限；本地也不必再存第二份并与服务端保持同步。
（对比 TODO6 §3.3 最初的设想——`<store root>/contacts.json`——那份东西的可见性是靠
`0600` 得到的，而"整机一张"与"每个 agent 一张"的粒度之争在服务端取值下根本不会出现：
粒度是**身份**。）

**键是 `subject`，不是 `did`。** 「备注」「昵称」「subject」是三个不同的东西：
备注是**我**给他起的（本地/本服务的记忆），昵称是他**自己**起的（在他自己的主机上），
`subject` 是**协议**给的稳定主体（在 DID 文档里，且就是为了"换钥不换人"才存在）。
`did update` 会把 DID 挪走（它内嵌了钥指纹），所以一条备注若挂在 `did` 上，
就会在对方换钥的瞬间**静默消失**，而用户看到的是"通讯录里怎么少了一个人"。
`subject` 去掉指纹、留下"还是同一个人"的那一段，正是为这件事存在的。
**`subject` 由服务端从 `did` 推导，调用方不能给**——让调用方给，就是把键的定义
分给了每一个客户端。`did` 因此是**列**不是键：它随换钥更新，行不动。

```ts
subjectOf(did)     // did:wba → 去掉变化的那一段（钥指纹），其余原样返回
```

`subjectOf` 对不是 `did:wba` 的输入**原样返回**（它是全函数），所以
`contacts.put` 收一个非 DID 的字符串会成功存下一行——**"是不是 DID"由调用方在参数处挡住**，
服务端不替它判（服务端只保证键稳定，不保证键可达）。`agentx-cli contacts add` 因此在
开身份之前就先拒掉非 DID 输入。

**目标建模与 §9.1 同规。** `meta.target = {kind: "agent", did: <owner_did>}`，
与 `meta.sender_did` 同值；`meta.target.did` **MUST** 等于 `meta.sender_did`，否则回
**1014 `anp.invalid_target_binding`**。这里没有"改别人的通讯录"这种操作，
把它做成显式校验而不是"反正也写不进去"。`meta.profile = "x_agentx.contacts.v1"`，
认证走 `origin_proof`（§9.2），同样**不得**出现在 `profiles[]` 里（§9.1 末段、§13）。

| 方法 | `body` | 结果 |
|---|---|---|
| `contacts.list` | `{}` | `{contacts: [{subject, did, remark, created_at, updated_at}]}` |
| `contacts.put` | `{did, remark?}` | `{contact: {...}, created: bool}` |
| `contacts.remove` | `{subject}` | `{subject, removed: bool}` |

`contacts.list` 按 `(owner_did)` 取全部行，按 `subject` 排序，`remark` 缺失时报
**JSON `null`**——"没有备注"与"这个服务不返回备注"不能长得一样。

**`contacts.list` 没有"按名字查一条"的变体，是刻意的。** 判定重名要能列出**候选**，
而候选只有拿到全表才列得出来；把名单留在客户端，"两个 Alice 就拒、并把两个都列出来"
这条规则就只有一处实现（[cli.md](cli.md) §5 的负结果纪律同理）。`contacts` 一族是
"整本取回、本地判定"，不是"服务端搜索"。

`contacts.put` **是幂等的 upsert**，键是 `subjectOf(did)`：已有行则更新，
`created: false`，且 **`created_at` 保持不变**（它是"这一行什么时候进来的"，
不是"最后一次被摸是什么时候"——后者是 `updated_at`，每次写都刷新）。

`remark` **缺席即清空**——线上没有"三态"，
所以"保留原备注"是**客户端**的语义（`agentx-cli` 用缺席＝保留、`--clear-remark`＝清空），
服务端只认"给了就写、没给就没有"。这一处不对称是**故意的**：服务端做最简单的
那件事，把"缺字段算不算一次修改"这个判断留给唯一知道用户意图的那一层。

`contacts.remove` 的线上参数是 **`subject`**，不是 `did`——键就是 `subject`，
让调用方拿 `did` 来删，服务端就得再算一次 `subjectOf`，而"算键"这件事只有一处是对的
（服务端）。回 `removed: false` 而**不是报错**：删一个已经不在的人是一次成功的删除，
不是一个错误。要按名字删是**客户端**的事——它先 `contacts.list` 把名字解成 `subject`。

#### 9.4.1 写入路径 ②：一封来信就会让这行出现

这本书有**两个**写入者，不是一个。除了上面那三条方法，还有一条**不经过 RPC** 的：

**一条 `direct.send` 被本地受理时，服务端顺手把发件人记进收件人的通讯录。**

它写的是"**认识一下**"，不是"起个名字"，所以：

- 行落成 `remark` 为 `null`（只能按 DID 找到，等用户给它起名）；
- 键同样是 `subjectOf(发件人)`，所以同一个人第二封落回同一行；
- **`remark` 一个字节都不动。** 这是它与 `contacts.put` 唯一、也是全部的区别：
  `contacts.put` 的线上规则是"缺字段即清空"，而一封来信对名字**没有说任何话**，
  照搬那条规则就会在被起过名的人下次来信时把名字抹掉——`msg send --to Alice` 随即找不到人。
  同理 `created_at` 保留。所以服务端有 `rememberContact`（只挪 `did` 与 `updated_at`）
  与 `upsertContact`（整行以这次为准）两条路径，是**故意的**：把"谁有权改名字"写进代码形状里。
- 它在受理的**同一个事务**里（§8.1），所以不会出现"消息在、人不在"。

顺带答掉一半的"换钥之后怎么办"：对端换钥后**只要再写一封信**，新 DID 就随
`meta.sender_did` 落回这一行的 `did` 列，而行与备注不动。剩下的那一半（对端换钥后
一直不再写信，本地的 `did` 停在新钥之前）仍然没有人触发刷新——那时**按 DID 发信会失败，
按名字解析出来的是同一个 subject，仍然是那个旧 DID**。这一条是已知的、还没解的问题。

**收到过的信会让人回来。** 删掉一个人之后他再写信，他又出现在书里（没有备注）。
这不是缺陷，是 ② 的直接推论：这条路径回答的是"谁跟我说过话"，而删除回答的是
"我现在不想看到他"——两条意图不同，服务端只实现了前者。要真正屏蔽一个人需要的是
别的机制（还没设计），不是让通讯录假装他从未出现。

**不做的事记在这里**：没有 `contacts.get_profile` 之类的跨域拉取。昵称与头像在
**对方自己的**主机上（`get_me`），把它们拷进来就是一份**没有失效机制**的缓存——
对方改了昵称，本地这份不会知道。`contacts` 只答"这个 DID 对我来说是谁"，
不答"他自己说自己是谁"，后一个问题属于对方的主机。

**也记一条没做的**：`contacts.put` 收的是 `did`，服务端**不校验它是活的**（不解析、
不发现）。通讯录可以录一个此刻解析不了的 DID——"我认识这个人"和"这个人此刻在线"
是两件事，把它们绑起来会让"对方主机挂了"变成"我不能给他加备注"。可达性由
`msg send` 那一刻的发现去答。

## 10. 联邦（P8）

**没有中继协议。** P8 §3.1 明确：发送方域**直接复用原业务方法**，不新增 Relay 方法。
发送方域按 `target.kind` 路由到目标域，把**原始**方法 POST 到对方入口服务。

本服务作为**接收侧**要做的：

1. 用发送方 `serviceDid` 验外层 HTTP 认证（§6.2.2 L374–383 的八步）
2. 按 §5.2 调 caller anchor
3. 直接进入正常处理流程——跨域与同域在业务语义上**没有区别**

本服务作为**发送侧**要做的：解析目标公开的 `ANPMessageService`，**不是自己**就用
**自己的** `serviceDid` 签外层请求，把**原始**方法发过去，业务层的 `origin_proof`
原样带上。

失败与重试：复用原业务幂等语义；重试**保持** `operation_id` / `message_id`，
负载语义等价，设备 selector 不变。内部 trace / attempt 字段**不得**替代幂等键。

**DID 停用**：应用处理前可返 HTTP 409；进入应用处理后返 `anp.did_superseded`。
同一请求 **MUST NOT** 两层都返。

全部决策、依据与三处偏离（外层认证失败回 401 而非 200；`direct.incoming` 不是跨域
消息、跨域转发的是原始 `direct.send`；**请求同步转发 / 通知异步 outbox** 的二分）见
[federation.md](federation.md)。

## 11. E2EE 对本服务的硬约束

- **MUST NOT 解密或重加密**（P5 §1392、P6 §1496）。P5 这一侧服务端只有两件事：
  **钥匙柜**（§4.4 L204–210 那七项密钥材料能力）与**邮箱**（§10.7 L1391 只放不透明密文）。
  §14.3 L1590–1594 说明这条边界的价值：一个恶意 Key Service 最坏只能拒绝转发、
  拒绝发放 OPK、诱导建链失败。
- **设备寻址是本层的一等公民**，且资格**每次操作都要重判**（P5 §4.1.1 L171–178、
  §12.4 L1515、P2 L630）。所选设备不在**当前** Manifest 里、未宣告本 Profile、
  或密钥引用对不上 → 停止供材料、停止入队投递、拒绝新材料并停用受影响 Session。
- **Mailbox 的键必须含设备**：§10.7 L1396「其授权与投递键 **MUST** 包含接收 DID 与设备」，
  而 [realtime.md](realtime.md) §5.1 L111 现在把 `device_id` 定成"搭车过来"——
  C12 要把订阅路由键从 `owner_did` 变成 `(owner_did, recipient_device_id)`。
  这条缝的完整说明在 [e2ee-direct.md](e2ee-direct.md) §4，C6 / C7 要先留出那一列。
- **§11.5 的两类状态一边一半**：外层幂等记录归服务端（就是 §6 那张表，键多两个设备段），
  init replay 记录归客户端（键含 `session_id`，是 DH 产物）。
- Device Delivery Queue 只持久化**公开元数据 + 不可读密文**（P6 §1508）。它与 P5 的
  Mailbox **是同一张表、同一个键**（`(recipient_did, recipient_device_id)`），别建两张。
- **P6 里 Host 不是控制者、不是成员、也不做最终 MLS 有效性判断**（§3.6 L199–204、
  §11.11 L1386）。它权威地知道的只有一份 `(DID, device)`→leaf 的**公开投影**
  （§11.10.3 L1372，不含任何能参与运算的材料），以及排序位置。
- `group.e2ee.leaf_not_current`（5013）是**强制的稳定错误**，且判定序固定：
  先 `group.not_member`（DID 不在 P4 `active`）→ 再 core 设备码 → 最后 5013，
  **MUST NOT** 折叠（§13.3 L1625）。它是"仅 leaf 被移除"时设备唯一的拉取式终态信号。
- DID 更新编排期间 Host **MUST** 串行化控制动作并**暂停**该群新的 `group.e2ee.send`
  （§10.5 L1092、L1094）；但**设备级撤销不暂停**（§10.4 L1074）。
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

这一节是**服务的视角**，只有流程和五条约束。三个平面各自站在哪、Access Grant 在哪一刻
长出来、票据为什么不签名、对象字节落盘与两条数据面路由、以及错误码里哪些在 v1 没有
产生路径，见 [attachments.md](attachments.md)。

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
本服务不写**别人**的 DID 文档，只交出这段 JSON。

**一处例外：本服务名下那些群的文档由本服务自己写**（B1b）。群 DID 就住在自己的命名空间里
（`<serviceDid>:g:<id>`，[groups.md](groups.md) §2），文档因此挂在
`GET …/g/<id>/did.json`（§2.3），里面那条服务条目就是**上面这段 JSON 原样搬过去、只把 `id`
换成群的**。所以上面那句"`id` 由嵌入方改写"仍然成立，只是**嵌入方变成了本服务自己**——而
本服务自己的身份文档（`config.serviceDid` 那份）依旧由 `awiki-open-server` 托管，外层 `keyid`
的 fragment 仍必须与发布方写进去的那一条对上（[federation.md](federation.md) §4 第 2 点）。
两者的区别值得记住：**群文档是本服务签的，服务自己的文档不是。** 这是应有的分工，不是待补的
缺口（2026-10-02 的裁定：**DID server 只管身份，本服务承载社交应用**）——身份文档归身份层，
群文档是消息层的产物，所以后者在本服务手里。同一裁定也意味着：身份文档里那条
`ANPMessageService` 指向谁，由**身份所有者**声明，DID server 只负责签进去，不替它决定。

**`id` 由嵌入方改写。** 上例里的 `…#anp-message-service` 省略的那一段是**文档所有者的
DID**：服务条目住在被描述的那个 agent（或群）的文档里，而本服务不知道对方是谁，也给不出
那个 DID。所以本服务交出的是自己那半边能给出的东西——`<自己的 serviceDid>#anp-message-service`
——**嵌入方把 DID 那一段换成自己的**。给一个真实存在、可解析的 DID，比给一个占位符好在：
忘了改写的时候，那个 id 至少是一个真 DID，而不是一段没人认识的字符串。

条目的字段分两处取，且**都必须**与实现一致：
- `serviceEndpoint` / `serviceDid` 来自配置（§14）；
- `profiles[]` / `securityProfiles[]` 从方法表**推出**（`capabilities.ts` 的
  `serviceCapabilities()`），与 `anp.get_capabilities` 的运行时答复**同源**，所以
  §8.3 L591–593 那条"冲突时以运行为准"在本服务里永远无事可做——两处不会不同。

**扩展能力不在那个条目里声明。** `profiles[]` / `securityProfiles[]` 只放规范定义的
Profile 与安全模式——把 `inbox.*` / `sync.*` / 订阅流塞进去，就是在对客户端撒谎
（一个只实现规范的服务会被误认为支持它们）。扩展能力另走一处，
由 `GET /.well-known/anp-message-service.json` 的一个 `x_agentx` 块自报，
并在订阅握手的 `stream.hello` 里再报一次（见 [realtime.md](realtime.md) §9）。
块里放的是 `x_` 命名空间下的东西（§9.1、§9.4 与 [realtime.md](realtime.md) §9 那三个
Profile 名），以及分属它们的方法：

```json
{
  "x_agentx": {
    "profiles": ["x_agentx.contacts.v1", "x_agentx.inbox.v1", "x_agentx.stream.v1"],
    "methods": ["contacts.list", "contacts.put", "contacts.remove",
                "inbox.get", "inbox.mark_read", "message.get_batch",
                "stream.ack", "stream.auth", "sync.delta"]
  }
}
```

`methods` 里的 `stream.*` 只在 WebSocket 上可达（§9 与 [realtime.md](realtime.md) §9）：
块说的是"这个服务有这些扩展方法"，**不是**"它们都能 POST 到 `serviceEndpoint`"。传输由
Profile 决定，所以没有按传输再分一层——多一层形状就多一处要维护的约定。

**`anp.get_capabilities` 只报规范字段**，扩展不进它的 `supported_profiles`：那个结果是
"**规范**能力"的运行时权威（§8.3 L592），掺进扩展会让一个标准客户端按规范理解出一个
错误的结论。

## 14. 配置

```
AGENTX_LISTEN           监听地址，默认 127.0.0.1:8787
AGENTX_PUBLIC_URL       对外可见的基址（用于 serviceEndpoint / object_uri）
AGENTX_SERVICE_DID      自己的服务 DID，默认由 PUBLIC_URL 推出 did:web
AGENTX_KEY_FILE         服务签名钥（跨域时签外层请求；hex 或 PEM）
AGENTX_KEY_ID           该钥的 keyid，完整 DID URL 且挂在 SERVICE_DID 下（配了 KEY_FILE 就必填）
AGENTX_DB               SQLite 路径，默认 ./agentx.db
AGENTX_OBJECT_DIR       附件对象目录（按摘要寻址，见 attachments.md §4）
AGENTX_MAX_BODY         请求体上限，默认 1 MiB（附件走数据面，不经这里）
AGENTX_MAX_OBJECT_BYTES 单个附件对象上限，默认 64 MiB（数据面 PUT 时边收边判）
AGENTX_ALLOWED_DID_HOSTS  允许出站解析 DID 文档的域，逗号/空白分隔，**默认空**
AGENTX_DID_DEV_HOSTS      联调放宽：这些域可以解析私有地址、可以用 http
AGENTX_DID_CACHE_TTL_MS   一份解析出来的 DID 文档最多沿用多久，默认 5 分钟（见下）
AGENTX_PREKEY_BURST       两条 Key 方法每个调用方的突发额度，默认 60
AGENTX_PREKEY_PER_MINUTE  同上，每分钟补充的令牌数（持续速率），默认 60
AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS  一条 P6 设备信封最多尝试几次，默认 8（§12.6 有界保留）
AGENTX_DEVICE_QUEUE_MAX_AGE_MS    一条 P6 设备信封最多在队里待多久，默认 24h（§12.6 有界保留）
AGENTX_DID_REFRESH_INTERVAL_MS    定时刷新成员 DID 的间隔，默认 6h（A3c-4，见下）
AGENTX_DID_REFRESH_BATCH          一轮最多查几个成员，默认 20（A3c-4，见下）
```

**没有配置项能关掉 `origin_proof` 校验。** 要联调就配一个宽松的 DID 解析策略，
不要开后门——那扇门会在某次部署里被忘掉。放宽正好是这两个变量：`ALLOWED_DID_HOSTS`
默认**为空**，也就是默认只认随请求带进来的内联文档，任何出站解析都被拒（fail-closed）；
`DID_DEV_HOSTS` 是给本地联调用的，它同时把域名加进白名单、并允许私有地址与明文 http。
两者都要求**逐个点名**，所以没有哪个取值能让解析变成无界的。

**代价**：接收跨域请求要解析对端的 DID 文档（caller anchor 与 `serviceDid` 各一份），
所以跨域接收在默认配置下**跑不起来**，必须把对端域加进 `ALLOWED_DID_HOSTS`。
关掉开关比放松白名单危险得多，所以这条不改，写清楚见
[federation.md](federation.md) §2.5。

**DID 文档缓存**（A3）：受理、投递、出站三条路共用**一份**进程内缓存，每个 DID 每个 TTL
窗口最多抓一次——不配它，同一次投递里"找入口"与"看设备清单"会把同一份文档抓两遍。它同时
是**对端身份变化的发现时延上界**：ANP 不为文档变化提供任何推送（P2 §5.5 规则 8），所以这个
窗口不可能为零，只能由这个数封住。缓存里放的是**已验过、且当下仍是当前版本**的文档：标了
`deactivated` 或带 `successorDid` 的文档不写进缓存，缓存里那份一旦变得不再是当前版本也不再
被读出（core `resolveDid.ts` 的 `isSuperseded`）。

**换 DID 的两条界**（A3c）。除了上面那份文档缓存，转移链还共用**一份进程内的"见证过的边"
台账**（core `did/chain.ts` 的 `DidChainEdgeStore`）。它不省任何工作——缓存里的边不会被拿来
代替重新验证——它只让"同一个旧 DID 先后指向两个不同的后继"这条冲突**跨解析**可见，而 P4
§8.12 要求接受一次换 DID 之前先确认"no … fork … exists"。没有这块台账，两条各自成立、合起来
是分叉的转移，谁都发现不了。同样因为没有推送，这个判断也只能覆盖**本进程见过**的那些边。

第二道界是**保证档位的可达范围**。§8.12 把 `provider_asserted` 交给业务策略决定，本服务的
选择是只收 `verified` / `recovery_verified`（用户 2026-10-02 裁定）。而 `recovery_verified`
本身要求"用一把**停用之前**的文档授权过的恢复钥"来验——那份"停用之前的文档"只能是文档缓存里
上一次解析留下的那一份。所以**恢复路只能在缓存 TTL 窗口内走通**：窗口外对端就得走一次
`verified`。这是收窄不是放行，方向与 §8.12 一致，所以不额外加配置项。

**换 DID 怎么被发现的**（A3c）。§8.12 的 `group.member_did_update` 是**宿主动作标识**，
被调用 MUST 回 `-32601`——没有任何客户端能让它发生，所以只能由 Host 在别的事的路上顺手做完。
本服务实现规范点名的全部三条：**请求触发**（一个可能的新 DID 来发 `group.send` /
`group.leave` / `group.update_profile` / `group.update_policy`，或来读私有群的
`group.get_info`，落 `rpc/memberDidUpdate.ts` 的 `adoptMemberDidForRequest`）、**投递触发**
（正要投给一个名册里的旧 DID 时先看一眼它有没有合规后继，挂在设备队列投递前那次资格复核上）、
以及**定时刷新**（`refresh/memberDidRefresh.ts`）。三条都收敛到同一个原子改名，靠 §8.12 那个
确定性操作标识幂等。

定时刷新是唯一能碰到**安静的成员**的一条：不请求、也收不到信封的成员，前两条永远不会经过它，
名册就会一直认着一个已经不该被授权的旧 DID。它的节奏是部署档位（默认 6 小时一轮、一轮 20 行）：
一轮的开销**恒为 20 次解析**，与群有多大无关；取行时**最久没看过的优先**，所以所有成员按同一
周期轮转。把 N 个成员轮一遍要 `ceil(N/20)` 轮，一个 1000 成员的部署因此约 12 天，要更快就调大
`AGENTX_DID_REFRESH_BATCH`。`group_members.last_did_checked_at` 是它的游标，记的是"看过"而不是
"没问题"——一次解析失败也盖章，否则一个暂时不可达的对端会卡住整个队列。它与两条队列 worker 分开
也是因为这个节奏差着四个数量级。

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
   —— 语义见 [groups.md](groups.md)
8. P7 附件数据面 —— 三平面、Grant 在承载消息被接受时才出现、数据面两条路由
   —— 决策见 [attachments.md](attachments.md)
9. P8 跨域：`serviceDid` 外层认证（八步 + 重放缓存）、请求同步转发 / 通知异步 outbox
   的二分——决策见 [federation.md](federation.md)

**v3**

10. P5 E2EE（prekey bundle + Mailbox）——钥匙柜与邮箱、OPK 池只出不进、
    Mailbox 加设备维度——决策见 [e2ee-direct.md](e2ee-direct.md)
11. P6 群组 E2EE（KeyPackage 三态柜子 + Device Delivery Queue + 公开投影 + DID 更新暂停）
    ——决策见 [e2ee-group.md](e2ee-group.md)

**发布前置条件**（不是本仓库的活，但会挡住 P6）：P6 仍是候选状态，
MLS `ExtensionType 0xF0A1` 待 IANA 注册（`README.md:10,34`；`06:98`）。
在它落地之前，P6 的能力**不得**在 `anp.get_capabilities` 里声明为稳定 Profile。
