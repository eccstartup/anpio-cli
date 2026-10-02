# 实时接收（`msg listen`）设计

按 Signal / 微信那类 IM 服务的模型来设计：**服务端持有账号的消息队列，客户端连上去、
按游标取、同时被推。**

这一层补的是规范刻意留白的一半（见 [cli.md](cli.md) §5），也是 `AgentXAgent`
作为"一个能用的消息服务"与"一个符合规范的投递端点"之间的差。

---

## 1. 为什么要有这一层

先用规范的措辞把边界钉死（P3 §3.3）：`direct.send` 返回成功**只**表示
"目标 Agent 的入口服务已接受、已进入协议处理边界"，**不**表示已展示、已处理。
而 `direct.incoming` 是 Notification，"**不改变** `direct.send` 的成功语义"。

这两句话合起来就是本设计的全部立足点：

> **推送是尽力而为的优化，游标和存储才是事实。**

任何一条推送丢了，都不影响消息的最终送达——因为下一条路是拉。
Signal 和微信都是这么做的（Signal 的消息队列 + APNs 提示、微信的 synckey + 长连接）。

### 规范的两条路，本设计选第二条

| | 推送方 | agent 需要 | 适用 |
|---|---|---|---|
| **A. 规范字面的 push** | 服务端 POST `direct.incoming` 到 agent 的端点 URL | 跑一个 HTTP 服务、有公网可达地址 | 常驻服务型 agent |
| **B. 订阅** | 服务端在**客户端主动建立**的连接上推 | 只要能往外连 | CLI、桌面、NAT 后面的一切 |

**CLI 走 B。** 理由很直接：`connectx` 在 NAT 后面，没有入站端口。
B 也同时解决了"游标从哪来"——连接是客户端建的，它自然能把自己的游标带上来。

A 不是被否掉，是留给常驻服务型的 agent。**两条路并存**，用同一个信封、同一个
dispatcher，只是传输不同（见 §3）。

## 2. 模型：Signal / 微信 的共性

把两个产品抽象掉外壳，剩下的骨架是一样的，本设计照抄这个骨架：

| 骨架 | Signal | 微信 | 本设计 |
|---|---|---|---|
| 持久连接 | WebSocket | 自有长连接 | WebSocket |
| 取件游标 | per-device queue | per-device synckey | per-`(owner_did, device_id)` 单调序号 |
| 重连补齐 | 带游标重连 | 带 synckey 重连 | 带游标重连 |
| 推送的作用 | 提示"有新东西" | 直接投递 | **只提示 + 顺带投递** |
| 投递确认 | 独立于已读 | 独立于已读 | 独立于已读（见 §6） |
| 多设备 | 每设备独立队列 | 每设备独立 | 每 `(did, device_id)` 独立 |

关键的一条：**连接断开不代表消息丢失，只代表推送暂时不可用。**
存储与游标在服务端，重连即补齐。

## 3. 传输：WebSocket 上的 JSON-RPC

`GET /anp-im/stream` → WebSocket 升级。

**帧就是 JSON-RPC 2.0 信封**，与 HTTP 控制面**完全同一套**：

| 方向 | 帧 |
|---|---|
| 客户端 → 服务端 | Request（带 `id`）：`sync.delta` / `inbox.mark_read` / 任何普通方法 |
| 服务端 → 客户端 | Response（带 `id`）：对上一条的回应 |
| 服务端 → 客户端 | **Notification**（无 `id`）：`direct.incoming` / `group.incoming` / `group.state_changed` / `group.e2ee.notice` |

**这是本设计最省事的一处：控制面的 Envelope 校验、认证、幂等、dispatcher 全部原样复用，
一行都不用重写。** 只是把"读一个 HTTP body"换成"读一个 WebSocket 帧"。

那条"禁 batch"的规则在流上也照样成立（P1）。`id` 必须是非空字符串也照旧。

## 4. 连接与握手

```
client                                server
  │  ── WS upgrade ──────────────────►  │
  │  ◄─ stream.hello {server_did,        │   服务端自报身份，客户端可据此校验
  │       head_seq, profiles[]}          │   head_seq 此刻只能是 0：信箱还没被认领
  │  ── stream.auth {device_id, cursor}► │   origin_proof 覆盖这次握手
  │  ◄─ stream.ready {device_id,         │   注册完成，head_seq 是订阅起点（权威值）
  │       cursor_accepted, head_seq}     │
  │  ── sync.delta {since: cursor} ────► │
  │  ◄─ Response {messages: [...]}       │   补齐
  │  ◄─ direct.incoming × N              │   补齐响应发出后才开始刷实时通知
  │  ── stream.ack {seq} ──────────────► │   推进交付游标（§6）
  │  ◄─ Response {cursor}                │
```

四条要点：

1. **握手要认证。** `stream.auth` 帧里的凭据覆盖 `{method, meta, body}` 的 JCS 规范化对象，
   与 HTTP 控制面同一套 `anp-rfc9421-origin-proof-v1`。握手失败即关连接，
   错误码沿用控制面那套。
2. **`stream.hello` 让客户端先看到服务端是谁。** 客户端应校验 `server_did` 与自己
   从 DID 文档解析出的 `serviceDid` 一致——连接是明文升级的，这一步是防中间人的第一道。
   它带不了别的：head 是按信箱算的，而信箱要到 `stream.auth` 才认领，所以**权威的
   `head_seq` 随 `stream.ready` 给**，`hello` 里那个是占位。
3. **服务端在补齐完成前不刷实时通知。** 见 §5，这是无空洞无重复的关键。
4. **两个 Profile 分属两件事。** `stream.auth` / `stream.ack` 是传输自己的
   `x_agentx.stream.v1`，`sync.delta` 与 `inbox.mark_read` 是取件面的
   `x_agentx.inbox.v1`（§9）。`meta.profile` 是"本次请求的唯一解释"，所以它是**按方法**
   给的，一条连接上两种都有；给错了就是 1001 `anp.unsupported_profile`。

## 5. 游标：无空洞、无重复

### 5.1 序号从哪来

交付序号是**收件箱级**的：服务端为每个 `owner_did` 维护一条单调递增的计数，消息落库时
分配，**在同一事务里**（[message-service.md](message-service.md) §7 的 `deliveries.seq`）。

游标才是按设备分的：`delivery_cursor` 的主键是 `(owner_did, device_id)`。两者不是一回事
——序号属于**账号**（同一封消息在账号里只有一个号，账号下哪台设备看到都一样），游标属于
**设备**（每台自己读到哪了）。订阅路因此按 `owner_did` 路由，`device_id` 只是搭车过来，
好让连接知道自己推的是谁。

### 5.2 经典 bug 与它的解法

朴素做法会漏消息：

```
1. 客户端拉补齐 → 拿到 (C, H]
2. 客户端订阅
   ← H+1 … M 在这两步之间到达，永远丢了
```

**解法是把订阅与补齐做成服务端的同一个操作、同一条连接上的先后两步：**

- 服务端收到 `stream.auth` 时就**已经注册**了订阅者，记下 `head_seq = H`；
- 但**先不推**，注册之后到达的每一帧都扣在缓冲区里；
- 客户端的 `sync.delta` 返回补齐；
- 补齐响应发出后，服务端才把缓冲里那些**比补齐真正的终点更新**的帧刷出去。

因为 `H` 是在注册那一刻取的，且服务端单点控制顺序，**区间无缝**。
客户端**仍应按 seq 去重**——这是 belt-and-braces，也是重连路径上真正兜底的那层。

上面第三条写的是"比补齐真正的终点更新"而不是"seq > H"，因为 `sync.delta` 只被
`since` 与 `limit` 约束，**不认 `H`**：注册与补齐之间落库的消息会同时出现在补齐结果和
缓冲区里。所以刷出去之前要按补齐实际结束的序号（`next_since`）过一遍，低于等于它的
已经在补齐里给过了。分页的、以及被拒的补齐都算没结束，订阅继续扣着——那是安全的一侧，
§5.3 的上限会终结一个卡在半路的客户端。

**这两段现在是分开测的**，因为它们对时序的要求正好相反（`packages/e2e`）：补齐那段
用 `--once` —— 它补完就返回、不转实时，所以"连上之前就等在库里的消息会被重放"是一条
不需要等、也不需要中断的确定性断言；实时推送那段**不能用 `--once`**（它在转实时之前
就结束了），得注一个 `ListenView` 和一条 `AbortSignal`，先等握手完成、再发、再等它到。
把两件事混在一条用例里，得到的会是一条关于"用例之间谁先跑"的断言。

### 5.3 服务端缓冲有上限

补齐期间到达的实时通知要先缓冲。缓冲有上限，超了就把客户端标记为"落后"，
断开并在客户端重连时走一次新的补齐。**宁可断，不可悄悄丢。**

### 5.4 游标归谁

**v1 放服务端**，按 `(owner_did, device_id)`。理由与 Signal / 微信一致：
服务端知道账号的状态，换一台机器登录 `connectx` 能接着上次读。

`device_id` 默认由本地存储的 `agent/profile` 推出，可用 `--device` 覆盖。
同一个 agent 在两个 profile 下是两台设备，各有各的游标——这与 P5 的 Mailbox
按 `(recipient_did, recipient_device_id)` 分片是同构的。

`--since <seq>` 覆盖服务端游标（排查用）。**本地不存游标**——
存了就变成两处状态，而它们一定会不一致。

### 5.5 实时帧上不带 `seq`

推送的那一帧就是规范的信封（§9），`params` 的键由 P1 定死为 `{meta, auth, body}`，
**多一个 `seq` 就不是规范信封了**。所以实时帧不带序号，而客户端仍然知道每条消息的
序号：

- 注册那一刻服务端报了 `head_seq = H`（`stream.ready`），补齐覆盖 `(C, H]`；
- 补齐之后刷出来的帧必然从 `H+1` 起，且**同一条 WebSocket 上按序到达**；
- 于是客户端从 `H` 起自己数，第 n 条实时帧的序号就是 `H+n`。

`sync.delta` 的每一项**带** `seq`（那是扩展面的结果，不是信封，见
[message-service.md](message-service.md) §9.3），所以补齐这段的序号是服务端给的、
实时那段是客户端数的，两边接在 `H` 上。

这个"数出来"的序号有两个用处：§5.2 的去重（重连后再补齐一遍时，服务端给回的 `seq`
会和客户端已渲染过的高水位撞上，撞上的就丢掉），以及 `--ack` 时 `stream.ack` 带的
那个 `seq`。**服务端缓冲溢出时必须断连**（§5.3），正是为了不让客户端数出来的序号与
真实序号悄悄错位——错位的后果不止重复，还有把一个好端端的游标推错。

`direct.incoming` 这类通知是 Message Service 自己的用法；`group.*` 同理。
§7.1 的 NDJSON 里那条 `seq` 是客户端重建后的值，不是从帧上读的。

## 6. 投递 ≠ 已读

必须分开的三件事：

| | 含义 | 谁决定 |
|---|---|---|
| 落库 | 服务端接受了 | 服务端（`direct.send` 的成功语义到此为止） |
| 送达客户端 | 帧已经发出去 / 客户端已收到 | 服务端 + 连接 |
| **已读** | 有人或某个 agent 处理过了 | **调用方**，靠 `stream.ack` 推进游标 |

推进游标的帧是 `stream.ack {seq}`，走 §4 那条连接（`x_agentx.stream.v1`）。它是
`delivery_cursor` 表**唯一**的写入者：`sync.delta` 不写（补齐归补齐），握手不写。
服务的实现把 `seq` 钳到当前 head 再写——`advanceCursor` 只进不退，一个凭空来的大数
会把游标顶到真实消息前面，下一次重连就静默跳过了。

**`msg listen` 默认不自动 ack。** `--ack` 才开。开的时候每个实时帧发两个调用：
`inbox.mark_read` 写**已读状态**（`msg inbox --include-read` 读的那份），
`stream.ack` 推**交付游标**。两个问题，两张表。

理由是不对称的代价：
- 忘了 ack → 下次重连重放一遍。烦，但**消息还在**。
- 自动 ack 而人没看 → 消息**永久消失**。

默认选那个可恢复的失败。

⚠ 规范明确**不定义已读回执**（P5 §10.7、P6、P8 §35）。所以上面的 `ack` 推进的是
**本服务的交付游标**（扩展面），不是发回给对方的「已读」通知。
真正的已读回执要作为扩展另做，v1 不做。

## 7. CLI 契约

`msg listen` 是 CLI 里**唯一**的常驻进程，所以它的契约要单独定死。

### 7.1 输出

沿用 `anp login` 已经验证过的两套渲染器模式（`login-view.ts`）：

- **TTY**：人类可读的滚动行，像 IM 那样
  ```
  ● alice                    9月30日 14:02
    hello
  ● group:contract-team      9月30日 14:05
    bob: 附件我先传了
  ```
- **非 TTY，或 `--json`**：**NDJSON**，一行一个对象

```jsonc
{"state":"connecting","service":"https://agentx.example/anp-im/rpc"}
{"state":"connected","device":"claude-code/default","head":42}
{"type":"message","seq":43,"message_id":"msg-…","from":"did:wba:…",
 "target_kind":"agent","content_type":"text/plain","text":"hello",
 "accepted_at":"2026-09-30T14:02:11Z"}
{"type":"message","seq":44,"target_kind":"group","group_did":"did:…",
 "from":"did:wba:…","text":"附件我先传了"}
{"state":"reconnecting","attempt":2,"after_ms":4000}
{"state":"error","code":"unauthorized","message":"…"}
```

`state` 取值沿用登录已有的 `connecting` / `connected` / `error`，新增 `reconnecting`。

### 7.2 退出码与信号

| 情况 | 行为 |
|---|---|
| `SIGINT`（Ctrl-C） | 干净退出，**exit 0**。已打印的不回滚 |
| `SIGTERM` | 同上 |
| 连接断开 | 指数退避重连（带 jitter）；期间 `state: reconnecting` |
| 认证失败 | **不重连**，`state: error` + exit 1（重试不会变好） |
| 重连耗尽 | exit 1 |
| `--once` | 补齐完就退，exit 0（等价于 `msg inbox`） |

**`--once` 是这个命令的逃生舱**：它把 `msg listen` 变成一次性命令，
脚本与 CI 用它，就不必碰常驻进程的那套契约。

### 7.3 不做的事

- **不写本地游标**（§5.4）
- **不自动 ack**（§6）
- **不渲染卡片、不要按键确认**——流里的每一条都弹确认是不可用的

## 8. 服务端

在 [message-service.md](message-service.md) 的架构上新增两块，其余不动：

### 8.1 订阅者注册表

```
subscribers: Map<owner_did, Set<{ socket, deviceId, headSeq, pending[] }>>
```

- 键是 `owner_did` 而不是 `(owner_did, device_id)`：序号是账号级的（§5.1），
  所以账号下每一条在看这个信箱的连接都收到同一条通知。
- 一个 `(owner_did, device_id)` 可以有多条连接（同一设备重连、或多开）。
  **允许多条，都推**——客户端去重，服务端不做单连接约束。
- **补齐期的、以及实时期的每一条通知都在这里过。** 补齐期扣进 `pending`，
  `sync.delta` 一答就按它实际的终点刷出去（§5.2）；实时期直接写 socket。
  两处都有上限，超了就断这条连接（§5.3）——**宁可断，不可悄悄丢**。
  上限对实时的连接也不是摆设：那条路用的是 socket 自己的写队列深度，
  客户端不读与客户端不补齐是同一个问题。
- 消息落库并分配 seq 后，查注册表，把通知写到所有匹配的连接。
- 推送发生在**事务提交之后**：事务里推的话，一次回滚就会让在线客户端看到一封
  从未落库的消息。所以受理路径把这次调用产生的投递收集起来，提交后才交给注册表。

### 8.2 连接即状态

连接**不持有**任何必须持久的东西（游标在库里，消息在库里）。
所以进程重启、连接全断，都不丢东西——重连即补齐。
这条让服务端可以无状态地水平重启，是这套设计最值钱的地方。

**出站 `outbox` 仍然要**：它服务的是"规范字面的 push"那条路（§1 的 A），
即推给常驻服务型的 agent 端点。订阅路（B）不需要 outbox，
因为连接断了消息本来就在库里。

## 9. 与规范的关系（别越界）

- 推的帧就是 `direct.incoming` / `group.incoming` / `group.state_changed` /
  `group.e2ee.notice`，payload 约束与 [message-service.md](message-service.md) §8.2 完全一致，
  尤其 **`origin_proof` 必须是原始无损副本，本服务不得重签**。
- **`sync.delta` / `inbox.mark_read` 是扩展面，不是规范能力。**
  它们照旧**不得**出现在 `anp.get_capabilities` 的 `profiles[]` 里。
  但它们**有**自己的 Profile 值（P1 §6.2.2 L277 把 `meta.profile` 定成 MUST，
  且是"本次请求的唯一解释"，所以线上必须有值）：业务方法用
  `x_agentx.inbox.v1`（[message-service.md](message-service.md) §9.1），
  传输握手另用一个 `x_agentx.stream.v1`——两者都是 `x_` 命名空间下的扩展标识，
  与 §13 那条"扩展不进 `profiles[]`"并不冲突：那里说的是**规范符合性**那张清单。
  流端点自己的能力由 `stream.hello` 自报，客户端连上即知。
- **两个扩展 Profile 走同一套目标建模**：`stream.auth` / `stream.ack` 与业务扩展方法
  一样要 `auth.origin_proof`，所以一样 **MUST** 带 `meta.target`
  （P1 附录 A.4 L1068），取值也一样是 `{kind: "agent", did: <本端身份>}`
  （P1 A.4 L1070 把 endpoint-local 方法的建模规则交给 Profile 定）。
  建模与重建规则只写一份，在 [message-service.md](message-service.md) §9.1.1。
- WebSocket 这条传输**不在规范里**。规范只规定 `direct.incoming` 这个 Notification 的存在
  和它的 payload，不规定它走什么传输。所以这是实现自由，但**要按规范的信封发**，
  这样 A 路（POST 到端点）与 B 路（订阅）对客户端是同一种东西。

## 10. 留白：以后可能想要的

记录，不实现。这些都是真 IM 有的，而规范要么不定义、要么明确排除：

| 能力 | 规范态度 | 备注 |
|---|---|---|
| 已读回执（发给对方） | 明确不定义 | 需扩展，且涉及隐私取舍 |
| 在线状态 / 正在输入 | 不定义 | 与 P3 §5.4「MUST NOT 暴露设备状态」相邻，要小心 |
| 消息编辑 / 撤回 | 不定义 | `group.update_*` 是群状态，不是消息 |
| 多端已读同步 | 明确不定义 | 微信那种"手机读了电脑也消失" |
| 移动端厂商推送（APNs / FCM） | 不定义 | 载荷就是 §7.1 那行的精简版 + 游标提示 |
