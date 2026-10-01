# connectx CLI 设计

`packages/cli` —— 本仓库的命令行客户端。二进制名 **`connectx`**（沿用旧仓库的名字）。

---

## 1. 定位

**薄壳。** CLI 只做三件事：解析参数、调用 `packages/core` 的协议原语、按人/机器两种读者呈现结果。
协议逻辑一行都不在 CLI 里。

这条边界来自旧仓库已经定下的判据，本仓库沿用：

> 判据不是"这个能力有没有用"，而是"**有没有一条 CLI 路径会消费它**"。
> 实时 / 长连接 / 持续状态的能力留 SDK 或 agent 运行时，不进命令面。

由此推出的三条硬约束：

1. **命令面宁少勿多**（旧仓库 `TODO2.md` Part D 的判据）：无头可脚本化 + 任务级 + 对 agent 有价值，
   三条全中才开一个命令；没有第二种形态的动作不单开子命令。
2. **`direct.incoming` 推送不进 CLI**。它是服务端到 agent 端点的长连接，属 SDK / agent 运行时。
   CLI 走**拉**（`msg inbox`）。这条与第 4 节的"待定"冲突，见那里的取舍。
3. **CLI 不从缓存里读回 token**。`login` 每次重新签名 + POST 然后覆盖缓存；
   因此**不设 `logout`**——没有一条命令会消费被清掉的缓存。

## 2. 与原 CLI 的差异

| | 原 `@connectx-sdk/cli` | 本仓库 `connectx` |
|---|---|---|
| `did` 族 | create / show / list / register / resolve / update / restore | **原样保留** |
| `anp` 族 | show / login / sign | 保留，**删掉 `--zk*` 全部** |
| `agent` 族 | show / use / list | **原样保留** |
| `project` 族 | init / generate + `templates/` + `generate/` + `template/` | **整族删除**——脚手架不是 ANP 协议 |
| 消息 | 无 | **新增 `msg` / `group` 两族** |
| `version` | 有 | 原样 |

删除 `project` 族顺带删掉 `@clack/prompts` 依赖与 `jiti`（配置加载），CLI 的依赖面回到
`picocolors` + `@noble/*`。

## 3. 命令面

命令面**以数据形式**声明在 `src/help/commands.ts` 一个文件里，`cli.ts` 的解析、help 渲染、
文档门禁、测试全部读它。这是旧仓库验证过的机制：命令的形状**只写一遍**，
help 里写了的旗标就是解析器接受的旗标，反之亦然，两者不可能漂移。**照搬这个文件的结构。**

### 3.1 `did` —— DID server 的对端（不变）

```
connectx did create  [--curve ed25519|secp256k1] [--force]
connectx did show
connectx did list
connectx did register --target <uri> --handle <name> [--rpc]
connectx did resolve <did> --allow-host <host> [--chain]
connectx did update  --target <uri> | --resume
connectx did restore
```

`did` 是**唯一会写 DID 文档**的地方。`connectx` 在这里是 `awiki-open-server` 的客户端。

### 3.2 `anp` —— ANP server 的对端（去 ZK）

```
connectx anp show
connectx anp login --target <uri>
connectx anp sign  --target <uri> [--method <verb>]
```

`anp login` 打的是**站点**的 verify endpoint（应用服务端，如 `agent-on`），**不是**消息服务。
它与 3.3 的区别是这条线上认的是"站点签发的 token"，不是"消息投递"。

`--wallet web3` 三个旗标（`--provider` / `--address` / `--chain-id`）在这里**原样保留**——
这是 CAIP-10 的入口，见第 4 节。

### 3.3 `msg` —— ANPMessageService 的对端（新增）

```
connectx msg send --to <did> (--text <s> | --body <json>) [--content-type <type>]
connectx msg caps <did>
connectx msg inbox [--since <cursor>]              # 扩展面
connectx msg show <message_id>                     # 扩展面
connectx msg read <message_id> | --all             # 扩展面
```

**`msg send` 是本仓库最重要的一条命令。** 它一条命令走完规范要求的全部步骤：

1. 解析收件人 DID → DID 文档 → 取**唯一** `ANPMessageService` 条目
   （`serviceEndpoint` + `serviceDid` + `profiles[]`）。这一步是规范的发现流程，不是可选优化。
2. 构造 `direct.send`：`meta` 必选字段（`profile` / `security_profile` / `sender_did` /
   `target.kind="agent"` / `target.did` / `operation_id` / `message_id` / `content_type`）
   + `body`（`text` / `payload` / `payload_b64u` **恰好一个**）。
3. 构造 Signed Request Object `{method, meta, body}`（**不含** `jsonrpc` / `id` / `auth`），
   RFC 8785 JCS 规范化后做 RFC 9421 签名，`scheme` 固定 `anp-rfc9421-origin-proof-v1`，
   组件集合固定 `("@method" "@target-uri" "content-digest")`，
   `@target-uri` = `anp://agent/<pct-encoded did>`。
4. POST 到 `serviceEndpoint`，按 JSON-RPC 响应报成功 / 错误。

**`operation_id` 由调用方给，不给就生成一个随机值。** 幂等键是
`(sender_did, target.did, method, operation_id)`；`--operation-id` 旗标存在的唯一理由
是**重试**——重发同一条消息必须复用同一个 `operation_id`，否则服务端会当成两条。
这正好落在"无头可脚本化"的判据上，所以它进命令面。

**`msg caps`** 打 `anp.get_capabilities`，打印对方支持的 `profiles[]` / `securityProfiles[]`。
它在命令面上的价值是"发之前先问一句"，也是排查 `anp.unsupported_profile` 的唯一手段。

**`msg inbox` / `show` / `read` 是扩展面**，见第 5 节——规范**没有**定义它们。

### 3.4 `group` —— 群组（新增）

```
connectx group create [--name <s>]
connectx group info    <group_did>
connectx group members <group_did>
connectx group join    <group_did>
connectx group leave   <group_did>
connectx group send    <group_did> (--text <s> | --body <json>)
```

群组**单开一族而不是挂进 `msg`**：它的定址对象不同（群有自己的 `group_did` 和自己的 host），
发的是 `group.send` 而不是 `direct.send`，这与旧仓库"按对端分族"的惯例一致
（`did` 与 `anp` 同属身份却也分了两族，理由相同）。

### 3.5 `agent` / `version`（不变）

```
connectx agent show | use <id> | list
connectx version
```

`agent` 归在 `did` 族下（它读写身份存储，回答"我现在以谁的身份行动"）。

## 4. CAIP-10 接入

CAIP-10 是**第三种密钥绑定机制**（提案 `anp.identity.caip10.v1`）：身份是 `eip155:1:0x…`
这样的链上账户 id，密钥绑定靠**地址由公钥派生**（`derive(pk) == account_address`），
而不是靠标识符里的指纹（`did:wba`）或域 + TLS（`did:web`）。

**它只在认证路径上生效，不改变命令面的形状**——所以实现方式是既有的三个旗标：

```
connectx anp login --wallet web3 --provider <module> --address 0x… --chain-id eip155:1 \
                   --target https://site/api/login/anp/verify
```

设计上要守住的几条（均出自提案正文）：

- **`keyid` 不是 DID URL**，这是提案唯一一处偏离 ANP-02（§12）。`anp sign` 的输出里
  会看到这个差别，**不要当 bug 改回**。
- **限 EOA**。地址由密钥派生的账户才行；合约账户（ERC-4337 / Safe）明确排除（§5.3），
  且这是**安全边界**不是便利性限制。
- **不做网络解析**。CAIP-10 账户 id 是不透明标识符，**MUST NOT** 尝试解析它，
  **MUST NOT** 类比 `did:wba` 的 `/.well-known/did.json` 去拼一个 URL（§4.3）。
  DID 文档**内联在已认证的请求里**。
- **必须先做地址派生校验，再用那把钥验签**，不等则拒（§5.1）。
- **无更新链**：地址承诺密钥，换钥即换账户；**MUST NOT** 为它合成
  `successorDid` / assurance 连续性（§8）。所以 `did update` 对它不适用。
- **规范化**：`eip155` 命名空间的规则是 `<十进制 chain id>` + 小写地址；
  非规范拼法**必须**被拒为 `invalid_did`（§4.2），否则同一账户有两个标识符，
  会打穿重放缓存的键。

### ⚠ 待定：CAIP-10 身份能不能当消息的收发地址？

**结论倾向：不能，至少 v1 不做。**

理由：提案自述适用范围是"agent 与 relying party 之间的**请求认证**"（提案 L11），
不是消息定址。而 `direct.send` 的投递模型要求**收件人方**能从发送方的 `sender_did`
解析出对方的入口服务才能回信；CAIP-10 账户 id **不可解析**（§4.3 明令禁止解析），
于是纯钱包身份的 agent 有 `sender_did` 但没有 ingress。

三个可选出路，v1 建议都不做，只记在这里：

- (a) 消息 `meta` 里加 `x_reply_to` 扩展字段——但 P1 §12.1 规定未知核心 `meta` 字段
  **MUST** 拒绝，只有 `x_` 前缀 MAY 忽略，所以这必须是一个**双方都认的扩展**，不是随便加的。
- (b) 钱包身份另配一个 DID 做消息地址（两个身份，认证用 CAIP-10，收发用 DID）。
- (c) `AgentXAgent` 兼做 DID 托管——与"DID service 是 `awiki-open-server`"的分工冲突，不建议。

**v1 的取舍**：`msg` / `group` 族**只接受 DID**；`--wallet web3` 在 `msg` 族上直接拒绝，
错误码 `caip10_has_no_ingress`，消息里写清原因并指向 (b)。用户若要用钱包身份收发，
走 (b)。

## 5. 扩展面：规范没有定义的那一半

规范在消息的**取件侧是空白的**，这是刻意的：

- P3 §1 明确**排除**历史拉取、已读状态、agent 内部同步；
- P5 §10.7 / P6 同样明确不定义历史拉取、已读回执、设备同步；
- P8 §35 也排除。

**规范里不存在 `inbox.get`。** 已全文 grep 核实。`inbox.*` / `sync.*` / `read_state.*`
是 `awiki-open-server` 自己的扩展（`MESSAGE_HANDLERS`，`messaging/core.py:2188`）。

`AgentXAgent` 也必须提供这一半，否则消息只能发不能取。**设计选择：沿用同一套方法名**，
不另起一套——

```
direct.get_history
inbox.get
inbox.mark_read
read_state.mark_read
sync.bootstrap / sync.delta / sync.thread_after
message.get_batch
```

这样 `connectx` 的 `msg inbox` / `show` / `read` **对 `awiki-open-server` 和 `AgentXAgent`
都能用**。自造命名只会让客户端多一套兼容分支，换不来任何东西。

⚠ 由此产生的一条纪律：`msg inbox` 等命令在**对端不支持该扩展**时，必须报
`unsupported_extension` 并说明"这是实现扩展，规范未定义"，**不能**把它当成规范能力宣传。

## 6. 不做的事（明确记录）

| 不做 | 理由 |
|---|---|
| `msg listen`（订阅 `direct.incoming`） | 长连接，属 SDK / agent 运行时。**见下方取舍** |
| `connectx logout` | 没有一条命令会消费被清掉的缓存 |
| `project init` / `project generate` | 脚手架，不是 ANP 协议 |
| `--zk*` 全部 | 用户裁定不要 ZK |
| `msg send --wallet web3` | 见第 4 节待定项 |
| 本地 bearer token 那条路 | 规范里它只是**可选优化**，且 **MUST NOT** 替代 `origin_proof`（P3 §9.5）。CLI **始终**签名，于是对任何符合规范的服务都能用 |

### ⚠ 待定：`msg listen` 要不要进命令面

第 1 节刚说"长连接不进 CLI"，但一个不能收消息的消息客户端是半个客户端。
这正是那条判据第一次遇到反例。

两种处理，**建议先按 A 做，等真有需求再改**：

- **A（建议）**：v1 不做。CLI 只拉（`msg inbox`），推送留给 SDK。
  agent 的运行循环里，收消息本来就是长驻进程的活，CLI 每次调用都是新进程。
- **B**：加 `msg listen`，输出 NDJSON 一行一条，复用 `anp login` 已有的
  "终端给卡片 / 管道给状态流"两套渲染器（`login-view.ts`）。Ctrl-C 退出，退出码 0。

选 B 的代价不是实现，而是**它把 CLI 从"一次性命令"变成"常驻进程"**，
之后 `--json` / 退出码 / 信号处理的契约都要按常驻进程重新定一遍。
旧仓库的判据是在有反例之前定的，反例成立时应该改判据——但改判据要有真实需求撑着。

## 7. 输出与退出码契约

沿用旧仓库已定的形状，不新造：

- **人读**：默认输出，一屏之内讲清"发生了什么"。
- **机读**：`--json`，一个 JSON 对象，或 NDJSON 状态流（长流程用）。
- **退出码**：`0` 成功；`1` 失败；`did resolve` 另用 `2`（DID 已被取代，是**结论**不是失败）
  与 `3`（更新链验不过，`did_chain_broken`）。消息族沿用 `0` / `1`。
- **错误行**：`connectx: <code>: <message>`，`code` 是 SDK 的错误码，
  让脚本不解析 `--json` 也能分支。

## 8. 存储

沿用旧仓库的布局，**不改**：

```
~/.connectx/
  <agent>/<profile>/
    identity.json       # 已注册的 DID + host + handle
    key.json            # keystore V3，静态加密
    key.next            # did update 暂存的继任钥
    session.json        # token 缓存（CLI 从不读回，见 §1.3）
  current-agent         # agent use 写的当前 agent
```

隔离粒度是 **agent 级**：同一 agent 跨项目用同一个 DID；每个 agent 一把独立随机密钥
（不共享助记词、不互相派生）；默认**不自动建号**。

`msg` 族**不新增存储**——它不缓存在途消息。要本地留痕就 `--json` 重定向到文件，
CLI 不替调用方决定。

## 9. 与 core 的边界

CLI **只** import `packages/core` 的公开面（`core/index.ts` 的具名导出）。
现在 CLI 用到的大约是：

```
createConfig, selectWallet, anpCli, keypairWallet
signRequest, login, register, update, registerViaJsonRpc
parseKeystore, subjectOf, ConnectxError, isConnectxError,
resolveDidChain, resolveDidDocument, isSuperseded, didToUrl
```

消息族要新增的核心面在 `core/message/`（见 [vendored-core.md](vendored-core.md) §4）：
`buildMessageEnvelope` / `signMessage` / `discoverMessageService` / `verifyMessage`。

**CLI 不得自己拼 JSON-RPC 信封或自己做 JCS 规范化。** 这两件事一旦在 CLI 里出现第二份，
`msg send` 与服务端的验签就会以最难查的方式不一致。
