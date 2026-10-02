# TODO5 —— 客户端换成 Rust（第五轮台账）

接 [TODO4.md](TODO4.md)。2026-10-02 提出一个**大手术**：客户端整体用 Rust 重写，起名
**`agentx-cli`**；**服务端保留**（继续 TS，并把它做好）；**TS 版 CLI 原地不动**，与新的 Rust
客户端并存。动机是让客户端**直接用 Rust 原生的 MLS**，省掉
[client-mls.md](docs/design/client-mls.md)（TODO4 §B2）里那层 napi 绑定。

本文件给可行性结论、落分阶段计划、列**要你定的点**（§7），并单开一节写**你没提到、但绕不开的
问题**（§8）。口径与 TODO1–4 一致。

**做到哪了，看 §6 开头的「进度总表」一处**——`~~划掉~~` 就是做完的，`- [x]` 同理；下面的正文
一律保留原样（那是当时的判断，不是现在的状态）。

---

## 0. 本轮锁定的决定

1. **命令行与服务是两个分开的东西。** 服务端 `packages/service` 保留，继续 TS，继续做好。
2. **客户端全量 Rust 化，不做 strangler。** 这是"真动"，一次到位。
3. **新客户端叫 `agentx-cli`**（不叫 `connectx`）。
4. **TS 版 CLI 原地不动**——`packages/cli` 保留、不删、不改，与新客户端并存。
5. **Rust 客户端按最新的官方 `anp` crate 写。** pin **1.0.5**（2026-09-24，crates.io）；
   本机检出停在 0.9.0、落后 origin/master 93 个提交，**可以更新**（§9 第 1 条）。
6. **新增一块此前没想过的：客户端自己的消息存储。** 见 §4——这是本轮浮出来的第二主题。

### 0.1 待定项的裁定（2026-10-02）

| # | 问题 | 裁定 |
|---|---|---|
| 1 | `agentx-cli` 与 `CONNECTX_HOME` | **分开**。新客户端有自己的 store 根与环境变量前缀，**不共用** TS 那份身份 → 两台不同的设备，§8-A 的 listener 互抢问题**不会发生**。 |
| 2 | 消息库明文策略 | **本地留明文**。理由见下——服务端会清理，不能当永久记录。**按对话分别存储，存储方式要设计**（§4）。 |
| 3 | 消息库是不是记录之源 | **是。本地存储就是记录之源。** 服务端降级为传输/中转（§8-C / §8-D）。 |
| 4 | `anp` pin | **1.0.5**；本机检出**更新**到最新后重核签名。 |
| 5 | TS CLI 的终局 | **冻结，不再更新**。它的验收线就是**明文的群聊跑得通**（今天 P4 已经是这样）；E2EE 群由新客户端负责。 |
| 6 | e2e 形态 | **没有历史包袱**——不纠结形态，直接把功能实现出来。新客户端自己的端到端随功能一起落。 |
| 7 | 客户端的 DID 文档挂哪 | **挂本机已有的 `awiki-open-server`**，不自己写 DID host 桩（§8-J）。这是"真实部署挂真 host"那条路，只是 host 在本机。 |

**第 2 条的依据（用户原话加以复述）**：服务端的消息**会被定期清理**，不能保证永远在。所以本地
客户端**必须**存下来，且按对话组织。**核对仓库现状**：今天服务端只有 **P6 设备队列**有 24 小时的
有界保留（`AGENTX_DEVICE_QUEUE_MAX_AGE_MS`），`deliveries` 表**还没有**清理任务——也就是说
"服务端会清理"要么是既定的演进方向、要么是要补的动作。**无论哪种，"服务端不是永久记录"这个
设计前提都成立**，本地库按记录之源来定（§4）。

---

## 1. 现状（量出来的）

| | 位置 | 规模 |
|---|---|---|
| TS 客户端 | `packages/cli`（**保留**） | **7336** 行 src + 3539 行测试 |
| 协议原语 | `packages/core` | **11500** 行 src，**cli 与 service 共用**（service 侧 70 处引用） |
| 官方 Rust SDK | crate `anp` | 本机检出 0.9.0 = **26653** 行；crates.io 最新 **1.0.5** |

命令面 6 族 24 条（[cli.md](docs/design/cli.md) 判据：**协议逻辑一行都不在 CLI 里**）：

- `did` create / show / list / register / resolve / update / restore
- `anp` show / login / sign
- `msg` send / caps / inbox / show / read / listen
- `group` create / info / members / join / leave / send
- `agent` show / use / list
- `version`

**`packages/core` 搬不动。** 它是 cli 与 service 的公共依赖，服务端还要用。所以 Rust 客户端
要**自己有一份客户端子集的实现**——不是把 core 移过去，是按需再写一遍。这是本台账最贵的一笔，
也是"翻译"与"移植"的分界。

---

## 2. crate 已经有的 / 明说不做的

**已经有**（`authentication` / `proof` / `group_e2ee` / `direct_e2ee` / `wns`）：

- `did:wba` 文档**创建 / 解析 / 校验**，`did:web` 与 `did:wba` 的 **HTTP 解析**（`network`
  feature 自带 `reqwest`）；
- 客户端侧 **HTTP 签名与 auth header 生成**（`generate_auth_header`、
  `generate_http_signature_headers`、`DIDWbaAuthHeader`）；
- `object_proof` / `did_wba_binding` / `group_receipt` / `rfc9421_origin` 四套 proof；
- **设备清单的读与写**（`add_device_to_did_document`、`build_vnext_did_document`、
  `find_eligible_device`）——本仓库今天**只有读**（[devices.ts](packages/core/src/message/devices.ts)），
  这一条是白捡的；
- **`group_e2ee` 的 MLS**（openmls 0.8.0）与 **`direct_e2ee`**；WNS；`keys`。

**明说不做**（crate README 原文）：不提供 **high-level base-message senders**——
`direct.send` / `group.send` 的构造"是应用层自己的事"。且 crates.io 元数据显示 **`bin_names: []`**，
官方仓库里**一个 Rust CLI 都没有**（无 `main.rs`、无 `clap`）。可参照的是**官方 Python SDK**
（`ANPClient` / `ANPCrawler`）——那是"一个客户端该长什么样"的现成答案。
**在 1.0.5 源码上核过更确切的位置**：crate 能造出并校验"签好名的请求对象"，但**不发出它**；
`reqwest` 只用于 DID 解析，本服务的扩展面（`x_agentx` / `inbox.*` / `deliveries` / `sync.delta`）
crate 里没有。所以补的这层是**传输**，见 §6 Phase 0 结果第 4 条。

---

## 3. 要在 Rust 里新写的（移植面）

**每条带一个状态签**（2026-10-02）：`[已落]` / `[部分]` / `[未动]`。

1. **[部分]** **CLI 参数 / 帮助 / 渲染**（~1600 行）：1193 行的命令表 + 渲染层。机械，但量在那儿。
   已落骨架与 `did`（3 条）/`msg`（6 条）/`group`（6 条 + `e2ee` 3 条）/`discover` 的面；
   `anp` / `agent` / `version` 未动。
2. **[部分]** **身份存储**（~1200 行）：含 **Ethereum keystore V3**（scrypt + aes-128-ctr + keccak256）与
   **EIP-1193 web3 钱包路径**——`--wallet web3` 是 CLI 的一等路径。
   已落的是**自定格式**那一半（§0.1 第 1 条把两个客户端分开了），keystore V3 / web3 未动。
3. **[部分]** **core 的客户端子集**（估 ~4000–5000 行）：`message/`（envelope / rpc / discovery / locator /
   verify / objectProof）、`connectors/`、`crypto/agentDescription`、`crypto/serverAuth`、
   `actions`（register / update）、`did/chain`。**crate 把这层留给应用，正是要在这里补的。**
   已落 `message/` 那条主线（信封 / 那一跳 / 发现 / 解析 / 验文档 / 流），其余未动。
   **调整（2026-10-02）**：crate 自带**客户端的 origin proof 构造**
   （`proof/rfc9421_origin.rs` 的 `build_signed_request_object` / `build_logical_target_uri` /
   `generate_rfc9421_origin_proof`），所以 auth 那一段不用移植——估量往下调。
   **已核到字节（同日）**，这条不再是估计：覆盖组件集合三份实现**完全一致**
   （core `ORIGIN_PROOF_COMPONENTS`、crate `RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS`、
   awiki 的 Python 参考客户端都是 `("@method" "@target-uri" "content-digest")`，
   `anp://` 前缀、RFC 3986 unreserved 百分号编码也一致）。**四组件那套
   （`@method @target-uri @authority content-digest`）是 ANP-02 登录签名，不是本 Profile**，
   别搬。参数集：`created` 由签发方写上、`expires` 可选、`nonce` 可选（服务端有则兑、
   没兑就不判，`dispatch.ts` 的 `consumeProofNonce`）。crate 的
   `build_im_signature_input` 总是补 `created` 和一个随机 `nonce`——**多出来的 nonce 不违例**，
   它进 `@signature-params` 那一行，签名自洽。结论：**`generate_rfc9421_origin_proof` 原样可用。**
4. **[部分]** **SSRF / 逐跳网络策略**（`core/crypto/resolveDid.ts` 的 `fetchControlledJson` 一族）。
   `message/rpc.ts` 用它，理由是"消息端点的**主机由对端选定**"——所以这一跳比 DID 文档那一跳
   **更需要**它。**已落（2026-10-02）**：策略被放进 `post_message` / `post_notification`
   内部（不是调用方传参才生效），所以**没有一条消息 POST 能绕过它**——`caller` 拿不到一个
   "不检查"的路。文档那一跳（`resolve.rs`）本来就在。**仍缺的一半是 DNS**：TS 还会把*主机名*
   解析成地址、拒绝私网地址（`resolveHostAddresses`），这条要一个 Rust 侧不带的解析器，
   所以只保留**字面 IP** 的判断（与 TS 在没有 `node:dns` 时的回退同形）。见
   [`assert_allowed_host`](rust/crates/agentx-cli/src/message/resolve.rs) 的函数注释。
5. **[部分]** **命令逻辑**（~1500 行）：`group` / `msg` / `listen`（含 `msg listen` 这条唯一的常驻契约，
   [realtime.md](docs/design/realtime.md)）。三族都已落；`group e2ee` 六条方法全落，只剩收包
   路径未做。
6. **[部分]** **[client-mls.md](docs/design/client-mls.md) 的 store 与编排**：落
   **`<新 store 根>/<agent>/<profile>/mls/`**（**不是** `CONNECTX_HOME`——§0.1 第 1 条把两个
   客户端的 store 根分开了）；owner 编排（§11.12）从 CLI 挪进 Rust 客户端。
   store 已落且真的在跑（`publish` / `get-key-package` / `create` / `add` / `remove` / `send`）；owner 编排的后半未动。
7. **[未动]** **客户端消息存储（新，§4）。**

**被省掉的东西**：走这条路，B2 的 **napi 壳整条取消**——不是"要写两次"，是"换一种方式拿 MLS"。
这是手术的收益。

---

## 4. 客户端消息存储（本轮新浮出来的第二主题）

**用户的话**："CLI 接收到了消息，我应该有一个客户端去存储它。这个我之前都没有想到过，但现在
觉得它也很重要。"

**先纠正一个容易跑偏的前提**：消息今天**不是没人存**——它存在**服务端**。本服务的
`deliveries` 表是一条**每 (owner, device) 单调递增游标**的收件箱，`msg listen` 用
`sync.delta` 按游标补拉、`msg inbox` 用 `inbox.get` 分页翻（`inbox.get` / `mark_read` 是
本服务的**扩展面** `x_agentx.inbox.v1`，**规范里根本没有**——[message-service.md](docs/design/message-service.md) §9）。
**TS CLI 自己一行消息都不存**，它是无状态的，每次去问服务端。

所以真正要问的不是"要不要存"，是**"本地存下来，比服务端那份多解决什么"**：

- **E2EE 的明文。** P6 服务端**不落明文**（[e2ee-group.md](docs/design/e2ee-group.md) §12.6）。要
  显示群历史，客户端得在本地留**明文**（或留能解出明文的 MLS 状态）。
- **记录之源。** 一个身份的聊天历史今天**只活在托管它的那台服务**上；服务没了，历史就没了。
  本地库让它变成客户端自己的资产。
- **聚合与离线。** 一个身份可能在多台服务上有群（群在自己域的、别人域的），`msg inbox` 今天
  只够到"我自己的"服务。本地库是所有会话汇到一处的地方。
- **读状态与断点。** read/unread、以及"处理到服务端 seq X"的本地游标，能在本地自洽。

**形状（2026-10-02 已定方向；具体设计在动手时落）**：

1. **范围**：只存"投递给本设备的"，还是也存"我发出的"？聊天客户端两个都要。
2. **内容与加密**：**留明文**（§0.1 第 2 条）。留明文 = 新的一件**密钥资产**，直接撞上
   TODO4 §E 那条规矩（"数据库文件、它的备份、任何'发过来看看'的调试，都按密钥对待"）；备份、
   调试、分享的行为要跟着立规矩。另：**加入之前的群历史永远解不开**（MLS 前向保密），
   要向用户讲清"本地库不是完整历史"。
3. **按对话组织**：一个身份下按**会话**（对端 DID / 群 DID）分开存，各自一条消息序。
   **存储方式要设计**——这是 §0.1 第 2 条点名的待设计项。
4. **权威**：**本地库是记录之源**（§0.1 第 3 条）。服务端 `deliveries` 降级为传输/中转，
   要有 ack / 清理契约；read 状态归本地。
5. **位置**：`<新 store 根>/<agent>/<profile>/messages.db`，与 `mls/` 同级
   （[client-mls.md](docs/design/client-mls.md) §4 同一条"一个身份的状态放哪"）。**注意 store 根
   与 TS 是分开的**（§0.1 第 1 条）。
6. **游标**：本地要有"已处理到服务端 seq X"的游标，才能断点续传、不重不漏。
7. **归谁**：按 [cli.md](docs/design/cli.md) §1 的判据，**持续状态的能力留 SDK / agent 运行时、
   不进命令面**——所以消息库要落在 **Rust 客户端库**里，命令面只做 `msg inbox` / `msg listen`
   的读出口，不是 `msg` 命令自己拿个文件写。

**注意这条与 §8-D 是一体两面**：本地库一旦成为记录之源，**服务端就得配合**（ack、保留期、
补拉接口），这正是"把 message service 做好"的落点。

---

## 5. 三笔要认的账

1. **双语言、双客户端。** TS service + Rust client 并存，**外加 TS 客户端也还在**（§0 第 4 条）。
   三个东西同时活着，同一个身份可能被两个客户端指向（见 §8-A）。
2. **core 分裂。** 服务端继续用 TS core，于是同一批协议原语存在两份（TS + Rust），两份都要跟
   ANP 演进走，长期漂移是真实风险。
3. ~~**盘上格式变成 ABI。**~~ **已作废**（§0.1 第 1 条）。原以为 TS CLI 不动、两个客户端要共享
   身份，所以 Rust 侧必须逐字节兼容 keystore / `identity.json` / session / `paths` 布局。
   **store 根一分开（§8-F），两个客户端就不共用盘了**，这条约束不成立——Rust 侧自定格式、
   自己拥有；只有"把旧身份搬过来"才需要一次性的导入（§8-E）。
4. **发布面变了。** `agentx-cli` 是**按平台发的原生二进制**（交叉编译矩阵、签名、升级）；
   keystore 的 scrypt/keccak、web3 的 EIP-1193 在 Rust 里要各自找库。

---

## 6. 分阶段计划（全量）

### 进度总表（2026-10-02）

`~~划掉~~`＝做完；`- [ ]`＝还没动。命令面的实际清单是 `agentx-cli --help`，这张表只记状态。

| 家族 | 命令 | 状态 |
| --- | --- | --- |
| `did` | `create` / `show` / `register` | ~~做完~~（对 awiki host 真跑通） |
| `did` | `resolve` / `update` / `restore` | 还没 |
| — | `discover` | ~~做完~~ |
| `msg` | `send` / `caps` / `inbox` / `show` / `read` | ~~做完~~（`send` 真阳性；`inbox` 一族对 awiki 为负是**正确**结果） |
| `msg` | `listen` | ~~做完~~（realtime.md 那条常驻契约） |
| `group`（P4） | `create` / `info` / `members` / `join` / `leave` / `send` | ~~做完~~（真阳性只对本仓 `packages/service`） |
| `group e2ee` | `publish` / `get-key-package` | ~~做完~~（对真服务跑通） |
| `group e2ee` | `create` | ~~做完~~（对真服务跑通） |
| `group e2ee` | `add` | ~~做完~~（对真服务跑通；群寻址，commit/welcome 进设备队列） |
| `group e2ee` | `remove` | ~~做完~~（对真服务跑通；群寻址，目标 leaf 转 terminal） |
| `group e2ee` | `send` | ~~做完~~（对真服务跑通；群寻址，收件进设备队列，只推 `group_event_seq`） |
| `group e2ee` | 收包路径（`process_notice_v2` / `decrypt_received_v2`） | ~~做完~~（`msg listen` 投递驱动，对真服务跑通 commit/welcome/final-notice 与 `group.incoming`） |
| `anp` | `show` / `login` / `sign` | 还没 |
| `agent` | `show` / `use` / `list` | 还没 |
| — | `version` | 还没 |
| 身份 | 换钥 / 换设备 / `update_document` | 还没 |
| 库侧 | 信封 / 那一跳 HTTP / SSRF 逐跳 / 身份存储 / MLS store | ~~做完~~ |
| 库侧 | 消息库 `messages.db`（§4、Phase 2） | 还没 |
| 收束 | Phase 4：`packages/e2e` 覆盖新客户端 / 命令面定稿 / TS CLI 冻结 | 还没 |

**Phase 0 —— 先证那条缝（spike，不进仓库）** —— [x] ~~已做完（2026-10-02）~~
最小 Rust 客户端：读本机 keystore 的身份 → 用 crate 的 `did_wba` / `http_signatures` →
对**真服务**发一条 `group.e2ee.*`，看能不能过服务端的方法表与资格门禁。不做 CLI、不做 e2e。
只回答一个问题：**1.0.5 的客户端能力，够不够接上服务端那 571 行。**

**结果（2026-10-02，spike 在 [`rust/crates/agentx-cli/src/main.rs`](rust/crates/agentx-cli/src/main.rs)）：
够，但缺口的位置和原先写的不同。**

1. **crate 那一侧是通的。** spike 用 `create_did_wba_document` 造身份、写出带 `deviceManifest`
   的 DID 文档、开 `ImCoreSqliteGroupMlsStore`、跑 `generate_key_package_v2`，产出一个**真的**
   `V2GroupKeyPackage`（`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`，`mls_key_package_b64u`
   1167 字节）。这不是"函数签名对得上"——是 crate 把整条设备侧验证跑完才吐出来的。
2. **产出与服务的形状判据逐字段吻合。** 拿产出对着
   [`groupE2ee.ts`](packages/service/src/rpc/groupE2ee.ts) 的 `keyPackageShapeProblem`
   （L191–223）核过：`KEY_PACKAGE_FIELDS` 五项、`BINDING_FIELDS` 六项、`proof` 是对象、
   `owner_did === binding.agent_did`、`owner_device_id === binding.device_id`，**全中**。
   这份 KeyPackage **原样就能发** `group.e2ee.publish_key_package`。
3. **两个坑，都已确认不是坑。**（a）P6 的设备条目**必须带整条依赖闭包**
   （`anp.core.binding.v1` + `anp.identity.discovery.v1` + `anp.group.base.v2` +
   `anp.group.e2ee.v2`），只写 `group.e2ee.v2` 会被 `require_dependencies` 拒掉——这是
   crate 在**替服务端**先把 §6.4 那道关，对上了。（b）`did_wba_binding` 必须由 `key-1`
   （Ed25519 身份钥）签；文档里 `key-2` 是 Secp256r1、`key-3` 是 X25519，**都验不了** MLS 的
   Ed25519 绑定。
4. **缺口的真实位置：不在 MLS，在那一跳 HTTP。** 在 1.0.5 源码里核过——`reqwest` 只被
   **DID 解析**用（`did_wba` / `did_web` / `wns/resolver`）；`direct.send` 只出现在
   **构造/校验请求对象**的那几处（`direct_e2ee/envelope.rs`、`v2_wire.rs`、`proof/`）；
   而 `x_agentx`、`inbox.*`、`deliveries`、`sync.delta`、`group.send` 在 crate 里**一个字都没有**。
   也就是说 **crate 停在"签好名的请求对象"那里，不负责把它发出去**，更不知道本服务的扩展面。
   这比 §2 那句"不提供 high-level base-message senders"更具体：**要新写的是传输层**——
   reqwest + 本服务的 JSON-RPC 信封 + `x_agentx.inbox.v1`（§4 里那条 `inbox.get` / `mark_read`
   的扩展面）。这本来就是客户端库的活，所以不构成阻塞，但它是 §3 第 3 条里的**大头**。
5. **还没做的那半步**：真正连一台跑起来的服务打一发。它需要的正是第 4 条那个传输层，
   所以**并进 Phase 1**，不留在 spike 里——spike 已经把它该回答的回答完了。

**Phase 1 —— `agentx-cli` 骨架 + 身份 + 一个族**
- [x] ~~Rust workspace 新建（顶层 `rust/` 或 cargo workspace 成员），arg 解析（clap）、帮助/渲染、
  身份读取（**自定盘上格式**，独立 store 根；**不需要**与 TS 逐字节兼容，见 §8-E）、
  core 客户端子集里 `msg` 必需的那部分。~~ **已落**（2026-10-02）。
- [x] ~~**第二件事是传输层**（Phase 0 结果第 4 条）：reqwest + 本服务的 JSON-RPC 信封 + HTTP 签名
  （crate 的 `generate_auth_header` / `did_wba`）+ `x_agentx` 扩展面。没有它，`msg` 一族一行都
  跑不起来；有了它，Phase 0 剩下的"真打一发"顺手就做了。~~ **已落**（2026-10-02）。

**Phase 1 进展（2026-10-02）**

- **骨架已立**：`rust/crates/agentx-cli` 现在是 `lib`（`agentx`）+ `bin`（`agentx-cli`）。
  spike 挪到 `examples/phase0_key_package.rs`，仍可复跑（`cargo run --example phase0_key_package`），
  但它**不是** CLI 的一部分。
- **传输层已落，并且真的打通了**：`src/message/envelope.rs`（出站信封装配，
  `core/message/envelope.ts` 的移植）与 `src/message/rpc.rs`（那一跳 HTTP，
  `core/message/rpc.ts` 的移植），13 个单测。**`agentx-cli discover <endpoint>` 对着真服务
  跑通了**——`anp.get_capabilities` 是唯一不需要 auth 的方法（P1 §8.2），所以它不需要身份，
  也就成了最省的"端点活着吗、说的是这个协议吗"检查。这一步同时回答完 Phase 0 剩下的那半步。
- **顺带核对**：服务端回的 `supported_profiles` 里有 `anp.group.base.v2`、**没有**
  `anp.group.e2ee.v2`——与 §6 的广告闸门（`WITHHELD_PROFILES`，TODO4 §B1）一致，符合预期。
- **交易面比 §3 第 3 条估的小**：`proof/rfc9421_origin.rs` 里 crate **自带客户端的
  origin proof 构造**（`build_signed_request_object` / `build_logical_target_uri` /
  `generate_rfc9421_origin_proof`），所以 auth 那块不用自己写。§3 第 3 条那 4000–5000 行的
  估计要往下调——真正要自己写的是**信封装配 + 那一跳 HTTP + 身份存储 + 命令逻辑**。
- **诚实记一笔缺口**：`rpc.rs` **还没**移植 `resolveDid.ts` 的 SSRF 逐跳策略。
  消息端点是从对端 DID 文档里读出来的（主机由对端选定），那一层在这一跳**更需要**，不是更
  不需要。移之前在 `post_message` 的文档注释里标了，也在 §3 立了账。
- **身份已发布（2026-10-02 跑通，本机 awiki host :8765）**：`identity/` 三件
  （`store.rs` 盘上格式 + 0600、`did.rs` 造文档、`host.rs` 读 host 文档并 `register`）+
  `agentx-cli did create|show|register`。**文档形状**：根 `#key-1`（Multikey Ed25519）+
  设备签名钥 + 设备协商钥（都是这条身份自己生成的，见 §8-J 第二个坑），关系集
  `authentication`/`assertionMethod` = {root, signing}、`keyAgreement` = {agreement}，
  manifest 宣告 P6 整条依赖闭包。**双向核过**：
  （a）awiki 的 `register` 收下了（它的 `_e1_document_binding_valid` 用 §2.5.5 的
  base58 验签器，通过）；
  （b）**本服务自己的解析路径**——`DidDeviceResolver` → `resolveDidDocument`
  （含 `verifyDidDocument` 验文档 proof，即重建后的文档 + base58 `proofValue` 真的验得过）
  → `checkDevice` 判 P6 合格：四项 profile 齐、`signing_key_id` 落 `assertionMethod`、
  `e2ee_key_id` 落 `keyAgreement`，全过。（这条用一次性 vitest 跑，验完即删，没有留进套件。）
- **`msg` 一族已落，并对真服务跑通（2026-10-02）。**
  `message/channel.rs`（`channel.ts` 的移植：`Sender` / `Endpoint` / `Channel`、
  `call` / `call_extension`、`payload_of`、协商与拒绝的映射）加上 `message/client.rs`
  （唯一那个**关掉重定向**的 HTTP client，理由写在其文件头）。命令面 `msg send | caps |
  inbox | show | read` 全部落在 `main.rs`，渲染层与 `channel.ts` 的 `field` / `summaryOf` /
  `renderMessage` 对齐。**跑通的**：`discover` 打真服务；`msg caps`（解析对端文档 → 发现
  服务 → 签一份 origin proof → POST，一次完整往返）；`msg send` 两个**本机 awiki 托管**的
  身份**双向** `direct.send`，两边都回 `accepted: true`。**预期为负的**：`msg inbox` /
  `show` / `read` 对 awiki 一律回"does not implement … (JSON-RPC -32601)"——awiki **没有**
  `x_agentx.inbox.v1` 这套扩展面，这正是 `call_extension` 该有的反应。
- **撞上的第三个坑：crate 1.0.5 验不了自己这一侧签出来的文档（`@context`）。**
  §8-J 记的是**生成**侧：crate 写 base64url、awiki 要 base58，签名底相同、只需重编码。
  **解析**侧是它的镜像，但结论相反：crate 1.0.5 验一个 base58（`z…`）`eddsa-jcs-2022`
  proof 时，会**把文档的 `@context` 折进 `proof_options`** 再算签名底
  （`rust/src/proof/mod.rs` 的 `verify_w3c_proof_detailed`，Python 侧同款），而 awiki
  （pin `anp==1.0.3`，自实现 §2.5.5 验签）签的是**不折**的那一版。结果：crate 对
  **每一条 awiki 托管的 e1 文档**都给假否定——同一个 64 字节签名，编码成 base64url 就过得去、
  编码成 `z`+base58 就过不去（**已用反证法在真文档上核过**）。`origin/master` 与
  `origin/release/0929` 都是这个行为，不是本地检出旧了。**处理**：`resolve.rs` 加一层
  `document_is_bound`——先问 crate，crate 说不才算；只有在那条 base58 proof 上才**把
  `proofValue` 重编码成 base64url 再问一次**（选中 crate 不折 `@context` 的那条分支）。
  **不重写验签器**（本模块的底线），只换编码；两种分支哈希的输入完全相同，公钥指纹那关也照过。
  与 §8-J 生成侧的重编码**互为镜像**。
- **`msg listen` 已落（2026-10-02）**，唯一那条常驻契约（[realtime.md](docs/design/realtime.md)）。
  `message/stream.rs` 是传输（`/anp-im/rpc` → `/anp-im/stream` 的地址推导、帧、WebSocket 拆成
  一条写任务一条读任务），`message/listen.rs` 是状态机（`stream.hello` 校验 `server_did` →
  `stream.auth` → `sync.delta` 补拉 → live → `stream.ack`），也是命令面唯一一条长跑的命令。
  **两处与 TS 参考实现不同，都是照规范补的**：（a）致命的握手失败**先打一行 `state: error`
  再退 1**（realtime.md §7.1/§7.2 要求，`listen.ts` 漏了这一步）；（b）中断用
  `tokio::sync::watch` 走到状态机的每一次等待上，所以退避睡眠（base 2s / max 30s / ±20%）
  不会把 Ctrl-C 拖到 30 秒。**游标不在本地**：它在服务端按 `(owner_did, device_id)` 存着，
  `stream.ack` 是唯一的写入者，`--ack` 顺带发 `inbox.mark_read`。
- **`group` 一族已落（2026-10-02）**：`create | info | members | join | leave | send`
  （P4 `anp.group.base.v2`）。`src/group.rs` 放协议逻辑——§7.1 的推荐策略原文、
  `--policy` 在它之上的**浅合并**、以及 §7.1 那几个封闭集合（`admission_mode`、
  permissions "包含且仅包含"：多一个键与少一个键同等拒绝，都在开身份之前）。
  `channel.rs` 加 `call_group`（target 是参数：`group.create` 打**服务**、其余打**群**，
  这个差别在签名对象里，是签出来的不是路由出来的）与 `open_channel_for`（解析一个
  **不是签名者自己**的 DID）。
- **对 awiki 跑 `group` 是预期为负的一条**，和 `msg inbox` 同理：`group create` 回
  HTTP 401。原因是 awiki 自己的策略——`hosted_group_create` 对**任何 public RPC 调用方**
  抛 `group.remote_create_not_allowed`（它的 `messaging/groups/service.py`），群创建只留在
  它本地的 bearer 面上，而本 CLI 不持 bearer（cli.md §5）。另外记一笔：awiki 把这类拒绝
  放在 **4xx** 里（`Unauthorized` → 401 + JSON-RPC 体），本 CLI 与 TS `connectx` 都只收 2xx，
  于是两边的体都被丢掉、只剩一句 HTTP 状态——与 message-service.md §2.1 定的"拒绝走 2xx"
  一致，**不要为此改客户端**。要端到端跑 `group`，目标是本仓的 `packages/service`，不是 awiki。
- **`group e2ee` 的两个服务作用域方法已落并对真服务跑通（2026-10-02）**：
  `group e2ee publish`（§8.1）与 `group e2ee get-key-package`（§8.2）。
  分工是 §1 那条：`src/mls.rs` 是**设备半边**（MLS store 落在身份自己的目录下
  `<root>/<agent>/<profile>/mls/`，KeyPackage 用**设备签名钥** `#<device>-sign` 签、
  不是 `key-1`，因为 §6.4 要的正是"文档里这个设备的 `signing_key_id`"）；
  `src/group_e2ee.rs` 是**线半边**（请求体的形状，与 service 侧
  `groupE2ee.ts` / `groupControl.ts` 的分法同源）。方法名、Profile、以及
  "哪两个方法读 `transport-protected`、哪四个读 `group-e2ee`"都在 `message/channel.rs`
  （`group_e2ee_security_profile`），是照 §4.3 L272–273 推出来的，不是调用点随手选的。
  **`publish` 的请求体只有一个字段**（§8.1.2），且是**整份对象原样**（`did_wba_binding`
  连同它的 proof）——§8.2.3 把同一个对象交给后来跑 `add` 的人，任何在这条路上做的规范化
  都会改掉下游每个验签方的输入。
- **`group e2ee create` 已落并对真服务跑通（2026-10-02）**，四条控制方法里的第一条（§9.2）。
  三处值得记：
  （a）**它是 service-scoped，但通道是用群的文档解析出来的**。§4.4.1 L292–293 让
  `meta.target` 仍是**服务的** `serviceDid`（文档 §3 明说不要"顺手纠正"成 group-addressed），
  可"服务是哪一个"只有**群的文档**说得清（`group_did = serviceDid + ":g:" + <id>`，
  groups.md §2）——所以 `open_channel_for(group_did)` 取端点、`service_target()` 取 target，
  而服务那边 `requireServiceTarget` 会核对 `meta.target.did` 就是它自己的 `serviceDid`。
  （b）**三阶段正好在 `create` 上第一次露出来**（§13.6）：prepare 写本地 → 发送 → 服务说了算。
  命令面在这一步**没有**走 `call_device`，而是直接匹配 `AnpResponse`，因为第三阶段该做哪个
  取决于**为什么**失败：服务**拒绝**＝它没收，本地 commit 就 `abort_commit` 回滚；**传输失败**
  则什么都不断言——请求可能已经被收下、只是回包丢了，那时回滚会让本机对一个服务认为存在的群
  一无所知，这一档是 crate `reconcile_pending_v2` 的事，不是这里猜的。已用两个反例核过：
  把本地 `mls/` 删掉再造同一个群，服务回 `crypto_group_mismatch`，本地 pending 转 `aborted`、
  binding 行与 OpenMLS group 都被清掉。
  （c）**"已经有 MLS 状态了"这件事本地先拦**。同一个群再跑一次 `create`，根本到不了网络：
  crate 的 prepare 就回 `group.e2ee.state_not_ready: a local MLS group binding already exists`。
  服务那两条 `cryptoGroupMismatch` / `epochConflict`（§13.5 第 5 项）因此在**本地 store 不记得**
  时才可达——换设备、或本地状态被清过，正是它们存在的理由。
  另外 `group_state_ref.group_state_version` 取自 P4 `group.get_info` 的当前值：§9.2.3 只校验它
  是十进制字符串，而 §14.1 L1707 规定 `create` **MUST NOT** 推进它，所以这个数只能读、不能算。
- **端到端怎么跑通的**（一次性脚手架，跑完即删，没有留进套件）：三条身份都挂在 awiki 上、
  文档里的 `serviceEndpoint` 也指着 awiki，而 awiki 没有 P6——所以 `group e2ee` 的
  **真阳性**必须打本仓的 `packages/service`。做法：(a) 起一台只发一份文档的玩具 DID 主机
  （`/user/<h>/<e1_…>/did.json`，注意路径里**带 DID 最后一段**，不是 `/user/<h>/did.json`）；
  (b) 把已存身份的 DID 换个主机段、`service` 条目改成服务自己的 `serviceDid`
  （`did:web:127.0.0.1%3A8788`）与端点，**用身份自己的 `key-1` 重签**（沿用 awiki 那版
  不折 `@context` 的签法）；(c) 服务开 `AGENTX_PUBLIC_URL` = 该端口 +
  `AGENTX_DID_DEV_HOSTS=127.0.0.1`。跑出来的：`publish` 回 `published: true` 且库里
  `group_key_packages` 真有那一行；`get-key-package` **逐枚取走**（第二句拿到的是下一枚，
  取空后回 `anp.group.e2ee.key_package_not_found`）——§8.2.4 L767 那条"发出即占住"的 MAY
  本服务是实现了的；`group create` 建群后 `e2ee create` 回 `created: true`，服务 `group_leaves`
  多出一行 owner leaf（`state = active`、`epoch = 0`），本地 `group_mls_bindings` 是
  `role = creator` / `status = active`、`group_mls_pending_commits` 那条转成 `finalized`。
  **顺带核到一条规范没写死的语义**：同一个 `key_package_id` 再生成一次
  被本地 store 拒（`group.e2ee.key_package_consumed`），所以 `--key-package-id` 是**命名**，
  不是"重试取回原包"——publish 重试要么换 id、要么走 `get_key_package` 读回。
- **`group e2ee add` 已落并对真服务跑通（2026-10-02）**，四条控制方法里的第二条（§9.3）。
  它把 `create` 那条三阶段原样复用（准备 → 发送 → 服务拒绝就 abort、传输失败就留给
  `reconcile_pending_v2`），新的只有"往哪儿发、拿谁的包"，三处值得记：
  （a）**两条通道，各带各的策略**。成员那一对（`member_did` / `member_device_id`）不在命令行上
  选，而是**取自 KeyPackage 自己的 owner**（§9.3.3 键在这个 owner 上，服务那边
  `didBindingInvalid` 正是为"两处不一致"设的）——所以先去**成员自己的** service 取 KeyPackage：
  成员的文档指名它的 Host，§8.2.3 允许跨域。`add` 本身则按 §4.4.2 **群寻址**
  （`meta.target.did == group_did`，crate 的 `validate_control_meta` 自己会核）。
  于是这条命令开两条 channel：取包那条打成员的域名、`add` 那条打群所在的 service，SSRF 逐跳
  策略各按各的文档走。
  （b）**`group_state_version` 还是只读不算**，同 `create`：先 P4 `group.get_info` 取当前值。
  但这次多一条可验证的断言——§14.1 规定 `add` **也 MUST NOT** 推进它，所以成功的 `add`
  跑完，P4 的 `group_state_version` 应当**纹丝不动**（见下）。
  （c）**`add` 的 `epoch` 是"加完之后"的那个数**（§9.3.3），只有 crate 知道；命令面把 body
  照 crate 的 `V2GroupAddBody` 九字段原样发，`group_e2ee.rs` 只加一个 `add_body`。
  端到端（同一套脚手架，换了 `rusty` 作新成员）：回 `accepted: true`，服务 `group_leaves`
  里源成员（carol）的 leaf 从 epoch 0 进到 1，新成员（rusty）的 leaf 落 `active`、epoch 1、
  `added_by_ref_json` 记着 `group.e2ee.add`；rusty 那枚 KeyPackage 转 `consumed`；
  **P4 的 `group_state_version` 停在 2 不动**——(b) 那条断言成立。
- **收包的路已经铺好一半，但收包本身没做**。`add` 成功后服务不是往 `deliveries` 写，
  而是往**设备队列**（`device_envelopes`）排：源成员拿到一条 `commit`，新成员拿到 `commit`
  再一条 `welcome`（§12.5/§12.6）。已核对本仓服务确实这样排（`emitAddEnvelopes` →
  `enqueueDeviceEnvelope`，两张表分开）——所以那两张 envelope 在 `deliveries` 里查不到
  **是对的**，它们等的正是 `process_notice_v2` / `decrypt_received_v2`（由 `msg listen`
  投递驱动）。→ [x] ~~已落（2026-10-02）~~，见 §6 与「收包路径」那一节。
- **`group e2ee remove` 已落并对真服务跑通（2026-10-02）**，四条控制方法里的第三条（§9.4）。
  它是 `add` 的镜像，但**只开一条 channel**，值得记的就三处：
  （a）**目标 leaf 是点名的，没有包可取**。`add` 的成员那一对来自 KeyPackage，`remove` 的
  那一对（`member_did` + `member_device_id`）只能来自命令行——§9.4.3 键在这个精确 pair 上。
  被移除的设备**不必**合格（"失去资格或被策略移掉的那一台"正是要移除它的理由），所以
  **完全不碰它的 service**：服务那边的 `deviceAddressed` 也只点名发送方一台，理由写在
  `methods.ts` 的 `GROUP_E2EE_REMOVE_SPEC` 上。
  （b）**只读目标的一份 DID 文档，策略直接从 DID 的主机段建**。`add` 是
  `open_channel_for(member)` 之后再 `resolve_did_document`（要拿它的 service 去取包）；
  `remove` 不需要 service，于是用 `policy_for(&[did_host(member_did)?], …)`——这正是
  `channel::discover` 给文档那一跳用的策略。这样一台 Host 已经没了的成员仍能被移除，
  只要它的文档还答得上来；文档取不到就没有依据说自己是哪一片 leaf，本地失败是诚实的结局。
  （c）**顺带核到"不能移除自己的那片 leaf"**。crate 的 `remove_member_prepare_v2` 在
  `sender_did/device == member_did/device` 时回 `group.e2ee.controller_required`——所以
  "退群"不是这条方法的退化用法，是另一族（`group leave`）。
  端到端（carol 移除 rusty）：回 `accepted: true`，rusty 的 leaf 转 `terminal`、epoch 2，
  carol 的 leaf 进到 epoch 2、仍 `active`，**P4 的 `group_state_version` 照旧停在 2**（§14.1
  对 `remove` 和 `add` 一样是 MUST NOT）；设备队列里 carol 多一条 `commit`，rusty 多一条
  `final-notice`（§12.3 L1455：Commit 给保留的 leaf，最终通知给被移除的那一条）。
  反例也核过：对同一片 leaf 再跑一次 `remove`，到不了网络——crate 的
  `find_exact_accepted_leaf` 在本地 group 里找不到那片 leaf，回
  `did_binding_invalid: exact DID/device pair must identify one current MLS leaf`，
  且**不留 pending 行**（prepare 还没走到写库）。
- **`group e2ee send` 已落并对真服务跑通（2026-10-02）**，四条控制方法里的最后一条（§9.5）。
  它是这四条里唯一**不是三阶段**的一条，另外三处值得记：
  （a）**没有 prepare / finalize / abort**。本地没有"等服务的受理或拒绝"的状态：它只是按
  **当前** epoch 造一个 `PrivateMessage`，加密要么产出 cipher object、要么失败，没有 pending
  行。服务的 `accepted: true` 也只说"收下并排序了"（§9.5 自己的成功语义），从不说有谁能解出来。
  （b）**origin proof 要由*设备*的钥签，不是 DID 根的 `key-1`**——§13.3 第 6 项。服务拿证明
  底里的 `keyid` 去比 `meta.sender_device_id` 在 DID 文档里的 `signing_key_id`，而本客户端
  其余每一跳都签 `key-1`（`Sender::from_identity`），所以 `send` 得把 signer 换成设备那一半
  （`Sender::signing_as_device` + `mls::device_signing_key`，`{device_id}-sign` 这条约定的
  唯一出处仍在 `mls.rs`）。**第一次跑就是被这条挡下来的**：回 `anp.unauthorized`，逐字说
  proof 必须用 `…#carol/default-sign` 做出。服务端只在 `send` 上比这一条（`groupControl.ts`
  L996），`add` / `remove` 不比，所以另外三条不改。
  （c）**三个 content type 各有各的规矩**。外层 `meta.content_type` 被 §9.5.3 钉死成
  `application/anp-group-cipher+json`（crate 常量，不给调用方选）；里层
  `application_content_type` 是自由的（注明"加密进去的是什么"）；而 `--text` / `--body`
  恰好二选一，对应 §7.4 的三选一里本客户端会产出的两种（`text` / `payload`，不产
  `payload_b64u`），且 `--text` 不许配 `application/json`——那是同一具身体的两句话。
  端到端（carol 对 e2e3 群发两次，一次 `--text` 一次 `--body`）：都回 `accepted: true`，
  epoch 2、**P4 的 `group_state_version` 停在 2**（§14.1：进排序链的只有 `send`），
  `group_event_seq` 从 2 推到 3、4；设备队列里 carol（群里唯一 `active` 的 leaf）各多一条
  `incoming`——那正是收包路径（`group_receive.rs`）要取的东西，已落。
- **`group e2ee` 收包路径已落并对真服务跑通（2026-10-02）**，收到的正是 §12 那两类推送。
  它与 `msg listen` 的关系值得写清：`msg listen` 只管**传输与游标**（连接、重连、
  `deliveries` 推进），**不知道任何 MLS**；`group_receive.rs` 是插进去的一层，
  拿到帧才知道该不该管。四处值得记：
  （a）**这两类帧不进 `deliveries`，所以绝不能推游标**（§12.6 没有 ack，服务写完 WS 就删行，
  是 at-least-once）。派发因此插在投递过滤**之前**并 `continue`——为一个既不占号、
  又可能重发的帧推游标，等于替本机认领了一条从没被投递过的消息，下次重连就会跳过那一号。
  测试把这个计数钉住了：紧随其后的 P4 `group.incoming` 拿到的是 `head + 1`，
  只有在前面那两帧一个号都没占的前提下才可能。
  （b）**`group.incoming` 这个名字与 P4 共用**，§12.5 是唯一的分野——e2ee 那一臂读的是
  `security_profile = group-e2ee`。所以接收方只在这个 profile 下认领它，其余回 `Ok(None)`，
  P4 的那条照旧走普通投递。**认领过的帧若出错，就当终局**，不再落到 `decode_message`——
  否则一条已经进过 e2ee 路的帧会被画成"服务可见的投递"，那是它从来不是的东西。
  （c）**通知要的是全体成员的文档**，不是发送方一人的：一条 Welcome 要验整片 leaf。
  这些文档取自 P4 的名单而不是本地 MLS 状态——首次 Welcome 时本地根本还没有这个群。
  它们**故意不缓存**：文档是"这台设备现在拿哪把钥签名"的权威，缓存旧了会表现为验签失败，
  那看起来像对方坏了，而不是像自己的缓存旧了。**通道**反而缓存，因为那是路由、不是密钥材料。
  （d）**先到的那条 Commit 会报 `group_not_found: no local MLS group binding found`，
  这是对的，不是 bug**：一台从没见过该群的设备无法把 Commit 应用到它上面，Welcome 才是建群
  的那一条。它作为一条状态行报出、会话继续，而不是终结一次「马上就对了」的运行。
- **跑通这条路上顺带修了服务端两个 bug**（都真发生了，不是预防性改动，各一次提交）：
  （a）**一次 Add 的 commit 与 welcome 共用一个 `meta.operation_id`**（Remove 的保留 leaf 提交与
  final-notice 同理）。`notice_id` 不在乎这个——§7.6 L665 明说一次密码学结果的各片 leaf MAY 共用——
  但 `anp` 的 `process_notice_v2` 用 `p6-v2-notice:{meta.operation_id}` 做回执键，存的是
  `{meta, notice, recipient_did, recipient_device_id}` 的摘要，同键不同内容直接回
  `group.e2ee.commit_invalid: notice operation_id was replayed with different content`。
  被加入的那台设备**两条都收**（§12.4 welcome 只发给它，commit 发给包括它在内的每一片 leaf），
  同收件人、不同内容、一个键——基于 crate 的接收方解不出第二条。改法是逐信封各造一个 id。
  （b）**客户端断开会把服务进程带走**。`ws.ts` 的 `finish()` 在退出时把 socket 的 `data`/`close`
  **连同 `error`** 监听都摘了；前两个是收尾，第三个是致命的——`finish` 在连接结束时都要跑，
  而拆掉 socket 恰恰会招来下一个事件：对面消失后 RST 晚一拍才被读到，Node 在 socket 上以
  `error` 抛出，**没有监听者的 `error` 事件按设计就是致命的**。序列于是变成
  "客户端突然断开" → "服务退出"。连续三次打断 `msg listen` 复现了它；去掉那一行即可
  （`finish` 本来就靠 `closed` 幂等，多留一个监听者什么都不改）。
- **第四个坑：crate 内部验文档那条路没有 `document_is_bound` 的那层回退。** §6 上面记的
  `@context` 折入问题不只在**解析**侧：`generate_key_package_v2` 会拿调用方递进来的
  issuer 文档再跑一次 `validate_did_document_binding`（`rust/src/proof/object_proof.rs`），
  而那条路是 crate 自己直呼、**没有我们那层重编码回退**的。于是"刚被本客户端成功解析并验过
  的 awiki 文档"递进去，回来的是一句
  `Issuer DID document binding validation failed`——一条假否定，且看不出和文档有关。
  **处理**：把 `document_is_bound` 拆成 `document_is_bound`（要的是是/否）与
  `document_in_crate_form`（要的是"递给 crate 的那份"），`mls.rs` 用后者。**只换编码，
  不重写验签器**，与解析侧同一条底线。这也解释了为什么 §8-J 生成侧与解析侧会互为镜像：
  同一个 crate 的签与验在 base58 这条分支上就不自洽。
- **未做**：身份这块还剩 "换钥/换设备/`update_document`"。
- 先落 **`msg`** 一族（含 `msg listen` 常驻契约），因为它是 §4 消息库的入口。
  → [x] ~~已落~~
- **与 TS `connectx` 并存**，`CONNECTX_HOME` 的处理见 §8-F。

**Phase 2 —— 消息库**（还没动）
- [ ] `messages.db`（§4）+ 本地游标 + 与 `mls/` 的分工；read 状态与对账规则落定。
- [ ] 这一步**触及服务端**（ack / 保留 / 补拉），与"把服务做好"合并做。

**Phase 3 —— 逐族补齐**（每族一次提交）
`group`（含 `group e2ee`，即 B2 的目标）→ `did` → `anp`（login/sign）→ `agent`。

- [x] ~~P4 `group` 一族~~（2026-10-02）：`create | info | members | join | leave | send`
- [x] ~~`group e2ee publish | get-key-package`~~（2026-10-02）
- [x] ~~`group e2ee create`~~（2026-10-02）
- [x] ~~`group e2ee add`~~（2026-10-02）
- [x] ~~`group e2ee remove`~~（2026-10-02）
- [x] ~~`group e2ee send`~~（2026-10-02）
- [x] ~~`group e2ee` 收包路径：`process_notice_v2` / `decrypt_received_v2`~~（2026-10-02；靠 `msg listen` 投递驱动）
- [ ] 身份：换钥 / 换设备 / `update_document`
- [ ] `did` 剩下的三条：`resolve` / `update` / `restore`
- [ ] `anp` 一族：`show` / `login` / `sign`
- [ ] `agent` 一族：`show` / `use` / `list`
- [ ] `version`

**Phase 4 —— 覆盖与收束**（还没动）
- [ ] 新客户端自己的端到端（Rust 侧，或驱动二进制的 TS 侧——今天的 `packages/e2e` **不覆盖它**，
  见 §8-H）；`agentx-cli` 的命令面定稿；TS CLI 冻结在某个版本（§8-I）。

---

## 7. 待定项（已在 §0.1 全部裁定，此处留索引）

1. **`agentx-cli` 与 `CONNECTX_HOME`** → 分开，独立 store 根（§0.1 第 1 条）。
2. **消息库明文策略** → 留明文，按对话存，方式待设计（§4）。
3. **消息库是不是记录之源** → 是（§4 / §8-C）。
4. **`anp` pin** → 1.0.5（§9）。
5. **TS CLI 的终局** → 冻结，验收线是"明文群聊跑得通"（§0.1 第 5 条）。
6. **e2e 形态** → 不纠结，随功能落（§0.1 第 6 条）。
7. **客户端的 DID 文档挂哪** → 挂**本机已有的 `awiki-open-server`**（§0.1 第 7 条 / §8-J）。

**本轮不再有挂起的裁定。** 身份存储 + DID 文档发布（含挂 awiki host）已跑通（§6 Phase 1）；
`msg` 一族的五个命令也跑通了（`send` / `caps` / `inbox` / `show` / `read`，见 §6）。
Phase 1 到此收口：`msg listen` 与 `group` 一族都已落地（见 §6）。Phase 3 已开工：
`group e2ee` 的六条方法（两条服务作用域的 `publish` / `get-key-package`，四条控制方法
`create` / `add` / `remove` / `send`）已落并对真服务跑通
（见 §6），收包路径（`process_notice_v2` / `decrypt_received_v2`，由 `msg listen` 投递驱动）
也已落并对真服务跑通，然后是剩下的身份工作（换钥 / 换设备 / `update_document`）与
`did` / `anp` / `agent` 三族。

---

## 8. 你没提到、但绕不开的问题

- **A. 两个客户端共用一个身份 = 一台设备，listener 会互相抢消息。**（**已裁定：两端分开，
  各用一套 store 根 → 两台设备，此问题不发生。** §0.1 第 1 条。）`device_id` 由 agent/profile
  名推出（[realtime.md](docs/design/realtime.md) §5.4）；投递游标与 read 状态都是服务端按
  **(owner, device)** 记的。若指向同一个 store 根，两个客户端就是**同一台设备**：同时跑
  `msg listen`，服务端游标只会前进一次，**消息被其中一边吃掉**。**分开就避开了**——但这也意味着
  TS CLI 那条身份与 `agentx-cli` 那条身份是**两个独立的账号/设备**，不能互相顶替。
- **B. 本地明文 = 新的密钥资产。** 见 §4 第 2 点。留明文就等于把 TODO4 §E 那条规矩的适用范围
  从 `mls/` 扩到 `messages.db`——备份、调试、分享都要重新立边界。
- **C. 两份真相要对账。** 服务端收件箱（扩展面 `x_agentx.inbox.v1`）与本地库会分叉。
  `inbox.get` / `mark_read` **不在规范里**，是本服务自己的扩展——本地库若成为权威，这套扩展
  面的去留、以及 read 状态归谁，都要重新定。
- **D. 服务端可能得跟着改（"把它做好"的具体落点）。** 本地库成为记录之源后，需要：
  一条明确的 **ack / 保留契约**（`deliveries` 留多久、ack 后能否删）；P6 **设备队列的有界保留**
  （`AGENTX_DEVICE_QUEUE_MAX_AGE_MS`，缺省 **24h**／`MAX_ATTEMPTS` **8 次**，
  [deviceQueue.ts](packages/service/src/delivery/deviceQueue.ts) 文件头）要不要为持久客户端放宽
  或另开一条；以及**补拉历史**的接口（现在没有规范位）。**这不是客户端单方面能解决的。**
- **E. 盘上格式：不再要求逐字节兼容**（**§0.1 第 1 条裁定之后已作废**）。原文担心的是
  "keystore 是 Ethereum V3（scrypt `N=2^16,r=8,p=1` + aes-128-ctr + keccak256）、`identity.json`
  存 curve、session 是缓存，两个客户端要共享身份所以得逐字节兼容"。**裁定把 store 根分开了，
  这一条的前提就没了**——两个客户端**各读写各的盘**，Rust 侧**不需要**兼容 TS 的格式。
  留下的是两件更小的事：（a）Rust 侧**自定**一套身份盘上格式并自己拥有它；（b）如果哪天要让
  一个已有身份**从 TS 迁到 Rust**，那是一次性的**导入**（读旧、写新），不是长期 ABI。
  **开工前不要按"逐字节兼容"去做 Phase 1 的身份部分**——那是作废了的约束。
- **F. 名字不只是名字。**（**已裁定：分开，独立前缀与 store 根。** §0.1 第 1 条。）
  `agentx-cli` 换了名，也用**自己**的 store 根与环境变量前缀，不碰 `CONNECTX_HOME` / 旧
  `AGENTX_*`。代价是两条身份各自独立（见 §8-A 末句），收益是两个客户端互不干扰。
- **G. crate 的依赖面要接受。** `anp` 1.0.5 是 **Apache-2.0**（本机 0.9.0 检出写的是 MIT）；
  `default` features 拖 **`reqwest` + `tokio`**；`mls` 拖 **`rusqlite`(bundled) + openmls
  `=0.8.0`**（**精确 pin**）；且 **`tiny_http` 是非可选依赖**——一个客户端会因此带进一个 HTTP
  **服务器**库。这些都要在 §7 第 4 点一并接受或绕开。
- **H. 新客户端没有任何端到端覆盖。**（**已裁定：接受，随功能落。** §0.1 第 6 条。）TS CLI
  不动，今天的 `packages/e2e`（TS 直接调 CLI 命令函数）**一行不用改，但它覆盖的是 TS 客户端**。
  `agentx-cli` 的端到端从零起，跟功能一起写。
- **I. 命令面会分叉。**（**已裁定：TS CLI 冻结，`agentx-cli` 是唯一前进方向。** §0.1 第 5 条。）
  24 条命令面是 [cli.md](docs/design/cli.md) 按判据裁出来的；TS 侧冻在"明文群聊跑得通"这条线，
  新命令面只在 `agentx-cli` 里长。
- **J. 客户端自己的 DID 文档**要挂在哪？**（**已裁定：挂本机已有的 `awiki-open-server`**，
  不自己写桩——§0.1 追加）**
  `did:wba:<host>:...` 里的 `host` 是 DID 的一部分，而服务端要**按那个 host 去取文档**才能
  验签（§13 的资格门禁、`group.e2ee.*` 的绑定验证都走这条）。也就是说：**光有私钥不够，
  文档得在一个服务端够得着的地方**。
  **用户指出本机已经有一份真东西**：`/Users/eccstartup/code/claude/awiki-open-server`
  （Python，community server + **DID host**，文档按 `/{sub_path}/did.json` 发，
  见其 `src/awiki_open_server/app/routes.py` L569–650）。所以**不用**照
  `packages/e2e/src/harness.ts` 那样自己起桩——**直接用它**，与"真实部署挂真 DID host"
  是**同一条路**，只是 host 是本机。
  **落地时要注意的两件**：消息服务侧要放行本机主机（`AGENTX_DID_DEV_HOSTS`，否则
  `AGENTX_ALLOWED_DID_HOSTS` 会拦掉）——**用 `AGENTX_DID_DEV_HOSTS` 加主机，不要去放宽
  `AGENTX_ALLOWED_DID_HOSTS` 那段逻辑**（用户明说过这条不动）；以及本机是 **HTTP**，
  不是 HTTPS。
  **TS CLI 走的就是这条路**，所以 Rust 侧是在复现一条已存在的路径，不是新开一条。
  **落地方案（2026-10-02 核到行）**：DID 取
  `did:wba:<domain>:user:<agent>:e1_<fp>`，`<fp>` = `compute_multikey_fingerprint(key-1)`
  （JWK thumbprint，`crv=Ed25519,kty=OKP,x=b64u(pub)`）——crate 的
  `compute_multikey_fingerprint`、`build_unsigned_e1_did_document` 与 awiki 的
  `ed25519_root_fingerprint` **同一个算法**。awiki 对路径段没有固定要求
  （`_validate_local_user_did` 只判 domain、`e1_` 与 `group|groups|service|services`
  这几个保留段），**handle 是随文档另注册的**，不进 DID。发布走
  `POST /user-service/v1/did-auth/rpc`（别名 `/did-auth/rpc`），JSON-RPC 方法 `register`，
  `params.did_document` 放**自签**文档；awiki 只认 `DataIntegrityProof` + `eddsa-jcs-2022`
  + `assertionMethod`，签的 VM 必须是 `Multikey`（`z`+base58(`0xed01‖32B`)），
  `proofValue` 必须是 **base58-btc 多基（`z…`）**。**一个坑**：crate 的
  `complete_w3c_proof` 写的是 **base64url** `proofValue`（awiki 的注释点名了这个偏差），
  而签名底两边一样（`sha256(jcs(proof))‖sha256(jcs(未签文档))`），所以**只需把
  `proofValue` 重新编码成 `z`+base58**，签名本身不用重算。服务端要取这份 HTTP 文档，
  得把主机加进 `AGENTX_DID_DEV_HOSTS`（= `resolution.allowInsecureTransport`，
  见 `config.ts:227,241`）。
  **已经落地（2026-10-02 跑通）**：见 §6 Phase 1 那条"身份已发布"。
  **落地上撞到的第二个坑（原方案里没写、只有跑起来才看得见）**：**设备签名钥不能是
  DID 根钥**。`awiki-open-server/protocol/anp_adapter.py::validate_single_device_document`
  除了"关系集必须与重建结果一致"外，还有一条
  `root_id in {signing_key_id, e2ee_key_id} or signing_key_id == f"{did}#key-1"` → 拒。
  换言之 P6 的那台设备**必须有自己的两把钥**（签名 Ed25519、协商 X25519），而 crate
  的 `enable_e2ee` 那一对（`#key-2` 是 P-256、`#key-3` 是 X25519）**不能用**：P-256 做不了
  P6 要求的 EdDSA 签名钥。所以客户端要**自己生成**这一对（`ed25519-dalek` / `x25519-dalek`，
  都与 crate 同版本，不引第二条依赖栈），文档则交给 crate 的
  `build_vnext_did_document(base, root_key_id, root_vm, entry, signing_vm, e2ee_vm)` 装配——
  **不要手插 `deviceManifest`**：awiki 会用**同一个 builder** 把文档重建一遍，再逐关系
  `set(values) & {root, signing, e2ee} == set(rebuilt[relation])` 比对，手工装的关系集
  过不了这一关。`base` 只放 builder 不管的字段（`id` / `@context` / `service`）。
  **第三个坑（解析侧，与生成侧的重编码互为镜像；2026-10-02 补）**：crate 1.0.5 验 base58
  `eddsa-jcs-2022` proof 时会**把 `@context` 折进签名底**，而 awiki 签的是不折的那一版，
  于是 crate 对**每一条 awiki 文档**都给假否定。解法同样是**只换编码**：验之前把
  `proofValue` 从 base58 重编码回 base64url，选中 crate 那条不折 `@context` 的分支
  （`resolve.rs::document_is_bound`）。细节见 §6 Phase 1 的那条。

---

## 9. 动手前必须先做的三件事

与 [client-mls.md](docs/design/client-mls.md) §8 同一份清单，此处只记依赖：

1. [x] ~~**fetch** 本机 `anp` 检出（0.9.0，落后 origin/master 93 个提交）；~~ 已 fetch
   （**注意**：crates.io 的 1.0.5 对应 `origin/release/0929`，**不是** `origin/master`；
   本机检出的版本号仍是 0.9.0 那条线，读源码用 `git show origin/release/0929:rust/...`）。
2. [x] ~~**在 1.0.5 上重核** §2 / §3 用到的每个函数签名（1.x 有 `v2_origin`、`sealed_handoff` 等
   新模型，0.9.0 上的判断要重验）；~~ 已核，结论落在 §2/§3/§6 的各处（含 crate 自带
   origin proof、`group_e2ee::operations::v2` 的真实签名）。
3. [x] ~~**定 pin**（§7 第 4 点）。与 `awiki-open-server` 钉 `anp==1.0.3`（Python）**无关**。~~
   已定 `anp = "1.0.5"`（`rust/Cargo.toml`）。

---

## 10. 工程（沿用 TODO4 §E）

每段一次提交，格式 `feat(cli): <摘要> (TODO5-<段号>)`，同时动 `TODO5.md` + `docs/design/*.md`
+ 源码 + 测试。提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
`🤖 Generated with [Claude Code](https://claude.com/claude-code)`。

不提交密钥。**消息库一旦落明文，它就是密钥**（§8-B）——备份、调试、分享一律按 TODO4 §E 那条办。

**当前基线**（TODO4 §E）：`npm run typecheck` 通过，`npm test` = 213 + 695 + 4 + 652 = **1564**
全绿。本台账**已不是"纯方案"**：命令面落到哪儿见 §6 的「进度总表」；Rust 侧 `cargo test` = **78**
全绿（`rust/`）。
