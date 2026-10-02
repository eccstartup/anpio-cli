# TODO3 —— 第三轮台账

接 [TODO2.md](TODO2.md)。TODO2 的 A 节（A1–A7）与 B 节（B1a–B7）都已落地。本文件只讲
一件事的拆解：**B1b —— `group.*` 的跨域出站**，以及它牵出的那句"谁来发布群 DID 文档"。

口径与 TODO2 一致：ANP **1.2 已发布**，规范里的 Profile 名仍是 `.v2` 那一套。

---

## 0. 一个已裁定的事（结论留档）

**2026-10-02 用户裁定：群 DID 文档由本服务自己发布。（B1a 记里的"选项 1"。）**

原话大意的两句：要做一个**独立于 awiki 的社交应用**；即使最后不走这条路，也用 **fork 版
的 `awiki-open-server`** 来发布，不走上游。

**为什么这是个决定，不是一句实现细节。** [groups.md](docs/design/groups.md) §2 与
[message-service.md](docs/design/message-service.md) §13 都写着"本服务不托管 DID 文档"，
那是 C9 当初在"awiki 托管一切"这个前提下做的取舍——文档由真正托管 DID 的服务发布，里面
再放一条指向本服务的 `ANPMessageService` 条目。选项 1 把这条接缝从**别人的事**变成**我们
的活**：本服务从"只解析 DID 文档"变成"**也发布** DID 文档"。

**为什么绕不过去。** 群族要跨域，Host 就必须先能被解析到（P8 §5.2 L215–221 的 **MUST**：
解析 `group_did` → 从文档里定出 Group Host 的 `ANPMessageService`）。而 `group_did` 按本
服务的选择就住在**本服务自己**的命名空间里（`group_did = serviceDid + ":g:" + <id>`，
§2）。把它交给另一个域托管，等于让别人的服务器替我们签一份关于我们的声明——既要多一层
同步，又与"独立出来"直接冲突。

**代价记账（写在这里，别等到改的时候才发现）：** 上面那两句"不托管 DID 文档"、以及
[federation.md](docs/design/federation.md) §3/§8 里"群 DID 文档还没有人发布"那句，全部
变成事实错误。改文档是本轮的一半，不是附赠（见 A6）。

---

## A. B1b 的拆解（六段）

### A1 群密钥：每个群一把 Ed25519，与群行同一个事务落库

`group.create` 的时候铸一把 per-group 的 Ed25519 私钥。存哪——**数据库列**，不是
`0600` 文件。理由：

- **不能有半个群。** 群行与"证明这个群的钥"必须同生同死。文件形态必然要跨两个东西写
  （一个文件 + 一行路径），中间崩一下就留下"有行没钥"的群，而那个状态的恢复路径是零。
  数据库列天然在一个 `BEGIN IMMEDIATE` 里，要么都有要么都没有。
- **两者性质不同。** `AGENTX_KEY_FILE` 那种文件形态是给**部署身份**用的——一把按部署
  配置、跨群稳定的钥，属于运维资产。群钥是**每个群一把、随群创建而生的数据**，它的生命
  周期就跟着群行走。

**代价要说清楚并落进文档：数据库因此含签名私钥。** 数据库文件、它的备份、以及任何
"把 db 发过来看看"的调试，都要按密钥对待。这是本轮唯一一处把"不提交密钥"这条纪律从
仓库扩到运行时的资产上。

**落地（2026-10-02）。** schema **v11**：新表 `group_keys (group_did PRIMARY KEY,
private_key, created_at)`，`private_key` 是 hex 的 32 字节种子——与 `AGENTX_KEY_FILE` 认的
裸 hex 同形，`parsePrivateKey(hex, 'ed25519')` 两边都能读。访问子是
`groupSigningKey()` / `insertGroupSigningKey()`，**单开一张表而不是 `groups` 上加一列**：
`Storage.group()` 是 `SELECT *`，加一列就等于让私钥跟着每一个 `StoredGroup` 走（日志、测试
快照、任何只是想看看群策略的调用点）；分表把"谁能读到钥"变回调用点上看得见的决定
（`sqlite.test.ts` 有一条测试钉住这件事）。铸钥在 `createGroup` 里、紧跟 `insertGroup`：
`perform` 的整个身体包在一次 `BEGIN IMMEDIATE` 里，所以要么两者都在要么都不在。**升级之前
的群没有钥，且不补铸**——事后铸出来的那把不是此前任何一句关于这个群的话所依据的那把，
`groupSigningKey` 返回 `undefined` 就是这个意思（v10 → v11 迁移测试钉住它）。

**不在这一条里做的**：没有从私钥推公钥的地方，也还没有任何消费者。公钥的推导
（`ed25519PublicKey`）随 A2 一起进 core 的 `advanced` 入口——A1 只负责"这把钥存在且属于这
个群"，A2 负责"它能变成一份文档"。

文档更正一处：groups.md 新增 §2.1（钥的三条取舍 + 数据库按密钥对待这条代价），§7 那段
"要签它需要 `assertionMethod` 私钥"指了过去。

### A2 群 DID 文档的形状与签名

按 §2 的形状造一份 `did:web` 文档：

- 一个验证方法（Ed25519），同时进 `authentication` 与 **`assertionMethod`**——后者是
  `group_receipt.proof` 要的那一支（groups.md §7）。
- 一条 `ANPMessageService` 服务项：`serviceEndpoint` = 本服务入口，并**声明
  `serviceDid`**——§6.2.1 L327 要求参与跨域的服务条目 **MUST** 声明它，而这条文档的全部
  意义就是让别的域据此找到我们。
- 一份自签的文档证明。

**一段已经查清、因此不必再猜的事**：核心解析层**不要求**这份文档有证明，所以"文档能被
解析"与"签名对不对"是两件事。`documentProofPolicy` 对原生 `did:web` 直接返回
`skipped`（原话是 Appendix B 禁止要求另一个方法的 WBA 文档证明），对末段不是 `e1_` 的
`did:wba` 在默认的 `lenient` 下是"有则验、无则收"
（[resolveDid.ts](packages/core/src/crypto/resolveDid.ts) 的 `documentProof` 文档注释）。

**那还签它做什么？** 三件事：`assertionMethod` 要有公开的归处（A5 的回执签名读它）；
自签文档是"这把钥确实属于这个群"的唯一声明；以及一个带证明的文档在 `strict` 档的部署
下也照样成立。**不是**为了让解析通过——写成那样会让下一个人以为去掉签名就会解析失败。

**落地（2026-10-02）。** core 侧只动了两处导出：新增 `crypto/ed25519.ts` 的
`ed25519PublicKey`（32 字节种子的长度检查留在这一层，因为它读的是数据库列 / keystore /
文件这类输入边界；Rust 那条路不需要，这里是 TS），以及把已有的 `buildBaseDidDocument` 公开
——它本来就把同一个 `keyid` 写进 `authentication` **和** `assertionMethod`，所以"两处授权"
是构造出来的而不是配出来的。两个名字都进 `@agentx/core/advanced`，`index.test.ts` 的钉死清单
同步。服务侧新增 `rpc/groupDidDocument.ts`：`groupDidKeyId()`（fragment 一处定义，因为文档里
的声明与证明里的引用必须是同一个值）、`groupServiceEntry()`（`well-known.ts` 那条原样搬过来
只换 `id`）、`buildGroupDidDocument()`（`parsePrivateKey` → `ed25519PublicKey` →
`encodeMultibaseEd25519` → `buildBaseDidDocument` → `signDidDocumentProofSync`）、以及
`groupDidDocument(storage, config, groupDid)`。

测试 `rpc/groupDidDocument.test.ts` 用**两条独立的验证路径**，各钉一句话：附录 B 的
`verifyObjectProofDetailed(doc, doc)`（把文档自己当 issuer 文档——不是取巧，`group_receipt.proof`
将来走的正是同一条路：同一个 Profile、同一个签名底）验的是"签名与 `assertionMethod` 授权"，
`verifyDidDocument(doc, groupDid)` 验的是"它能被解析成这个 DID 的文档"——后者对 `did:web` 跳过
证明，所以测试里**特意把 `proof` 删掉再解一次**，把"签名不是为了解析通过"写成可执行的断言而不
只是注释。服务条目的 `serviceEndpoint` 断言读 `RPC_PATH` 而不是抄字符串——抄一次就多一个会漂的
常量。

文档：groups.md §2 那段"v1 不发布"改写成"由本服务自己发布"（并写清发布的是**群**文档、
本服务自己的身份文档仍由 awiki 托管，§C3），新增 §2.2 记形状与三条"缺一不可"。

### A3 托管路由：`GET /g/<id>/did.json`

与 `didToUrl` 对这条 DID 的映射严丝合缝（[resolveDid.ts:520](packages/core/src/crypto/resolveDid.ts:520)
把 `did:web:host:g:XXXX` 映成 `https://host/g/XXXX/did.json`）。两处要注意：

- **不是本服务签发的群 id → 404，不是 500。** 一个陌生人猜了一个 id 打过来，是"这里没有
  你问的东西"，不是"我们坏了"。
- `Content-Type` 用 `application/did+json`——与 awiki 那条路一致，也是 `packages/e2e`
  的玩具主机已经在用的。

**落地（2026-10-02）。** 路由挂在 `http/server.ts`（路由表本来就在那里），处理器是 `main.ts`
里的一句 `groupDidDocument(storage, config, groupDid)`。**前缀是推出来的，不是写死的**：
`groupDidRoutePrefix(config)` 拿一个哨兵 id 去问 core 的 `didToUrl`，再把哨兵那段切掉——于是
"对端会 GET 的路径"与"我们挂的路由"用的是同一个函数。`serviceDid` 自带路径段时（
`did:web:host:svc`）前缀就是 `/svc`，测试里有一条专门钉它（写死 `/g/` 的实现会在这条上红）。
段解码与数据面共用新抽出来的 `decodeSegment`（"一个段要么是可用的 id 要么不是"这个判断不该
因为问的是哪条路由而不同）。状态码：未接线的处理器 → 501（与 well-known 同规矩），未知群 /
v11 前无钥的群 / 空段 / 多一段 / 坏转义 → 404，非 GET → 405 + `Allow`。

`main.ts` 那句"this service never writes a DID document itself"随之改掉——本轮之后它对**群**
文档是假的；本服务**自己**的身份文档仍由 DID Service 托管，那句话保留的是这一半。

### A4 schema v11 + 把 `group.*` 接进 `RELAYED_METHODS`

表只有一张（群钥）。接法与 B1a **一字不差**：`RELAYED_METHODS` 加上方法名，`relayFor`
的规则不动一行——解析 `meta.target.did` 公开的 `ANPMessageService`，是本服务就本地办完，
不是就转发原始方法。B1a 在 `relayFor` 的注释里留的正是这句话："等 Host 侧发布文档之后，
把 `group.*` 那几条加进 `RELAYED_METHODS` 即可，机制本身不用改。"

**群族要分两批接，因为它们的 `meta.target` 不是一回事**（
[methods.ts](packages/service/src/rpc/methods.ts) 的 `targetMode`）：

| 批次 | 方法 | `meta.target` | 与谁同形 |
|---|---|---|---|
| 先接 | `group.create`、`group.e2ee.create` | `kind: "service"`，`did` = 某个 `serviceDid`（§8.1.2 L624–625） | **与 `attachment.*` 完全同形**——连"目标写着 `config.serviceDid` 就本地办"那次短路都复用 |
| 后接 | `group.get_info` / `join` / `add` / `remove` / `leave` / `update_profile` / `update_policy` / `send` / `e2ee.add` / `e2ee.remove` / `e2ee.send` | `kind: "group"`，`did` = `group_did`（§8.2.2 L648–649、§8.9.2 L833–834） | 就是 A1–A3 要撑起来的那一批 |

**`group.create` 的 `target.did` 是 `serviceDid`，不是 `group_did`**——那两条是"请一个服务
建群/建 MLS 组"，建群之前还没有群可指。所以它们的短路条件与附件一致（目标是自己就不
出站），**晚于 A3 也不会变**，可以随 A1 一起先接上。把这一批单独列出来是因为很容易漏：
看族名会以为"群族全都要等群文档"，其实只有后一批要。

### A5 `group_receipt.proof` 开始签

groups.md §7 记的"v1 不签"是**有前提的欠账**，不是结论：

> 要签它需要 `group_did` 的 `assertionMethod` 私钥与一份可解析的群 DID 文档，两件都是
> C11 的活。

A1/A2 之后两件都有了，所以这一步不是新功能，是把已经写明的欠账还掉。判据照 §7.9 L516：
回执会离开 Host 所在域并被别的域依赖时 **MUST** 有 proof。

**选择：不分同域/跨域，一律签。** 回执现在只有一种生成路径，按来源域分成"签/不签"两种
形状，等于给未来留一个"跨域回执漏签"的坑，而签一次是对称的本地操作。同域多签一次没有
第二个验证方，也就没有额外信任面。

### A6 文档更正

随 A1–A4 变成事实错误的句子：README §"两处服务"、groups.md §2、message-service.md §13、
federation.md §3/§8。**与 B1a 一样，更正不是附赠，是这一步的一半**——一份写着"本服务
不托管 DID 文档"的设计文档，在它**开始**托管群 DID 文档之后，比没有文档更坏。

---

## B. 部署侧的（不是代码，也不是本轮能做的）

- **`did:web` 解析要 HTTPS。** `didToUrl` 对任何 `did:web` 一律给出 `https://`，所以
  `AGENTX_PUBLIC_URL` 是 `http://…` 的部署（**包括本仓库的默认值** `http://127.0.0.1:8787`），
  它的群 DID 会指到一个没有 TLS 的地址——跨域解析必然失败。这不是本轮的 bug，是 `did:web`
  的固有约束，与 `serviceDid` 的约束同源（federation.md §2.5）。真实部署必须 https；本地
  联调走 `AGENTX_DID_DEV_HOSTS` / 内联文档那条口。
- **`AGENTX_ALLOWED_DID_HOSTS`**：跨域**接收**要求把对端域加进白名单（federation.md §2.5）。

---

## C. 仍然悬着的（接 TODO2 §C）

- **C1 P6 不得对外声明**——原样保留，等上游发布稳定的 MLS `ExtensionType` code point。
  与本轮不冲突：A4 接的是**出站路由**，与"要不要在 `anp.get_capabilities` 里广告 P6"
  是两件事（扣留仍在 `capabilities.ts` 的 `WITHHELD_PROFILES` 里）。
- **C2 客户端侧群 MLS 的密码学库**——Rust crate → napi 绑定，独立一块，需要你定什么时候开。
- **C3 `serviceDid` 自己那份文档仍由别人托管。** A1–A4 让本服务开始发布**群**文档，但
  **本服务自己的身份文档**（`config.serviceDid` 那份）仍由 `awiki-open-server` 托管——外层
  `keyid` 的 fragment 必须与发布方写进去的一致（federation.md §4 第 2 点）。这一条与本轮
  无关，但不该被"我们开始发文档了"这句话盖过去：**本轮发的是群文档，不是服务自己的文档。**
  要不要把后者也收回来自己发，与 A7 同族，等群这一轮落地之后再看。

---

## D. 工程（沿用 TODO2 §D）

- 每个任务一次提交，格式 `feat(service): <摘要> (B1b-<n>)`，同时动 `TODO*.md` +
  `docs/design/*.md` + 源码 + 测试。
- 提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- 不提交密钥。**A1 之后这条多一层意思**：群私钥进数据库，所以数据库文件与它的备份也按
  密钥对待，不随日志、不随 bug report 外发。
- 当前基线：`ff129d8`（`19b23c3` 之后只有一次纯文档提交），`npm run typecheck` 通过，
  `npm test` = 213 + 693 + 3 + 629 = **1538** 全绿（按 workspace 顺序：cli / core / e2e /
  service）。**更正一处**：本文件原先记的 `209 + 693 + 3 + 624 = 1529` 里，第一个数抄的是
  CLI 更早的 209——在 `19b23c3` 上它就已经是 213，所以那一行的真值是 1533。服务端
  624 → 629 是 B1b-A1 的五条（storage 四条 + handler 一条）。
