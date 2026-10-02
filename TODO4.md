# TODO4 —— 第四轮台账

接 [TODO3.md](TODO3.md)。TODO3 的 A 节（B1b，六段）已全部落地——`direct.send` /
`attachment.*` / `group.*` **三族都能跨域**了。本文件记**还剩什么**：让这套机制在真部署里
跑起来缺的东西、P6 的两条，以及 TODO2 里剩的一个部署动作。

口径与 TODO2 / TODO3 一致：ANP **1.2 已发布**，Profile 名仍是 `.v2` 那一套。

---

## 0. B1b 落地后的状态（结论留档）

三件事现在是事实，且 A6 已把与它们冲突的文档改完：

- **三族都接进了中继**（`RELAYED_METHODS`）：`direct.send`、四条 `attachment.*`（B1a）、
  十三条 `group.*`（B1b-A4）。`relayFor` 的规则一行没动——解析 `meta.target.did` 公开的
  `ANPMessageService`，是本服务就本地办完，不是就转发原始方法。
- **群 DID 文档由本服务自己发布**（A2 / A3），路由 `GET …/g/<id>/did.json`，前缀由
  `didToUrl` 推出来而不是写死，所以 `serviceDid` 自带路径段时也对得上。
- **`group_receipt.proof` 一律签**（A5）。唯一例外是没有钥的群（v11 之前建的），而那种群
  没有可发布的文档、不可能跨域。

**这三件当初都没在真跨域的环境里跑过。** 转发测试里的"对端"是一个 stub：它回答"文档指向我"
或"文档指向别处"，不真解析、不起第二个服务；`packages/e2e/src/harness.ts` 的文件头也明写了
本用例用不到 `relay`。所以下一轮最该做的不是加功能，是**把两台服务真的连起来**（§A3）。

**A3 之后这个缺口补上了**（2026-10-02）：`packages/e2e` 起两台真的 `AgentXAgent`，A 域对
B 域命名空间里的群发 `group.send` 全链路跑通，`harness.ts` 的文件头也随之改掉了那一句。
剩下没验的是真 https / 真域名与**外层签名那一半**——两条都记在
[federation.md](docs/design/federation.md) §8 第 4 条。A 节余下的 A1 / A2 是部署侧前提，
不是本仓库的代码。

**顺带更正 TODO2 的一处时态**：A7 里记 fork 的 `adc796c`「**未推**」，已经推到
`eccstartup/awiki-open-server` 了（`main` 跟踪 `eccstartup/main`，无待推提交）。

---

## A. 跨域真正上线缺的

都不是本仓库的代码缺陷，但没有它们，B1b 那套机制在真部署里一次也跑不起来。

- **A1 `did:web` 解析要 HTTPS。** `didToUrl` 对任何 `did:web` 一律给出 `https://`，所以
  `AGENTX_PUBLIC_URL` 是 `http://…` 的部署（**包括仓库默认值** `http://127.0.0.1:8787`），
  它的群 DID 会指到一个没有 TLS 的地址——对端解析必然失败。这不是 bug，是 `did:web` 的固有
  约束，与 `serviceDid` 的约束同源（federation.md §2.5）。本地联调走
  `AGENTX_DID_DEV_HOSTS` / 内联文档那条口。
- **A2 `AGENTX_ALLOWED_DID_HOSTS` 要把对端域加进白名单。** 跨域**接收**时解析对端文档要过
  SSRF 守卫（federation.md §2.5），清单里只有自己的域，一次也解析不了。
- ~~**A3 两台服务真连一次（新）。** 起两个 `AgentXAgent`（两个域，各带 https 或 dev-host 口
  子），让 A 域的 agent 对 B 域命名空间里的群发 `group.send`，验三件事：转发真的发生、
  B 域签的回执**在 A 域**用 B 域发布的群文档验得过、A 域本地一个群行都没落。这是把 A4 / A5
  的 stub 测试换成正链路的那一步，落点就是 `packages/e2e`——它已经是"真 HTTP、真签名"的包，
  今天只差 `relay` 那一半接线。~~

  **落地（2026-10-02）。** `packages/e2e/src/harness.ts` 接上了跨域那半边——`relay` /
  `egress` / 群文档路由，与 `main.ts` 逐行对应，收在一个 `crossDomain` 开关后面，单服务
  世界的行为一字不变；新增的 `startFederatedWorld()` 起两台服务（同一台机器、两个端口，
  `serviceDid` 分别是 `did:web:127.0.0.1%3A<port>`）。新用例
  `packages/e2e/src/groupFederation.test.ts` 让 alice（A 域）对 B 域命名空间里的群发
  `group.send`，三件事都验到了：**转发真的发生**（B 有群行、名册、消息行，正文原样过境）、
  **B 签的回执在 A 域验得过**（用从网络上取回来的那份 B 域群文档跑
  `verifyObjectProofDetailed`）、**A 域一条群行都没落**（群行 / 名册 / 消息行都是零；A 这一侧
  只写幂等台账）。顺手做了一次变异验证：把 A 的 `crossDomain` 关掉，用例立刻红在第一处断言
  ——它验的是真的那一跳。

  两处**故意没走**的东西，写下来免得被读成"忘了"：

  - **没用 `connectx group send`。** 那条命令解析群 DID 之后直接把请求 POST 到群自己的域
    （`groupChannel` → `discover(groupDid)`），这是 P2 §9.2 的地址发现，走不到中继。中继要的
    是"请求打到了 A、目标却在 B"，所以用例手工搭了一个指向 A 的 `Channel`，而 `call` /
    `senderFor` / `policyFor` 三个真客户端件照用——它们是客户端那一侧要被验的部分。
  - **没走外层签名。** `egress` 的 `keyid` 必须指着本服务自己的 DID 文档，而那份文档不在本
    服务手里（§C2，仍由 awiki 托管），e2e 里没有一处能解析出它，签了也验不过。P8 §2.3 对
    不带外层身份的调用方的处置本来就是"按本地调用处理"，业务层的 `origin_proof`（由 alice
    真签）照旧是唯一的授权依据。外层那半有它自己的方法级测试。

  没验到的其余部分（真 https / 真域名、跨机器）记在
  [federation.md](docs/design/federation.md) §8 第 4 条——那里也是这一条落地后唯一需要改的
  设计文档。

---

## B. P6 / 群 E2EE（等上游，或等你定）

- **B1 P6 不得对外声明**，直到上游公布稳定的 MLS `ExtensionType` code point。扣留仍在
  `capabilities.ts` 的 `WITHHELD_PROFILES`（`capabilities.test.ts` 钉住"只有这一条"）。
  **上游公布后**：移除扣留、把 P6 放进 `anp.get_capabilities` 的稳定 Profile 列表，并复核
  [e2ee-group.md](docs/design/e2ee-group.md) §13 的门禁描述。
- **B2 客户端侧群 MLS 的密码学库。** TODO1 D4 已定"内嵌进 `connectx`"（Rust crate → Node 的
  napi 绑定，与官方 SDK 同向）。v1 不受影响，但要真跑群 E2EE 就得写。**需要你定什么时候开。**

---

## ~~C. 只剩部署动作的（TODO2 A7 的尾巴）~~ 按职责切开后不是问题

**2026-10-02 用户裁定，本节一次收口。** 口径是：**DID server 与 ANP message service 是两个
职责不同的服务**——前者**只管身份**（它唯一的产物就是身份文档），后者**承载社交应用**（今天
是聊天，将来可以是别的）。C1 / C2 原先读起来像"两面都不太对"的接缝，其实是**两层的输出**
被放在一起看了。切开之后两条都划掉。

- ~~**C1 让 fork 真的接受"端点指向别处"的文档。**~~ **归 DID server 自己的策略，而且那条
  策略本就混了两层。** 一份身份文档里的 `ANPMessageService` 条目指向哪个消息服务，是**身份
  所有者**的声明（"我的消息走这一家"），DID server 的职责只是把这条声明签进身份文档——
  awiki 原先那两条"必须等于服务器自己"的相等检查，恰恰是替身份所有者做了这个决定、把身份层
  与消息层焊在了一起。fork 的 `adc796c` 新增开关
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE`（默认 `False`）把两层拆开，方向是对的。

  **本仓库这一侧不需要任何改动。** 本服务与 DID server 的接口只有一个：
  `GET /.well-known/anp-message-service.json` 交出的那段 JSON
  （[message-service.md](docs/design/message-service.md) §13），DID server 拿它去嵌自己的
  文档。这条接口在 C11 就已经是现在这个形状，与本次裁定一致。**剩下的是部署侧一行配置**：
  在一台要发布"消息端点指向别处"的文档的 DID server 上设
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE=1`。不设它，那台服务器仍然只发布端点指向它
  自己的文档（`signed_did_document_service_endpoint_mismatch`）——这是**那台服务器的部署
  选择**，不是本服务缺什么；挑 DID server 本来就要挑一家肯照着你的声明签的。
- ~~**C2 `serviceDid` 自己那份文档仍由 awiki 托管。**~~ **裁定：就这样，是分层不是缺口。**
  身份文档是 DID server 的输出，本服务不发布它；本服务发布的是**消息层**的文档（群文档，
  [groups.md](docs/design/groups.md) §2）。所以外层 `keyid` 的 fragment 由发布方决定、本服务
  用 `AGENTX_KEY_ID` 配成一致——**这不是一处待补的耦合，就是"身份归身份层"这件事本身**
  （[federation.md](docs/design/federation.md) §4 第 2 点）。[TODO3.md](TODO3.md) §C3 里那句
  "要不要把后者也收回来自己发"到此有了答案：**不收。**

  **唯一因此存在的技术后果**已经记在 §A3 的"故意没走"第二条里：`packages/e2e` 走不到外层
  签名那半——`egress` 的 `keyid` 得指着本服务自己的身份文档，而那份文档不在本服务手里。这
  本来就是 P8 §2.3 允许的一档（不带外层身份 → 按本地调用处理，业务层 `origin_proof` 照旧
  唯一授权），不是留了个洞。

---

## ~~D. 台账卫生（没划但已落地）~~

- TODO2 的 **A3 父条**（对端身份状态的同步）没有划掉，但它下面的 A3a / A3b / A3c（含
  A3c-1…4）**全部**已落地并各自划掉。父条本身不是待办，只是当时忘了划。**2026-10-02 已
  补划**：[TODO2.md](TODO2.md) 里那条父标题划掉了，并写明它从来不是待办、子段各自何时落的。
  这一条没有代码，改的只有两份台账。

---

## E. 工程（沿用 TODO3 §D）

- 每段一次提交，格式 `feat(service): <摘要> (TODO4-<段号>)`，同时动 `TODO4.md` +
  `docs/design/*.md` + 源码 + 测试。
- 提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- 不提交密钥。**群私钥在数据库里**（B1b-A1），所以数据库文件、它的备份，以及任何"把 db
  发过来看看"的调试，都按密钥对待。
- 当前基线：A3 之前最后一次代码提交是 `fd02df4`；A3 之后 `npm run typecheck` 通过，
  `npm test` = 213 + 695 + **4** + 652 = **1564** 全绿（按 workspace 顺序：cli / core / e2e /
  service；e2e 从 3 到 4 就是本条的新用例）。
