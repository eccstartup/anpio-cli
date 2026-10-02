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

**这三件都没有在真跨域的环境里跑过。** 转发测试里的"对端"是一个 stub：它回答"文档指向我"
或"文档指向别处"，不真解析、不起第二个服务；`packages/e2e/src/harness.ts:7` 更是明写了
本用例用不到 `relay`。所以下一轮最该做的不是加功能，是**把两台服务真的连起来**（§A3）。

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
- **A3 两台服务真连一次（新）。** 起两个 `AgentXAgent`（两个域，各带 https 或 dev-host 口
  子），让 A 域的 agent 对 B 域命名空间里的群发 `group.send`，验三件事：转发真的发生、
  B 域签的回执**在 A 域**用 B 域发布的群文档验得过、A 域本地一个群行都没落。这是把 A4 / A5
  的 stub 测试换成正链路的那一步，落点就是 `packages/e2e`——它已经是"真 HTTP、真签名"的包，
  今天只差 `relay` 那一半接线。

---

## B. P6 / 群 E2EE（等上游，或等你定）

- **B1 P6 不得对外声明**，直到上游公布稳定的 MLS `ExtensionType` code point。扣留仍在
  `capabilities.ts` 的 `WITHHELD_PROFILES`（`capabilities.test.ts` 钉住"只有这一条"）。
  **上游公布后**：移除扣留、把 P6 放进 `anp.get_capabilities` 的稳定 Profile 列表，并复核
  [e2ee-group.md](docs/design/e2ee-group.md) §13 的门禁描述。
- **B2 客户端侧群 MLS 的密码学库。** TODO1 D4 已定"内嵌进 `connectx`"（Rust crate → Node 的
  napi 绑定，与官方 SDK 同向）。v1 不受影响，但要真跑群 E2EE 就得写。**需要你定什么时候开。**

---

## C. 只剩部署动作的（TODO2 A7 的尾巴）

- **C1 让 fork 真的接受"端点指向别处"的文档。** 代码已经就位——fork 的 `adc796c` 新增开关
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE`（默认 `False`，只查形状、不要求等于服务器
  自己）。缺的是运维侧一步：**在需要接受对端声明端点的那台服务器上设
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE=1`。** 不设它，一份指向本服务的带 P6 能力文档
  在那台服务器上仍然发布不出来（`signed_did_document_service_endpoint_mismatch`）。
- **C2 `serviceDid` 自己那份文档仍由 awiki 托管。** 与 C1 同源——外层 `keyid` 的 fragment
  必须与发布方写进去的一致（federation.md §4 第 2 点）。本轮发布的是**群**文档，服务自己的
  身份文档不在内（[TODO3.md](TODO3.md) §C3）。要不要把它也收回来自己发，等群这一轮在真
  环境里验过再定。

---

## D. 台账卫生（没划但已落地）

- TODO2 的 **A3 父条**（对端身份状态的同步）没有划掉，但它下面的 A3a / A3b / A3c（含
  A3c-1…4）**全部**已落地并各自划掉。父条本身不是待办，只是当时忘了划。

---

## E. 工程（沿用 TODO3 §D）

- 每段一次提交，格式 `feat(service): <摘要> (TODO4-<段号>)`，同时动 `TODO4.md` +
  `docs/design/*.md` + 源码 + 测试。
- 提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- 不提交密钥。**群私钥在数据库里**（B1b-A1），所以数据库文件、它的备份，以及任何"把 db
  发过来看看"的调试，都按密钥对待。
- 当前基线：`fd02df4`，`npm run typecheck` 通过，`npm test` = 213 + 695 + 3 + 652 = **1563**
  全绿（按 workspace 顺序：cli / core / e2e / service）。
