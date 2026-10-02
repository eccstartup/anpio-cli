# TODO2 —— 第二轮台账

接 [TODO1.md](TODO1.md)。TODO1 是"把 P1–P6 做出来"，到 `3e3747b` 为止 C1–C13 全部落地。
本文件记两件事：**C13 端到端实测暴露的、需要你裁定的问题**，以及 **TODO1 里还没划掉的部分**。
设计文档仍在 `docs/design/`。

---

## 0. C13 端到端实测（结论留档）

（口径：**ANP 1.2 已发布**，不再是 vNext。本文件原先写的"vNext 文档"即 1.2 文档，已改过来；
规范里的 profile 名仍是 `.v2` 那一套，两者说的是同一版。）

**方法**：拿 `awiki-open-server`（用户改过的版本，`http://127.0.0.1:8765`）当 DID 服务器，
真注册一份 1.2 单设备文档（root + 设备签名钥 + 设备 E2EE 钥），再让**本服务的解析器**发真
HTTP 取回它、验 e1 文档证明、按 `allowInsecureTransport` 那条联调口放行，最后用**真签的**
`origin_proof` 打真方法。脚手架脚本跑完已删（它靠改模块常量取巧，不该当测试留在仓库）。

**两跑对比**：

| 方法 | 现状（不改任何东西） | 隔离（仅替掉下面 (a)(b) 两件事） |
| --- | --- | --- |
| `group.create`（P4） | 3008 the origin proof did not verify | **200 OK**，拿到 `group_did` |
| `publish_key_package`（§8） | 1017 …#dev-1 does not declare `anp.group.base.v2` | **200 OK** |
| `group.e2ee.create`（§9） | （没走到） | **200 OK** |

**结论**：除了 (a)(b)，P6 的受理链路上**再没有别的东西挡着**。顺带证到一件有价值的事——
KeyPackage 的 `did_wba_binding` Object Proof 由设备自签，验证侧从**服务器发回来的那份文档**
里取公钥，验过了；说明 `bindingProblem` 与"从 DID 文档取钥"这条路对真实服务器输出是通的。

---

## A. 需要裁定的（按要紧程度排）

- ~~**A1 core 的指纹绑定管得太宽 —— 最要紧，P6 在真实 DID 网里跑不起来的直接原因。**
  `packages/core/src/crypto/resolveDid.ts:1100` 在解析**任何** keyid 时都
  调 `assertFingerprintBinding`（定义在 `packages/core/src/crypto/resolveDid.ts:1236`），
  要求解析出的那把钥的指纹等于 DID 路径段里的 `e1_`。可 1.2 单设备文档里，`e1_` 承诺的是
  **root** 钥，设备签名钥是另一把。于是 `${did}#dev-signing` 一律解析失败：
  `binds fingerprint "e1_…" but the resolved key's fingerprint is "e1_…"`。
  而 P6 §6.4 要求 origin proof 由设备的 `signing_key_id` 签——**今天本服务无法验证一台合规
  设备的 P6 调用**。这是一条审计驱动的安全控制（ANP-2026-09-11-01），动它就是动安全边界。
  选项：(i) 放宽成"只对文档自身证明用的那把钥绑指纹，其余 keyid 只要求被关系授权"；
  (ii) 保持现状，在文档里记成已知限制。**建议 (i)**，但需要你拍板。~~
  （2026-10-02 按 (i) 落地，`7028711`：只有"active e1_ 文档、证明策略为 required、且 keyid
  点名的不是那把证明钥"这一档才免掉整体绑定。免掉的底气是文档自身的证明——`assertDocumentProof`
  已经要求并以指纹绑定的那把钥验过它，其后取到的方法属于一份**已被认证的文档**，
  `assertAuthenticationAuthorized` 照旧把它限在 `authentication`。其余各档——`k1_` 或认不出
  的 profile、过渡态的 deactivated 文档、不带 fragment（按位选方法而非按名）的 keyid、
  以及证明钥自己——一律保持严格整体绑定。）

- **A2 设备 profile 集合两边对不上。**
  `packages/service/src/rpc/groupE2ee.ts:144` 的 `GROUP_E2EE_DEVICE` 要
  `[core.binding.v1, identity.discovery.v1, group.base.v2, group.e2ee.v2]`——与规范 §4.2
  （spec 第 10 行、256–258 行）**逐字一致**。但 SDK 的 Manifest builder 只肯发布"全 v1 基础
  \+ `group.base.v1`"或"全 v2 基础 + `group.base.v2`"（四个 v2 基础 profile 是只读草案，
  服务器拒绝发布）。实测两个方向都试过：交 v1 组 → 服务器收、我方拒（缺 `anp.group.base.v2`）；
  交全 v2 组 → 服务器收、我方拒（缺两个 v1）。**服务器今天发不出任何一份能过我方资格门的
  文档。** 选项：(i) 我方迁就 SDK 改成 `group.base.v1`（与规范字面不符）；(ii) 推 SDK 侧让
  v2 基础 profile 可发布。**建议 (ii)**——(i) 是让实现去迁就一个上游的临时限制。

- **A3 对端身份状态的同步（换设备、换 DID、DID 服务器已更新而我们没同步）。**
  用户 2026-10-02 裁定：**换 DID 与绑定新设备都必须支持**——新绑的设备能收群消息，被取代的
  旧 DID 不能再收；并点名要想清楚"DID Server 更新了但 ANPMessageService 没同步"这一档。
  另裁定：同步走**定时刷新**，但要低负载。
  分三段，A3a 已落地：

  - ~~**A3a 一份共享的 DID 文档缓存 + 可配 TTL。**~~
    （2026-10-02 落地，`8d3bdef`：受理、投递、出站共用 `config.didResolution.documentStore`，
    `AGENTX_DID_CACHE_TTL_MS` 默认 5 分钟。不配它，一次投递会把同一份文档抓两遍——`discovery.ts`
    找入口与 `devices.ts` 读清单各调一次 `resolveDidDocument`。它同时就是"对端身份变化的发现
    时延上界"：ANP 不为文档变化提供推送（P2 §5.5 规则 8），窗口封不到零，只能封成一个部署
    能声明的数。缓存不放松判定——core 不写、也不读出 `deactivated` / 带 `successorDid` 的文档。）
  - **A3b 投递前复核设备资格。** `delivery/deviceQueue.ts:132` 的 `deliverable()` 只读自己那
    两张投影表（`group_leaves` / `group_members`），**从不回看对方的当前文档**，所以一台被主人
    从清单里删掉的设备会**继续收到群密文**；而 P6 §10.4 L1074 逐字要求 Host "MUST stop
    authenticating and **delivering new service data to the revoked device**"。
  - **A3c 换 DID。** 今天完全没有：`member_did` 在 `group_members` / `group_leaves` 的**主键**
    里，成员的 DID 改不了（只能删一行加一行）；P4 §8.12 的 `member-did-updated` 本服务的 P4
    （C9）没有接受，`group_did_updates` 因此没有写入者。换 DID 的验证侧 core 已经写好
    （`packages/core/src/did/chain.ts` 走完转移链并给出四档保证），服务端缺的是调用它、按保证
    档位决定接受，再按 P6 §10.5 编排（暂停 → 逐设备 add 新 DID → 逐设备 remove 旧 DID → 恢复）。

- **A4 同 DID 的 Remove 分支 v1 不做，回 5003。**
  理由写在 `packages/service/src/rpc/groupControl.ts:52`：该分支的前置是
  "目标设备已撤销/已失去资格"这个**否定**结论，而本服务是**肯定**门禁；且它还要 Host 验"发送
  设备有当前设备管理授权"，P2 清单里没有这个概念可读（只有 `signingAuthorizedBy` /
  `e2eeAuthorizedBy` 两个关系）。这是**收窄不是放行**（该拒的仍拒），但那条合法路径暂时不可用。
  选项：接受 v1 缺失，或补一个"否定门禁"的表达。

- ~~**A5 两个有界保留闸门是 worker 选项，不是 Config 设置。**
  `maxAttempts` 默认 8（`packages/service/src/delivery/deviceQueue.ts:49`）、
  `maxQueueAgeMs` 默认 24h（`packages/service/src/delivery/deviceQueue.ts:55`），
  今天要调只能改代码。选项：提升到 `Config` 做成部署档位。**建议提**（运维会想调）。~~
  （2026-10-02 落地，`ec4e273`：`AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS`（缺省 8）与
  `AGENTX_DEVICE_QUEUE_MAX_AGE_MS`（缺省 24h），解析口径与其他数值设置一致——空值当未设、
  非正整数在启动时拒绝而不是悄悄钳住。worker 选项保留作覆盖，测试仍可钉住某一条上限。）

- **A6 §12.6 第 3 项"投递前复核"的判据。**
  规范这句没给判据，现取"每次尝试前重跑资格检查，仅点名的那两个例外放行"（在
  `deviceQueue.ts`）。这是我定的读法，可复核。

- **A7 服务器侧的部署结论（不是我们的 bug，但挡住真实部署）。**
  `awiki-open-server` 只肯发布 `ANPMessageService` 端点指向**它自己**的签名文档，否则
  `signed_did_document_service_endpoint_mismatch` / `..._service_did_mismatch`。所以一份指向
  我们服务的、带 P6 能力的文档，今天**没法在那个服务器上发布**。要真实部署落地，这条得服务器侧
  放开——需要你去跟那边定。

**A1 与 A2 是前置**：这两个不定，P6 在真实 DID 网里跑不起来，其余几条都只是能力边界。

---

## B. 承接 TODO1 未划掉的

- **B1（= TODO1 C11 尾）** `group.*` / `attachment.*` 两族的**跨域出站**判断——今天落本地、
  响亮失败。两族的锚点各异（P8 §3.2），接口留在 `dispatch.ts` 的 `relayFor`。
  另有 C11 记的"挡住 v1 的"两条：群 DID 文档没人发布（§5.2 L220 要求解析 `group_did` 才能
  找到 Host）；`serviceDid` 文档由 `awiki-open-server` 托管，外层 `keyid` 的 fragment 必须与它
  写进去的一致（与 A7 同源）。
- **B2（= TODO1 E4，端到端）** `connectx msg send` → `AgentXAgent` → `connectx msg listen` 收到。
  今天 P4/P5/P6 都是**方法级**测过、**没串起来端到端跑过**。A1/A2 定了之后，这条应该顺带把
  P6 也串进去。
- ~~**B3（= TODO1 A7 尾）** `packages/service` 里不得直连 `resolveDidDocument`——消息定址一律走
  `ServiceLocator` / `KeyResolver`。core 里那 5 处与 CLI 那 2 处是 ANP-02/03/04 自己的解析，
  **留着**，只有 service 这一侧要收敛（E3 的评审清单钉这条）。~~
  （2026-10-02 核过：`packages/service/src` 里 `resolveDidDocument` / `resolveDidChain` **零处**，
  全部经 `ServiceLocator` / `KeyResolver` / `DeviceResolver`。这条是早期收敛留下的结论，今天
  不需要改动。）
- **B4（= TODO1 E2 缺口）** `help.test.ts` 的第三条门禁读 `skill/connectx/SKILL.md`，而那份
  skill 没搬过来，已随删除记录。要搬 skill 就把它一起恢复。
- ~~**B5（= TODO1 E3）** 评审清单：CLI 与服务端里**不得出现 `isDid()` 之类的身份类型分支**
  （[vendored-core.md](docs/design/vendored-core.md) §6.3）。~~
  （2026-10-02 审过并修掉唯一一处：`packages/cli/src/commands/auth.ts` 的 `isDidIdentifier`
  用 `didHost` 试一下再决定 `printIdentity` 印 `did:` 还是 `account:`，正是 §6.3 说的"在命令层
  复制一份判断"——[locator.ts](packages/core/src/message/locator.ts) 的 `isDidIdentity` 注释
  已写明那份判定"只在这里使用"。改法是**不由 CLI 判**：`--wallet web3` 这条路径的契约本就要求
  `--address` / `--chain-id`（`buildConnector`），产出的必然是 CAIP-10 账户 id，所以 `document`
  由调用点按自己已知的事实传 `false`，并删掉那个助手。service 侧 `isDid` 零处。）
- **B6（= TODO1 CI）** 仓库里没有 `.github/workflows`，`gh run list` 为空——门禁目前只能在本地
  按 job 分组跑。要真正的 CI 得补 workflow（我可以写，但 `.github/` 那条路径和要不要跑在
  GitHub 上得你定）。
- **B7（= TODO1 E5 剩最后一步）** 文档站的 Vercel 连接要你的账号，我做不了。

---

## C. 下一轮（要新做的）

- **C1 P6 不得对外声明，直到上游给出稳定 code point。**
  见 [e2ee-group.md](docs/design/e2ee-group.md) §13 与 TODO1 D2：MLS `ExtensionType 0xF0A1`
  还是草案私有值，规范说 ANP 在发布 v2 前 MUST 公布稳定注册 code point（§6.3.1 L430、
  §20 L2457）。已落成 `capabilities.ts` 的 `WITHHELD_PROFILES`（`capabilities.test.ts` 钉住
  "只有这一条"）。**上游公布后**：移除扣留、把 P6 放进 `anp.get_capabilities` 的稳定 Profile
  列表，并复核 [e2ee-group.md](docs/design/e2ee-group.md) §13 的那段门禁描述。
- **C2 客户端侧群 MLS 的密码学库。**
  TODO1 D4 已定"内嵌进 `connectx`"（与官方 SDK 同向，官方明写群 MLS 是库调用、不是子进程调用）。
  v1 不受影响，但要真跑群 E2EE 就得写 Rust crate → Node 的 napi 绑定。这是**独立的一块**，
  规模不小，需要你定什么时候开。
- **C3 群 DID 文档的发布路径。**
  §5.2 L220 要求解析 `group_did` 才能找到 Host，而今天没人发布群 DID 文档。这与 A7 是同一类
  问题（谁来托管、托管在哪），要一起定。

---

## D. 工程（沿用 TODO1 的口径）

- 每个 C 任务一次提交，格式 `feat(service): <摘要> (C<编号>)`，同时动 `TODO*.md` +
  `docs/design/*.md` + 源码 + 测试。
- 提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- 不提交密钥。
- 当前基线：`a9e0a68`，`npm run typecheck` 通过，`npm test` 207 + 693 + 581 全绿。
