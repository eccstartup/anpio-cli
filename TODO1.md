# TODO1 —— 活动台账

设计文档见 [docs/design/](docs/design/)。本文件只记**还剩什么**，做完的划掉。

---

## A. `packages/core` —— 裁剪与新增

- ~~A1 从 `anp-sdk` 搬候选模块进来~~（2026-10-01）
- ~~A2 删 ZK~~（2026-10-01：`core/zk/*` + 4 个 zk 测试文件；core 里本就没有引它的地方）
- ~~A3 反向收敛~~（2026-10-01：`tsc --noEmit` 只报一处测试的 `../advanced` 路径。
  另删 `connectors/anpExtension.ts`、`connectors/index.ts`（死 barrel）、`defineConfig.ts`
  （只服务已删除的 `project` 族）。`anpDevShim.ts` **改判保留**，理由见
  [vendored-core.md](docs/design/vendored-core.md) §2）
- ~~A4 **新增 `core/message/`**~~（2026-10-01：`envelope` / `sro` / `sign` / `verify` /
  `discovery` / `idempotency` / `locator`，38 个测试。逐条引 P1 附录 A 与 P2 §7–§9 行号）
- ~~A5 sign / verify 共用同一份 JCS~~（2026-10-01 核过：全仓只有 `crypto/fingerprint.ts`
  一处 `jcsCanonicalize`；`message/sro.ts` 是它唯一的消息层入口）
- ~~A6 **新增 `core/message/locator.ts`**~~（2026-10-01：`ServiceLocator` / `KeyResolver` /
  `TrustAnchor` 三个接口 + `DidServiceLocator` / `DidKeyResolver` 两个实现。
  `caip10_has_no_ingress` 由 `locate()` 抛出——账户 id 与"文档里没有服务条目"是两件事，
  给两个码）
- A7 全仓 grep `resolveDidDocument` 的**直接调用点**，一律改走 locator / resolver。
  2026-10-01 已查：core 里还有 5 处直连（`crypto/wns.ts`、`crypto/agentDescription.ts`、
  `crypto/serverAuth.ts`、`did/chain.ts`、`protocol/anp.ts`），**都留着**——它们是
  ANP-02/03/04/07/08 自己的解析，不是"给消息定址"。账户 id 上没有 handle、没有
  ad.json、没有更新链，硬塞进 locator 只会把两个协议的正确性互相污染。
  `packages/cli` 同理：`commands/did.ts` 里那两处是 `did resolve` / `did update` 读
  一个 DID 自己的文档，属 ANP-02，留。
  **剩下的部分只在 C：`packages/service` 里不得直连**（消息定址一律走
  `ServiceLocator` / `KeyResolver`）

## B. `packages/cli` —— connectx

- ~~B1 从 `anp-sdk/packages/cli` 搬 `cli.ts` / `help/` / `commands/{auth,did,agent}.ts` / `identity/`~~（2026-10-01）
- ~~B2 删 `project.ts` / `generate/` / `template/` / `templates/`，清掉 `@clack/prompts` + `jiti` 依赖~~（2026-10-01：连同 ZK
  一起清干净——`--zk*` 五个旗标、`login-view.ts` 的 `ZkLoginOutcome` / `describeZkSession` / `protocol: 'zk'` 分支、
  `auth.ts` 的整段 `runZkLogin` 与它的属性/描述符助手、`help/commands.ts` 的 Zero-knowledge 旗标组与 `project` 页。
  `SessionWrite` 的 `uncacheable` 与 `LoginCard` 的 `note` / `identity.label` 随之删除：它们的唯一取值来源就是 ZK。
  `packages/cli/package.json` 本就已是 `@agentx/cli` + 四个运行时依赖，无需再改）
- ~~B3 `help/commands.ts` 加 `msg` / `group` **两族**（页面数据，见 [cli.md](docs/design/cli.md) §3）~~
  （2026-10-01：两族共 12 页）
- ~~B4 `msg send`：发现 → 构造 → 签名 → POST → 报错，全链路~~（2026-10-01。含 P1 §10.3 L726 与
  P3 §5.5 L206–208 要求的 `anp.did_superseded` 重试）
- ~~B5 取件三命令 `msg inbox` / `show` / `read`~~（2026-10-01。扩展面的接口定义落进
  [message-service.md](docs/design/message-service.md) §9——之前只有方法名，参数形状要去
  另一个仓库反推，这是断链的根因。定下：扩展面有自己的 Profile `x_agentx.inbox.v1`
  （P1 §6.2.2 L277 要求 `profile` 是 MUST 且是"唯一解释"，规范 Profile 解释不了它）；
  认证走 `origin_proof`；`message.get_batch` 收 `message_ids` 而非 awiki 的 `event_ids`。
  **awiki 的取件面够不着**（它要 bearer，CLI 不持 bearer），cli.md §5 的说法已随之更正）
- ~~B6 `group` 六条命令~~（2026-10-01。`meta.target` 两档（`create` 打服务、其余打群）、
  `--policy` 的形状检查、以及两处刻意留白——不给 `group.add` / `group.remove`、群族不写
  `did_superseded` 重试——理由与出处都在 [cli.md](docs/design/cli.md) §3.4）
- ~~B7 `msg` 族拒绝账户 id，错误码 `caip10_has_no_ingress`~~（2026-10-01：拒绝点确在
  `DidServiceLocator.locate()`，命令层无判断；`caps` 侧有测试钉住）
- ~~B8 对端不支持扩展面时报 `unsupported_extension`~~（2026-10-01：读对端的答复判定，
  `-32601 method_not_found` 与 `1001 anp.unsupported_profile`（Profile 是 `x_agentx.*` 时）
  都映射过去。不先探 `anp.get_capabilities`——扩展本来就不该出现在 `profiles[]` 里，
  探它只能证明"没有"却多一次往返）
- ~~B9 **`msg listen`**：WebSocket 连接 + 补齐 + 实时渲染 + 重连退避~~
  （2026-10-01。契约在 [realtime.md](docs/design/realtime.md) §7；`listen.ts` 19 个测试，
  只注入 socket，握手/游标/退避/解码都是真跑的代码。顺带修了一个已提交的缺陷：
  `inbox` / `show` / `read` 与监听握手都没带 `meta.target`，P1 附录 A.4 L1068 要求
  带 `origin_proof` 的方法必须有它——之前只有 core 的签名器会拦。建模规则写进
  [message-service.md](docs/design/message-service.md) §9.1.1（A.4 L1070 要求 endpoint-local
  方法的 Profile 自己定义），`msg.test.ts` 钉住信封形状）
- ~~B10 `msg listen` 的两套渲染器：TTY 人类可读 / 非 TTY 或 `--json` 出 NDJSON~~（2026-10-01：
  `listen-view.ts`，连接提示一律走 stderr）
- ~~B11 `msg listen --once`（等价 `msg inbox`）与 `SIGINT` → exit 0~~（2026-10-01。另把
  `--since` 的校验提到开 keystore 之前：参数写错不该先付一次口令提示与发现往返）

## C. `packages/service` —— AgentXAgent

- C1 `node:http` 骨架 + `Storage` interface + `node:sqlite` 实现
- C2 Envelope 校验（[message-service.md](docs/design/message-service.md) §3 那张表的每一条）
- C3 Auth：`origin_proof` 验签 + `keyid` 归属 + `authentication` 授权
- C4 幂等（事务内写消息 + 幂等记录），含 DID 取代时的精确重放
- C5 `direct.send` 全流程 + `direct.incoming` 异步推送 + `outbox` 退避重试
- C6 取件扩展面 + 游标（`delivery_cursor`）
- C7 **订阅路**：`GET /anp-im/stream` + 订阅者注册表 + 补齐期间缓冲与背压
  （时序见 [realtime.md](docs/design/realtime.md) §5.2/§5.3）
- C8 `/.well-known/anp-message-service.json` + `x_agentx` 扩展块
- C9 P4 群组 + Group Host（线性顺序 / `group_state_version` / `group_event_seq`）
- C10 P7 附件数据面（Slot → PUT → commit → ticket → GET）
- C11 P8 跨域：`serviceDid` 外层认证 + **caller anchor 单点判断** + 并发投递
- C12 P5 E2EE：prekey bundle + Mailbox
- C13 P6 群组 E2EE：KeyPackage 状态机 + Device Delivery Queue

## D. 待用户裁定

- D2 P6 发布前置：MLS `ExtensionType 0xF0A1` 的 IANA 注册（不在本仓库，但会挡住 P6）

~~D1 包名：`@agentx/*`~~（2026-10-01 定：`@agentx/core` / `@agentx/cli` / `@agentx/service`，用户说后面可改）

~~D1 命令面分两族~~（2026-10-01 定：分 `msg` / `group`）
~~D2 `msg listen` 进不进命令面~~（2026-10-01 定：做，按 IM 模型设计，见 realtime.md）
~~D3 CAIP-10 当消息收发地址~~（2026-10-01 定：v1 不做，留口子，见 vendored-core.md §6）

## E. 工程

- ~~E1 仓库脚手架~~（2026-10-01：workspace + 每包 `tsup` / `vitest` / `tsconfig`；
  `packages/service` 的 `engines` 定 `>=24.16.0`，见 [message-service.md](docs/design/message-service.md) §2。
  2026-10-01 补：`packages/service` 还没有 src，它的 `tsc` 因 `include` 匹配不到文件报 TS18003、
  `vitest` 因没有测试文件退 1，把根 `typecheck` / `test` 一起弄红。改成 `include: ["src", "*.ts"]`
  与 `--passWithNoTests`，C1 落地时把前者收回 `["src"]`）
- E2 命令面门禁：`help.test.ts` 已随 B1 一并搬来（两条不变量都在跑）。
  **缺口**：原文件的第三条门禁读 `skill/connectx/SKILL.md`，而这份 skill 没有搬过来，已随删除
  记录在此——要搬 skill 就把它一起恢复
- **远程未配**（2026-10-01 用户裁定：**先不开远程，继续本地做 CLI**）。本地提交会累积，
  CI 一次都没真跑过；要发版或想跑门禁时再回来开
- E3 **加的评审清单**：CLI 与服务端里**不得出现 `isDid()` 之类的身份类型分支**
  （[vendored-core.md](docs/design/vendored-core.md) §6.3）
- E4 端到端：`connectx msg send` → `AgentXAgent` → `connectx msg listen` 收到
