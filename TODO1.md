# TODO1 —— 活动台账

设计文档见 [docs/design/](docs/design/)。本文件只记**还剩什么**，做完的划掉。

---

## A. `packages/core` —— 裁剪与新增

- A1 从 `anp-sdk` 搬候选模块进来（清单见 [vendored-core.md](docs/design/vendored-core.md) §2/§3），**先不删**
- A2 删 ZK：`core/zk/*`、`src/zk.ts`、CLI 侧 `zkstore.ts` / `auth.ts` 的 `--zk` 段 / `help/commands.ts` 的 `ZK` 组
- A3 复核 §3 那四个「保留但需复核」模块：`tsc --noEmit` 反向收敛，没人 import 的删掉
- A4 **新增 `core/message/`**：`envelope.ts` / `sign.ts` / `verify.ts` / `discovery.ts` / `idempotency.ts`
- A5 把 `sign` / `verify` 共用的 JCS 规范化抽到一处，**确认只有一份**
- A6 **新增 `core/message/locator.ts`**：`ServiceLocator` / `KeyResolver` / `TrustAnchor`
  （[vendored-core.md](docs/design/vendored-core.md) §6 的口子）。v1 只实现 DID 那一个
- A7 全仓 grep `resolveDidDocument` 的**直接调用点**，一律改走 locator / resolver

## B. `packages/cli` —— connectx

- B1 从 `anp-sdk/packages/cli` 搬 `cli.ts` / `help/` / `commands/{auth,did,agent}.ts` / `identity/`
- B2 删 `project.ts` / `generate/` / `template/` / `templates/`，清掉 `@clack/prompts` + `jiti` 依赖
- B3 `help/commands.ts` 加 `msg` / `group` **两族**（页面数据，见 [cli.md](docs/design/cli.md) §3）
- B4 `msg send`：发现 → 构造 → 签名 → POST → 报错，全链路
- B5 `msg caps` / `msg inbox` / `msg show` / `msg read`
- B6 `group` 六条命令
- B7 `msg` 族拒绝账户 id，错误码 `caip10_has_no_ingress`——**拒绝点在 locator 层，不在命令层判断**
- B8 对端不支持扩展面时报 `unsupported_extension`（不是模糊失败）
- B9 **`msg listen`**：WebSocket 连接 + 补齐 + 实时渲染 + 重连退避
  （契约全在 [realtime.md](docs/design/realtime.md) §7）
- B10 `msg listen` 的两套渲染器：TTY 人类可读 / 非 TTY 或 `--json` 出 NDJSON，
  复用 `login-view.ts` 的既有模式
- B11 `msg listen --once`（等价 `msg inbox`）与 `SIGINT` → exit 0

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

- D1 包名：`@agentx/core` / `@agentx/cli` / `@agentx/service` 是否可用
- D2 P6 发布前置：MLS `ExtensionType 0xF0A1` 的 IANA 注册（不在本仓库，但会挡住 P6）

~~D1 命令面分两族~~（2026-10-01 定：分 `msg` / `group`）
~~D2 `msg listen` 进不进命令面~~（2026-10-01 定：做，按 IM 模型设计，见 realtime.md）
~~D3 CAIP-10 当消息收发地址~~（2026-10-01 定：v1 不做，留口子，见 vendored-core.md §6）

## E. 工程

- E1 仓库脚手架：`package.json` workspace + `tsup` + `vitest` + `tsconfig`（照搬旧仓库形状）
- E2 命令面门禁：把 `help.test.ts` 那两条不变量（「页面写出的旗标集合 ＝ 它接受的集合」
  「页面声明的参数 ＝ 它的 usage 行」）一起搬过来
- E3 **加的评审清单**：CLI 与服务端里**不得出现 `isDid()` 之类的身份类型分支**
  （[vendored-core.md](docs/design/vendored-core.md) §6.3）
- E4 端到端：`connectx msg send` → `AgentXAgent` → `connectx msg listen` 收到
