# TODO1 —— 活动台账

设计文档见 [message-service.md](docs/design/message-service.md)（九份都在 `docs/design/`）。本文件只记**还剩什么**，做完的划掉。

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

- ~~C1 `node:http` 骨架 + `Storage` interface + `node:sqlite` 实现~~（2026-10-01。
  `config.ts` 按 §14 逐项（含 `did:web` 推导，以及非 loopback 监听时拒绝凭空推 public URL）；
  `storage/{schema,types,sqlite}.ts`；`http/server.ts` 只做路由与读体，分派留在 `handleRpc`
  接缝后（C2 起），所以 `main.ts` 现在对每个合法请求回 `-32601`——是"还没做"，不是"做错了"。
  48 个测试；E1 里 `include` 收回 `["src"]`、`--passWithNoTests` 一并撤掉。
  三处结论进了设计文档：[message-service.md](docs/design/message-service.md) §2.1 新增
  路由与状态码表（**规范不规定 HTTP 状态码**，一律 200 的理由是自家客户端对非 2xx 直接抛错）；
  §7 改 `idempotency` 键（草案的五列 PK 装不下 §9.1 L639 要求的设备 selector，改为存 core
  `idempotencyKey()` 的字符串）并补 `deliveries` 表。另：`tsup` 加
  `removeNodeProtocol: false`——`node:sqlite` 没有裸名字，tsup 默认去前缀会把它变成
  import 一个叫 `sqlite` 的第三方包）
- ~~C2 Envelope 校验（[message-service.md](docs/design/message-service.md) §3 那张表的每一条）~~
  （2026-10-01。校验本身全在 core 的 `parseEnvelope`（B 线已做），`rpc/envelope.ts` 只补
  CLI 用不到的两件：进来的是**文本**，以及每个失败都要带正确的 `id` 出去。
  `ParsedRequest` 是 `AnpRequest | AnpNotification` 的联合，但 `AnpRequest` 结构上是
  `AnpNotification` 加一个 `id`——所以 `isNotification` 这个类型守卫在否定分支会把联合收成
  `never`，判别一律用 `'id' in value`（`envelope.ts` 里写了原因，`main.ts` 与测试都照做）。
  §3 表里有两行**不在这里**，它们要方法自己的声明而不是信封：target 建模模式（§6.2.5.1 L382）
  与 §7.3 L491–499 的十进制字符串计数器，随 C5 的方法表一起来）
- ~~C3 Auth：`origin_proof` 验签 + `keyid` 归属 + `authentication` 授权~~（2026-10-01。
  验签主体是 core 的 `verifyOriginProofDetailed`（`resolveDid.ts:1120` 查 `authentication`），
  `rpc/auth.ts` 补服务端才需要的三件：算锚点、把失败翻成规范错误码、把时间窗一起判掉。
  锚点＝**一个** `callerAnchor()`：普通方法取 `meta.sender_did`，群通知取 `body.group_did`，
  群身份缺失时**不回落**到 `sender_did`（回落就等于谁都能冒充群）。错误码**由方法表给**
  ——P1 只有 1005，P3 §11 L599–600 拆成 2005/2006，所以 `authenticate()` 收一对码。
  时间窗只认 proof 自带的 `expires` 与跑在前面的 `created`，**不加**年龄上限（P1 §13.2 L816
  把防重放交给 Profile，本服务里就是 C4 的幂等记录）。失败分类**不上线**，只回给服务记日志
  （逐条答出去就是 keyid 授权状态的 oracle）。20 个测试，用 `DidKeyResolver` + 内联文档跑
  真签名——`DidKeyResolver` 原先一个调用点都没有，这是它的第一个。
  顺带修了 core 两处：`AnpRejection.anpCode` 原先是 `AnpErrorCode` 封闭联合，而 P1 §10.3
  只固定公共段，Profile 自己的码（2005）根本写不进去，改成开放的 `AnpErrorName` 并加
  `profileRejection`；`VerifyOriginProofInput.auth` 改成可选——函数体本来就写着
  `input.auth?.scheme`，缺 `auth` 是 `scheme_unsupported`（P3 L390 与"无效"同码），
  不是调用方的类型错误）
- ~~C4 幂等（事务内写消息 + 幂等记录），含 DID 取代时的精确重放~~（2026-10-01。
  `rpc/accept.ts` 的 `acceptOperation()`：查表 → 干活 → 记结果，全在一个事务里；
  判定用 core 的 `idempotencyVerdict`。**`perform` 只在未命中时被调用**，
  于是 §9.1 L641 的"以 DID 已被替代拒绝之前先查旧 DID 记录"变成结构性保证，
  不靠调用方记性。`Storage` 加了可重入的 `transaction()`（SQLite 不许嵌套 `BEGIN`，
  而原子单位是"一次操作"、访问器各自又要能单独用），`busy_timeout` 从 node:sqlite
  默认的 0 改成 5 秒——抢不到锁立刻报错的话，`BEGIN IMMEDIATE` 的串行化就是空的。
  另把幂等记录存的东西说清楚：存**操作结果**不存信封（重试带自己的 `id`）。
  11 个测试。同一批把 core 幂等模块里那串**过期的行号**修了——它引的是旧版 P1 §9，
  最大一处把 L641 写成"L646–648"，而那里是 §9.2 的重试清单一角）
- ~~C5a `direct.send` 受理路径：方法表 + 认证接线 + DID 解析策略~~（2026-10-01。
  `rpc/methods.ts`＝`MethodSpec` 数据表 + `checkMethod`（Profile / security_profile / 必填字段 /
  `target.kind`；§6.2.5 L341 + §6.2.5.1 L377–380 + A.4 L1068 取并成一条
  `needsTarget = targetMode !== 'endpoint-local' || requiresOriginProof(meta)`，
  `kind` 不符回 §10.3 L722 的 1014，缺 target 回 1003——规范列了拒绝、没给码，取舍记在
  §8.1）。`rpc/direct.ts`＝正文互斥 + 落库 + 消息级重复识别；`rpc/dispatch.ts`＝
  `createDispatch()`，层序 parse → 方法表 → 认证 → 正文 → `acceptOperation`，理由在 §8.1。
  `config.ts` 补 DID 解析策略：`AGENTX_ALLOWED_DID_HOSTS` 默认空＝只认内联文档，
  `AGENTX_DID_DEV_HOSTS` 是联调放宽（同时进白名单、允许私有地址与明文 http）。
  存储顺手修了一处**设计缺陷**：`messages` 主键原为 `message_id` 单列，而 §8.2 L444–450
  给消息级重复识别定的三元组才是键——那个标识是发送方自己起的（P1 §6.2.7 L402），撞名合法，
  旧主键会把本该正常受理的第二次发送变成 500。同批 `outbox.endpoint_uri` → `recipient_did`
  （重试必须重新解析，钉住的 endpoint 可能已失效），两者合一个 v2 迁移。148 个测试）
- ~~C5b `direct.incoming` 异步推送 + `outbox` 退避重试~~（2026-10-01。受理路径只在
  `outbox` 落一行，推送归 `delivery/worker.ts`——事务里不能有网络往返。core 补
  `buildMessageNotification()`（**没有 `id`**，§5.3 L162 让通知不能是 Request）与
  `postNotification()`；两者共用 `resolveDid.ts` 抽出的一条受控交换，**读体仍在超时
  定时器之内**（返回 `Response` 再清定时器，等于给对端一个慢速 body 就能越过
  `timeoutMs`）。推送目标每次重新解析（`recipient_did` 而不是钉住的 endpoint）；
  解析出来就是本服务端点时**不作 HTTP**——`deliveries` 那行已经持久，C7 会交出去。
  退避数值是本实现的选择，依据 P3 §8.4 L477。§7.3 L491–499 的十进制字符串仍留给 C9；
  §5.5 L208 的"target 已被替代"仍缺连续性来源。一处**规范内部张力**记进
  §8.2：A.3 L1046 让 SRO 只含 `method`，而 §7.2.3 要求转发后除 `method` 外逐字段相同，
  A.6 L1136 又要求按**当前请求的** `method` 重建——本服务按 §7.2.3 与 A.8 转发逐字节
  不变的原证明，验证留给收件人。164 个测试）
- ~~C6 取件扩展面 + 游标（`delivery_cursor`）~~（2026-10-01。`rpc/inbox.ts`＝四个方法
  `inbox.get` / `inbox.mark_read` / `message.get_batch` / `sync.delta`，线上 Profile 取
  `x_agentx.inbox.v1`，另加一条本服务自己的约束：`meta.target.did` MUST 等于
  `meta.sender_did`，否则 1014（本扩展面没有"代别人读收件箱"）。`MethodSpec` 因此长了
  `validateBody`——C5a 里那句"第二个方法的正文规则出现时就清楚了"说的就是这个。
  `message_reads`（v3）：**已读不是投递游标**，键取 `(owner_did, message_id)`，因为
  `inbox.get` 两个方向都返回而只有 incoming 有投递行；`msg read --all` 递过来的是无界 id
  列表，查它走 `json_each(?)` 而不是 `IN (?,?,…)`。`inbox.get` 按时序归并两个方向
  （两侧各取 `limit+skip` 再排：全局第 k 条必在任一侧的前 k 条里），outgoing 的 `read_at`
  诚实地留 null，于是 CLI 的未读判定**排除 outgoing**——不排的话用户发过的每条都进未读计数。
  `delivery_cursor` 表在 C5a 就建好了，推进它的是 C7 的 `ack` 而不是 `sync.delta`。
  **`direct.get_history` v1 不发**，`since_seq` 没有覆盖出站一半的定义，理由写进 §9.3。
  存储 9 + 派发 13 + CLI 渲染 8 个测试；service 186 / core 666 / cli 206）
- ~~C7 订阅路：`GET /anp-im/stream` + 订阅者注册表 + 补齐期间缓冲与背压~~（2026-10-01。
  两处与 §5.2 字面不同，都是实现逼出来的，理由写在 `stream/registry.ts` 头部：
  **①** 放行按补齐**实际结束**的 `next_since` 过滤，不按注册时的 `H`——`sync.delta` 只认
  `since`+`limit`，注册与补齐之间落库的消息会同时在补齐结果与缓冲区里，按 `H` 刷就是
  重复投递；**②** 序号是**收件箱级**的（`deliveries.seq` 按 owner 递增），游标才按设备，
  所以注册表按 `owner_did` 路由（原 §5.1/§8.1 写成按 `(owner, device)`，已改）。
  两处上限：补齐期按帧数与字节数（§5.3），实时期按 socket 写队列深度——不读与不补齐是
  同一个问题。断连码 1013（"你再来"）对 1001（"我走了"）。
  `stream.ack` 是 `delivery_cursor` **唯一**的写入者，且写前把 `seq` 钳到当前 head：
  `advanceCursor` 只进不退，凭空来的大数会让下一次重连静默跳过真实消息。
  推送在**事务提交之后**（`dispatch.ts` 收集，提交后才交给注册表），事务里推的话一次
  回滚就会让在线客户端看到一封从未落库的消息。
  CLI 侧一个真 bug：`meta.profile` 原来一条连接只给 `x_agentx.stream.v1`，而
  `sync.delta` / `inbox.mark_read` 属 `x_agentx.inbox.v1`，真服务会对整个补齐回 1001；
  测试里的假服务不校验 profile 所以没红——它现在校验了。`--ack` 除 `inbox.mark_read`
  外再发 `stream.ack`；补齐段不 ack（游标只进不退，第一条实时 ack 自然带过，
  且 `--once` 要保持 §7.2 的只读语义）。文档改 realtime.md §4/§5.1/§5.2/§5.5/§6/§8.1/§9
  与 message-service.md §2.1（426）、§9.3。真机冒烟：426、`stream.hello` 首帧、
  带活连接 SIGTERM → 客户端收 1001 且进程 exit 0。service 240 / core 666 / cli 207）
- ~~C8 `/.well-known/anp-message-service.json` + `x_agentx` 扩展块~~（2026-10-01。顺带补了
  `anp.get_capabilities`：它是发现的最后一环（P1 §8.2），设计 §15 第 2 步写着却一直没做
  ——**静态 hint 没有运行时权威对照，就是一张没人核对的清单**。两份清单同源
  （`capabilities.ts` 从方法表推），于是 §8.3 L591–593 的"冲突时以运行为准"永远无事可做。
  它匿名可达（§8.2.1 L543），所以不要 proof；也不要 `operation_id`——§6.2.6 L388 只对会改
  状态的操作要求它，例子里有它，但例子不是规范。扩展**不进** `supported_profiles`：那是
  "规范符合性"的运行时权威。条目里 `serviceEndpoint`/`serviceDid` 来自配置，清单来自方法表；
  `id` 用自己那半边的 DID，**嵌入方要改写**（服务条目住在对方的文档里，§13）。
  `serviceDid` 顺带过一遍 §8.7 L512：它是 DID 不是 DID URL——这个值会写进 DID 文档，也是
  跨域 `keyid` 的解析基准，一个 fragment 会把"这个服务"悄悄变成"它的某个 key"。
  真机冒烟：well-known 200 且三个字段齐、`get_capabilities` 匿名 200、错 Profile 1001。
  service 262）
- ~~C9 P4 群组 + Group Host（线性顺序 / `group_state_version` / `group_event_seq`）~~（2026-10-01。service 305）
  - ~~设计~~（2026-10-01：[groups.md](docs/design/groups.md)。定下的是几个规范没说话的地方——
    `group_did` 形状、群消息不写投递行、3002 没有产生路径、私有群缺省、merge patch 校的是
    合并后的对象、receipt 的 `proof` v1 不签。§7 的 `group_members` 随之补两列，schema 到 v3）
  - ~~九条方法进方法表 + 成员状态机与权限判定 + 群消息 fan-out + `group.state_changed`
    （含被移除者的"最后一封"）~~（2026-10-01。实现与设计共两处修正，都写在 groups.md：
    `group.get_info` 的 proof 取 `(meta) => meta.sender_did !== undefined` 而不是 `false`；
    schema 落 **v4**（v3 已被 `message_reads` 用掉），多两列 `messages.group_event_seq` /
    `group_state_version` 供消息级重放答受理时快照）
- ~~C10 P7 附件数据面（Slot → PUT → commit → ticket → GET）~~
  - ~~设计~~（2026-10-01：[attachments.md](docs/design/attachments.md)。定下的是几个规范没说话
    的地方——票据是不透明令牌、不签名；数据面用真 HTTP 状态码（§2.1 那条"一律 200"在数据面
    不成立）；对象按摘要寻址放文件系统；6007 只从"查不到/一次性票已兑"两条路开口，6004 /
    6011 在 v1 没有产生路径；回环下 `object_uri` 允许 http，这是对 §7.5 L488 那条 MUST
    的显式偏离；同域仍要求 `origin_proof`）
  - ~~四条方法进方法表 + 上传槽状态机 + 两条数据面路由（含 HTTP 层的字节路）+ Grant 建在
    受理事务里（群路径与 C9 共用）+ 票据签发与下载校验~~（2026-10-01。附带的"动手前先修"
    也一并做完：`rpc/direct.ts` 那条被读成等号的规则现在是 `payload.ts` 里的
    `payloadFieldRequiredBy`，单向、`+json` 按后缀收）
  - 还剩一个**产品取舍**待你定：`connectx` 要不要发/收附件的命令（见
    [attachments.md](docs/design/attachments.md) §11）。服务端已满足 §13 L1117–1129 的
    MTI 要求，没有对应命令面也合规——所以这不是阻塞项
- C11 P8 跨域：`serviceDid` 外层认证 + **caller anchor 单点判断** + 并发投递
  - ~~设计~~（2026-10-01：[federation.md](docs/design/federation.md)。定下的是几个规范没
    说话的地方——外层认证按"有没有带 `Signature-Input`"触发；失败回 ANP-02 的 401 + `WWW-Authenticate` 而不是
    §2.1 的 200；**请求同步转发、通知才走 outbox**；`isOurOwnIngress()` 就是"该不该出站"的全部判断；
    重放防护一张 `http_nonces` 表。八步验证与 §6.2.2 的 caller anchor 落到 C3 的同一个 `callerAnchor()`）
  - ~~**动手前先修**：`delivery/worker.ts` 转发的是 `direct.incoming`，而 P8 §5.1 L206–210 要的是
    **原始 `direct.send`**（§6.2.2 L348–368 的跨域方法表里没有 `direct.incoming`），且 P3 §7.2.1 L397
    把它定义成"已被目标 ingress 接受"之后的那一跳——跨域时它语义上不成立。C5b 写的，当时没读 P8~~
    （2026-10-01 拆完：请求在事务外同步转发原始 `direct.send`，对端接受才落库、拒绝什么都不写；
    `direct.incoming` 不再入队，outbox 只剩群通知在写。转发前先查一次幂等记录，重试不再出站）
  - ~~外层八步 + `http_nonces`~~、~~出站签名（`AGENTX_KEY_ID`，配上 `AGENTX_KEY_FILE` 才签；
    没钥就不签，§2.3 说那失去的是域级归属而不是受理）~~、~~非 2xx 读成答复而不是异常
    （core 新原语 `fetchControlledResponse`，两条既有出站函数把非 2xx 读成失败，不能走）~~
  - 还剩：`group.*` / `attachment.*` 两族的出站判断（今天落本地、响亮失败）。两族的锚点各异
    （§3.2），接口留在一个入口 `dispatch.ts` 的 `relayFor`
  - **挡住 v1 的**：群 DID 文档没人发布（§5.2 L220 要求解析 `group_did` 才能找到 Host），
    挡 MTI 第 1/4/5 项；`serviceDid` 文档由 `awiki-open-server` 托管，外层 `keyid` 的 fragment
    必须与它写进去的一致
- C12 P5 E2EE：prekey bundle + Mailbox
  - ~~设计~~（2026-10-01：[e2ee-direct.md](docs/design/e2ee-direct.md)。定下的是几个规范没
    说话的地方——**OPK 池只出不进**（`assigned` 是终态，于是 §6.6 L449 那条"建链成功后标记
    已消费"服务端根本观察不到，被更强的不变量覆盖掉，**不是被忽略**）；`publish` / `get`
    两条幂等键的分工与"幂等记录 + OPK 分配"的原子写；§11.5 的两类重放状态一边一半
    （外层归服务端、init replay 归客户端，因为键含 `session_id`）。不建 init replay 表）
  - 还剩：两条 Key 方法进方法表（`targetScope` 两档不同）+ OPK 池与分配 + `bundle_id`
    不可重定义检查（§6.2.2 L371）+ Mailbox 的设备维度 + 限流（§7.3 L598 是 MUST 的落点）
  - ~~**动手前先留列**~~（2026-10-01 做了：`deliveries.recipient_device_id` 是 schema v7，
    订阅推送按它筛连接——见 [e2ee-direct.md](docs/design/e2ee-direct.md) §4。取件面还没跟上，
    等 `anp.direct.e2ee.v2` 进方法表时一起做）
  - **挡住 v1 的**：无。两条 Key 方法同域即可跑，跨域部分随 C11
- C13 P6 群组 E2EE：KeyPackage 状态机 + Device Delivery Queue
  - ~~设计~~（2026-10-01：[e2ee-group.md](docs/design/e2ee-group.md)。定下的是几个规范没
    说话的地方——**Host 侧唯一的"群状态"是一份不含任何可运算材料的公开投影**（§11.10.3
    L1372），MLS 全在 owner 客户端；Device Delivery Queue 与 P5 的 Mailbox **是同一张表同一
    个键**，别建两张；队列内四种顺序规则（§12.6 L1512）选"把已入队的应用信封投完再发最终
    通知"；`group.e2ee.leaf_not_current`(5013) 的判定序是先 `group.not_member` → 再 core
    设备码 → 最后 5013，**MUST NOT** 折叠（§13.3 L1625）。§12.6 L1500 那句"Host 无法为
    离线设备重新生成信封"是队列不建在历史服务上的全部理由）
  - 还剩：六条方法进方法表（三档 `targetMode`）+ KeyPackage 三态柜子（`group_key_packages`
    的 `state` 列已在 v3）+ `group_leaves` 投影 + Device Delivery Queue 与队列内排序 +
    `group_did_updates` 的暂停/串行化 + 最终 Remove 通知的有界收尾 + `origin_context` 的
    原样保留（§13.6）
  - **动手前先留列**：与 C12 同一条缝（`deliveries` 没有设备列、C7 按 `owner_did` 路由）
  - **挡住 v1 的**：`0xF0A1` 还是草案私有值，规范说 ANP **在发布 v2 前 MUST 公布稳定
    注册 code point**（§6.3.1 L430、§20 L2457）——**决定 P6 能不能对外声明**
    （`anp.get_capabilities` 里不得作为稳定 Profile 出现）；群 DID 文档未发布（同 C11）

## D. 裁定留档

- ~~D2 P6 发布前置：MLS `ExtensionType 0xF0A1` 的 IANA 注册~~（2026-10-01 定：**照抄官方
  SDK 的位置**。Rust crate 已把这条做成显式门禁 `ErrP6V2PublicReleaseBlocked`
  ——"blocked until the draft MLS extension has a stable registered codepoint"
  （`rust/src/group_e2ee/v2_errors.rs:84`；草案值 `v2_models.rs:13`）。**代码可写，
  `anp.get_capabilities` 里 P6 不得作为稳定 Profile 出现**，直到上游公布稳定 codepoint。
  见 [e2ee-group.md](docs/design/e2ee-group.md) §13）
- ~~D4 客户端侧的密码学库放哪~~（2026-10-01 定：**(a) 内嵌进 `connectx`**，与官方 SDK 同向。
  官方明写群 MLS 是"库调用、**不是** `anp-mls` 子进程调用"（`rust/README.md` L33–38），
  且 MLS 只存在于 Rust crate `anp::group_e2ee`（openmls 0.8.0），Python/TS/Dart/Java 都没有；
  Go 侧靠已被移除的一次性二进制驱动，于是 `anp-cli` 群组 E2EE 至今不可用——反面教材。
  代价：TS 侧无现成绑定，`connectx` 要自己写 Rust crate → Node 的 napi 绑定；不影响 v1。
  见 [e2ee-direct.md](docs/design/e2ee-direct.md) §9.1）
- ~~D5 被移除 leaf 已入队的应用信封~~（2026-10-01 用户定：**(a) 按序投完**。用户补一句事实
  ——**已经读到过的消息无法收回**，最终通知只能宣告"你已被移除"。产品取舍，不是技术限制。
  见 [e2ee-group.md](docs/design/e2ee-group.md) §14）

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
- **远程**：`origin` = `github.com/eccstartup/AgentX`，本地 `main` 与 `origin/main` 同步。
  2026-10-01 已不再"先不开远程"（当时只做本地 CLI 阶段）。**但 CI 仍跑不了**：仓库里
  没有 `.github/workflows`，`gh run list` 为空——所以门禁目前只能在本地按 job 分组跑
- E3 **加的评审清单**：CLI 与服务端里**不得出现 `isDid()` 之类的身份类型分支**
  （[vendored-core.md](docs/design/vendored-core.md) §6.3）
- E4 端到端：`connectx msg send` → `AgentXAgent` → `connectx msg listen` 收到
- ~~E5 文档站~~（2026-10-01：VitePress，`srcDir` 指仓库根，所以 README / 本文件 /
  `docs/design/*.md` 是**同一份文件**的两种呈现；`vercel.json` + 根 `docs:dev|build|preview`。
  改到三处**真的断了**的相对链接：`e2ee-direct.md` / `e2ee-group.md` 里 `../TODO1.md`
  少了**一**层目录，`TODO1.md` 指向的是目录不是页面。剩下**只有一步要你做**：在 Vercel 上
  连这个仓库——它要你的账号，我做不了）
- ~~E6 说法对齐 ANP 1.2~~（2026-10-01：README 那张"规范出处"表还停在
  `chinese/vnext/`（`release/0910`），现已按 v1.2 的正式路径改写——ANP-02/03/04 在
  `chinese/` 根下，九篇消息在 `chinese/message/`；`vnext/` 降级为"下一轮修订的起点"。
  顺带核到：ANP-02 的行号（L82/L98/L112/L143/L437）两种取法差一行，现已明确以正式路径为准）
