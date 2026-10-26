# 私聊端到端加密（P5）—— 服务端只有两件事：钥匙柜与邮箱

P5 里最容易搞错的是**服务端到底参与多少**。答案是参与得很少，但**参与得不能更少**：

- X3DH-like 建链、Double Ratchet、`AD_init` / `AD_msg`、`MKSKIPPED` —— 一行都不在本服务里。
- 本服务做的是 §4.4 L204–210 那七项**密钥材料能力**，加上 §10.7 L1391 的一件事：
  **把不透明密文放进收件设备的邮箱**。

§14.3 L1590–1594 把这条边界说得很直白：一个恶意 Key Service 最坏能做的只有**拒绝转发**、
**拒绝发放 OPK**、**诱导建链失败**——它拿不到明文，也伪造不了绑定。设计如果越出这条线，
就把 "端到端" 三个字送掉了。

[message-service.md](message-service.md) §11 只有三行硬约束。这份写它背后的东西：
设备为什么是本层的一等公民、OPK 池的状态机与它必然的消耗、以及 Mailbox 与 C7 订阅路
之间那条还没接上的缝。

## 1. 设备：从"可选字段"变成"寻址单位"

P3 只用 DID 寻址；P5 在 DID 之上**多加一层设备**（§3.1 L74）：

- `meta.sender_device_id` / `meta.recipient_device_id` 选出一个精确的密码学设备对；
- 发往同一接收 DID 的多个合格设备 = **多条独立的 `direct.send`**，各带自己的
  `message_id` / `operation_id`（§3.1 L76、§3.7 L136、§12.4 L1513）；
- 服务 **MUST NOT** 共享 Ratchet 状态，也 **MUST NOT** 做隐藏的密码学 fan-out（§3.1 L76）。

设备清单住在 P2 的 `deviceManifest`（P2 §5.5 L236–264）：只有宣告设备定址 E2EE Profile
的 DID 才必须有它（P2 L263）。每个标准条目**只含** `device_id`、`signing_key_id`、
`e2ee_key_id`、`profiles` 四项（P2 L264）——所以服务端读它是**结构化**的，不是读一个自由
对象。

**资格是每次操作都要重判的**（P5 §4.1.1 L171–178、§12.4 L1515、P2 L630、P2 L947）：
所选设备必须是**当前** Manifest 里的条目、必须宣告本 Profile、密钥引用必须对得上。
任一条不再成立时，服务 **MUST**：

- 停止发布或返回它的 PreKey 材料（§12.4 L1515）；
- 停止向它的 Mailbox 入队与投递（§12.4 L1515）；
- 拒绝新材料与密文，并**停用受影响的缓存与 Session**；**调用方**重新解析 DID（§4.1.1 L178）。

这几条不是"启动时校验一次"，是每个操作的前置。错误码用 P1 公共段里那四个
（`anp.device_binding_required` / `_invalid` / `anp.device_not_eligible` /
`anp.device_state_changed`——core 的 `envelope.ts` L199–202 已经有 1015–1018），
P5 自己的段只用来表达**资格通过之后**的绑定不一致（§13 L1550）。

## 2. 两条 Key Service 方法

都是 **service-scoped**（§7.1 L465、§7.2 L520），`meta.target.did` 是公开服务的
`serviceDid`，`security_profile = transport-protected`，且**未协商扩展时 `params.auth`
MUST 缺省**（§7.1 L470、§7.2 L525、§3.8 L140）。

| 方法 | 正文 | 幂等键 |
|---|---|---|
| `direct.e2ee.publish_prekey_bundle` | `prekey_bundle`（必）+ `one_time_prekeys`（选，非空数组） | §7.1 L487 |
| `direct.e2ee.get_prekey_bundle` | `target_did` + `target_device_id`（必）；`preferred_suite` / `require_opk`（选） | §7.2 L579 |

两条要求是本层的硬骨头：

1. **`get_prekey_bundle` 的幂等键比 `publish` 长**——多了 `target_did` / `target_device_id`
   与 `meta.target.did`（§7.2 L579）。同一个调用方对同一设备的同一 `operation_id` 重试，
   **MUST** 拿回**同一个 `one_time_prekey`**（§7.2 L580），所以"幂等记录写入 + OPK 分配"
   **MUST** 是一个原子动作（§7.2 L581、§7.3 L594）。这与 C4 的 `acceptOperation()`
   是同一件事：OPK 的分配就写在 `perform` 里，跟结果一起提交。
2. **`require_opk = true` 但池子空了** → **MUST** 回显式错误（4003
   `anp.direct.e2ee.opk_unavailable`），**SHOULD** 而不是伪造或复用旧 OPK（§7.2 L574）。

`publish_prekey_bundle` 还有一条**服务端要主动执行的唯一性检查**：同一 `bundle_id`
**MUST NOT** 被重定义成另一组字段（§6.2.2 L362、L371）。落地就是：该设备已有同 id 的行，
但 `owner_did` / `owner_device_id` / `suite` / `static_key_agreement_id` /
`signed_prekey.key_id` / `signed_prekey.public_key_b64u` 六项里有任何一项不同 → 拒。

**表是每设备一行**（`prekey_bundles` 的 PK 就是 `(owner_did, owner_device_id)`，schema.ts
L193–200）。§6.2.2 L371 允许服务端在 grace period 内同时接受多个 `bundle_id`，那是
**MAY**；而 L362/L373 那个"接受窗口"是**接收设备**的窗口——它要留住旧 SPK 私钥，
那是客户端的事，不是服务端要存两份 Bundle。**新发布覆盖旧行**，就够对端拿到当前材料。

### 2.1 服务端要验的那份 proof

Bundle 的 proof 是这份材料唯一的自证（§6.2.3 L379、§6.5 第 2 项）。判据要问**两次**，
顺序不能反：

1. 只问附录 B——不合规就是 **4001** `bundle_invalid`，§6.2.3 L379 逐字这么指定；
2. 再问"签的是不是清单里那条 `signing_key_id`"——只可能以
   `unexpected_verification_method` 失败，那是 **4012** `invalid_security_binding`。

**合成一次调用会让码变得含混**：core 的 `verifyObjectProofDetailed` 把期望值比较排在验签
**之前**，于是"签名完全对不上、`verificationMethod` 又恰好不是这一条"会被报成 4012，而
§13 给 "proof verification failed" 的码是 4001。

同一层还有两处"与另一处的比对"，都回 4012（§13 L1547 把 "P5 Bundle owner" 与密钥引用
归在那一码名下）：`owner_did` / `owner_device_id` 必须等于 `meta.sender_*`；
`static_key_agreement_id` 必须等于清单里的 `e2ee_key_id`。最后一条两边都先过
`canonicalDidUrl` 再比——`#ka-1` 与整条 DID URL 指的是同一把钥。

**4012 只管"调用方送来的东西绑错了"。** 领取侧还有一条"存着的那份已经过时"：设备换掉
`signing_key_id` / `e2ee_key_id` 之后、重新发布之前，库里那份已经没有合规发送方会用
（§6.5 会各自拒掉它）。这条回 **1018** `anp.device_state_changed`，不是 4012——L1547 把
"current Manifest changes" 明确划给 Core 那张表，而调用方在那件事上什么都没做错。这也
正是 §4.1.1 L178 第 4 项那个 "**returning**" 要在领取侧再跑一遍的原因。

**两个码在本服务里没有产生路径**：

- **4002 `bundle_expired`**：`expires_at` 不在 §6.3 L383–391 的 `MUST contain` 清单里
  （§6.5 第 6 项把它写成**发送方**的 MUST），本服务既不要求也不判它。每设备又只留一行
  "最新"（§7.3 L592），所以"过期了但池里还有旧的"这种情形构造不出来。
- **4004 `missing_key_agreement`**：本服务不解析 Bundle 里的钥，`keyAgreement` 有没有对应
  条目由 §4.1.1 第 3 项那次资格判定回答（`eligibility.ts`）。

`preferred_suite` 只做**形状**校验，不参与任何判断：它的用途是"服务端同时维护多份材料时，
调用方想先拿哪一份"，而本服务每设备只有一份。把它当筛选条件，会让"服务端只有一份"这个
事实变成一个 4000。

## 3. OPK 池：一个必然被消耗的池子

OPK **不**进 Bundle（§6.2 L302、§6.3 L395–397），也 **MUST NOT** 被静态 proof 覆盖
（§6.4 L410）。它在 `get_prekey_bundle` 的成功响应里**按次**发放（§6.6 L429）。

状态机：

```
（未上传） --publish one_time_prekeys--> available --get 分配--> assigned --（永不回头）
```

- 同一 OPK **MUST NOT** 被并发分配给多个发送方或设备对（§6.6 L448、§7.3 L595）。
  落地就是分配在同一条 `UPDATE … WHERE state = 'available'` 里，靠主键与事务串行化，
  不靠先查后写。
- 分配后**不回收**。§6.6 L450 与 §7.3 L597 都说"是否允许回收由部署策略决定"，那就选
  **不回**：`assigned` 是终态，这个池子只出不进。
- **于是 §6.6 L449 那条"建链成功后 MUST 标记为已消费"我们观察不到，也不需要观察。**
  §10.7 L1392 不许服务端解密，接收方处理完 init 也没有定义一条回执方法——服务端
  **没有**能区分"建链成功"与"建链没发生"的信号。好在"永不回收"比"标记已消费"更强：
  任何被分配过的 OPK 都 **MUST NOT** 再次发放（§7.3 L597），而它确实不会再发放。
  **这条 MUST 是被更强的不变量覆盖掉的，不是被忽略的。**

代价很实在：池子会被抽干，而且**每次 `get_prekey_bundle` 都消耗一个**——一个反复用新
`operation_id` 调用的对手可以不建链就把某个设备的 OPK 抽空。§7.3 L598 已经预见到这件事：
"caller identity、限流与防滥用策略 **MUST** 基于 hop / service 级认证实施"。所以限流
**必须**在这一层做，而且它是本条 MUST 的落点，不是可选项。

**（2026-10-01 落地）**规范只写了那一句 MUST，没给数字、算法、码，也没说罩哪几条方法。
三项都由本实现补（`rpc/rateLimit.ts`）：

- **范围**：只覆盖这两条 Key 方法。§7.3 那一节讲的就是"发放 PreKey 材料"这件事本身；
  把整个服务都罩进来，拒掉的会是规范没让拒的请求。
- **键**：`callerKeyOf`——跨域用外层签名验出来的 `serviceDid`，同域退回 `meta.sender_did`。
- **码**：**1011** `anp.rate_limited`（P1 §10.3）。P5 自己的 4000 段里没有对应项，那一段
  全是关于材料的。拒绝时带 `retry_after`（`error.data.details.retry_after`）与
  `retryable: true`——一个不说什么时候能再来的 `retryable` 只能让调用方盲重试。

算法用**令牌桶**：这两条方法的正常节奏是"一阵一阵的"（发布一批 OPK 是一次突发，建链时
连着来几次），固定窗口会在边界上放过两倍流量。容量与补充速率走配置
（`ANPIOCLI_PREKEY_BURST` / `ANPIOCLI_PREKEY_PER_MINUTE`）。

**已知弱点写在明处**：同域那半边按自报的 `sender_did` 计数，挡得住"一个身份发得太快"，
挡不住"换一串 DID 的洪泛"；跨域那半边好一些——键取的是签名验出来的身份，伪造要拿到那颗
私钥。真正的兜底在传输层（连接数、请求体量闸门），不在这一层。计数器也在进程内存里，
横向扩成多进程时"每调用方一个桶"会变成"每进程各算一份"，也就是额度乘以进程数。这条缺口
与它的出路记在 §9 第 3 条。

池空时的行为：`require_opk = true` → 4003；否则正常返回 Bundle、不带 OPK
（§6.6 L451 允许这样继续建链，代价是前向安全更多依赖 SPK 生命周期）。

## 4. Mailbox：本服务已有的投递表，差一个设备维度

§10.7 L1391 那句话就是 Mailbox 的全部定义：

> 只将**不透明密文**入队到 `(recipient_did, recipient_device_id)` 的 Mailbox；且
> **不得解密、重加密或将密文 fan-out 给其他设备**。

它**不拥有** Ratchet 状态，也**不定义**历史拉取、已读回执或设备同步方法（L1396）——
所以它不需要新概念，它就是 `deliveries`。

**缝在这里**：`DeliveryRecord`（`storage/types.ts` L57–64）只有 `ownerDid`，没有设备列；
而 C7 的订阅路是**按账号**路由的，`device_id` 在那里被明确定成搭车：

> 订阅路因此按 `owner_did` 路由，`device_id` 只是搭车过来，好让连接知道自己推的是谁。
> ——[realtime.md](realtime.md) §5.1 L111

注册表的键也就是 `Map<owner_did, …>`（§8.1 L266–270）。而 P5 要求"**只**投递给
`meta.recipient_device_id`"（§10.7.1 L1407）。`device_id` 从搭车变成了**路由键的一半**：

- `deliveries` 要记下 `recipient_device_id`（P5 消息必填，P3 消息为空）；
- 订阅连接要**声明它代表哪个设备**，路由键从 `owner_did` 变成
  `(owner_did, recipient_device_id)`；P3 的消息（没有设备）照旧按 owner 广播。

序号仍**只**按账号递增（§5.1 L106：同一封消息在账号里只有一个号）——变的不是"谁排的号"，
是"这一号推给谁"。

**（2026-10-01 落地）**这两条已经做了：`deliveries.recipient_device_id` 是 schema v7，
`Registry.publish` 按它筛连接（`stream/registry.ts` 的 `reaches`）——**候选**仍从账号那张
`Map` 里取，所以序号不变；**筛选**才看设备。一条没声明设备的连接因此只收账号级消息。

**取件面（C6）也跟上了（2026-10-01）**：`sync.delta` / `inbox.get` / `message.get_batch`
各收一个**选填**的 `body.device_id`，读侧套同一条规则——账号级的那批加上投给**这台**设备的
那批。字段名与订阅握手一致不是巧合：它们是同一台信箱的两半，而 `sync.delta` 补的正是订阅
会推的那些帧，两边用不同的名字就会各有各的答案。

**缺席按"没声明"处理，不是"没有限制"**。这是刻意的 fail-closed：默认放行等于默认泄漏，
而漏出去的密文收不回来。所以一个不声明设备的 `msg inbox` 只看得到账号级的消息——那台设备
本来就解不开别的设备的密文，少给它是**对的**，不是功能缺失。

实现落在一条 SQL 谓词上（`storage/types.ts` 的 `deviceFilter`），四处查询共用：交付流水、
收件箱翻页、计数、按 id 取。**它取表别名做参数**——三处查询都带别名，把谓词直接拼在 `d.`
后面会写成 `d.(…)`，那是个只在 prepare 时才炸的语法错误。

`inbox.mark_read` 没有这一项：已读是**账号级**的状态（`message_reads` 的键是
`(owner_did, message_id)`），它不是一次交付，也就没有"投给哪台设备"这回事。

成功响应的形状服务端要照抄（§10.7 L1394）：`accepted` / `message_id` / `operation_id` /
`target_did` / `recipient_device_id` / `accepted_at`，且回显 **MUST** 等于请求。**逐设备的
结果不合并成数组**——每个设备一条 `direct.send`、一份独立结果（§3.1 L76、§12.4 L1513）。

## 5. 两类重放状态，一边一半

§11.5 L1455 让接收方维护两类状态，**它们不在同一侧**：

| 状态 | 键 | 归谁 |
|---|---|---|
| 外层幂等记录 | `(sender_did, sender_device_id, recipient_did, recipient_device_id, method, operation_id)`（L1458） | **服务端**——就是 C4 的幂等记录，键变长而已 |
| init replay 记录 | `(recipient_did, recipient_device_id, recipient_bundle_id, sender_did, sender_device_id, sender_ephemeral_pub_b64u, session_id)`（L1461） | **客户端**——它含 `session_id`，那是 DH 的产物，服务端不可能知道 |

分法的依据正是 §10.7 L1392：服务端不解密，所以任何需要会话状态的判重都在设备侧。
`anp.direct.e2ee.replay_detected`（4008）因此有两条来源：设备侧命中 init replay 键
（L1466），服务端侧命中幂等键但 `contentDigest` 不同。

**`operation_id` = `message_id`** 是 P5 独有的约束（§3.7 L134），所以外层幂等键与消息标识
在这里是同一个值——C4 的键不用改，只多两个设备段。

**设备段带 owner，不是裸 `device_id`**（`eligibility.ts` 的 `deviceSelector` =
`<identity>#<deviceId>`）。`device_id` 是发布方自己起的不透明字符串（P2 §5.5 L263），
两个 DID 各自取 `dev-a` 完全可能；只写设备 id 就会让 "S 的 a → R 的 b" 与 "S 的 b → R 的 a"
算出同一个键，而它们是两件不同的事。

## 6. 跨域

- `direct.e2ee.get_prekey_bundle` 是 P8 §5.3.1 L255–259 点名的跨域 getter：解析
  `body.target_did`、**保留并校验 `body.target_device_id`**、找到目标公开
  `ANPMessageService`、**直接调用，不得替换为其它设备**。设备 selector 逐跳原样保留
  （P8 §3.7 L102）。路由细节见 [federation.md](federation.md)。
- §5.3.1 L267：v1 最小互通**不假定**匿名获取 PreKey 材料。
- Agent DID 迁移**不**继承密码学身份：§12.5 L1525 明令 **MUST NOT** 在后继 DID 下复制或
  复用旧 DID 的 Session / Ratchet / 私钥 / skipped key / replay state。本服务因此也不做
  任何"按联系人继承 Bundle"的事——它按 `(owner_did, owner_device_id)` 存，DID 一换就是
  另一行。

## 7. 存储增量

`prekey_bundles`（schema.ts L193）与 `group_key_packages` 已经在 v3 里。要加的只有 OPK 池
与 Mailbox 的设备列（v7 加后者，v8 加前者）：

```sql
-- 逐设备 OPK 池。state 只有两个：available 被分配即变 assigned，且不回头（见 §3）
CREATE TABLE one_time_prekeys (
  owner_did TEXT NOT NULL, owner_device_id TEXT NOT NULL,
  opk_id TEXT NOT NULL, public_key_b64u TEXT NOT NULL,
  state TEXT NOT NULL,                 -- available | assigned
  assigned_to TEXT, assigned_at TEXT,
  uploaded_at TEXT NOT NULL,
  PRIMARY KEY (owner_did, owner_device_id, opk_id)
);

-- Mailbox 的设备维度。P3 消息这一列为 NULL
ALTER TABLE deliveries ADD COLUMN recipient_device_id TEXT;
```

**没有 `assignment_key`。** 这一列在设计里出现过，落地时去掉了：它要回答的是 §7.2 L580
的"同一幂等键重试拿回同一个 OPK"，而这件事 `idempotency` 那张表已经回答了——命中同键时
`acceptOperation` **不调用** `perform`，直接回放上次那份响应，里面就是同一枚 OPK。再存一份
就是同一个事实的第二个说法，两者一旦不同步没有谁能判谁对。

`assigned_to` / `assigned_at` 留着：它们不是给幂等用的，是"这枚 OPK 发给了谁"的唯一取证
材料——§6.6 L448 要求它 **MUST NOT** 被并发发给两个发送方，出问题时这是仅有的凭据。

`opk_id`（发布方自己起的名，§6.4 L401）在主键里，所以同一个 `key_id` 重传是**忽略**而不是
覆盖：先写者赢，否则后一次上传能把一枚已经发出去的 OPK 换掉。

**不建 init replay 表**：它在客户端（§5）。

## 8. v1（C12）不做

- **任何 DH、AEAD、KDF、Ratchet**（§8–§10 全部）。服务端一行都没有，也不会去验密文。
- **Header Encryption**：§10.6 L1374 是 MAY，且要显式协商。
- **`Direct Init Accountability Extension`**：§3.5 L116、§3.8 L142——不协商扩展时收到
  `params.auth` **MUST** 拒绝，这条要落成校验，不是"忽略它"。
- **OPK 回收**：§6.6 L450，见 §3。
- **历史拉取 / 已读回执 / 设备同步**：§10.7 L1396 明说 Mailbox 不定义这些。
- **透明目录与 Bundle 可审计日志**：§14.3 L1596 是 SHOULD，属运维面。

## 9. 已定的三件事

1. ~~**客户端侧的密码学放哪。**~~（2026-10-01 定：**(a) 内嵌进 `connectx`，与官方 SDK 同向**。
   与 [TODO1.md](../../TODO1.md) 的 `D4` 是同一个问题——X3DH-like、Double Ratchet 以及 P6 的
   MLS 都在设备侧跑。依据是官方 SDK 自己的走向：

   - 官方 Rust SDK 明写群 MLS **是库调用、不是 `anp-mls` 子进程调用**（`rust/README.md`
     L33）；同段说 MLS state 放在 `anp::group_e2ee::storage` 的 store 实现后面，
     "**rather than a subprocess or CLI JSON command surface**"（L37–38）。
   - 官方 monorepo 里 MLS **只**存在于 Rust crate `anp::group_e2ee`（依赖 `openmls 0.8.0` +
     `openmls_sqlite_storage`）；Python / TS / Dart / Java 四套 SDK **都没有** MLS 实现。
   - Go SDK 只剩 `ExecProvider`，驱动已被移除的 `anp-mls` 一次性二进制；于是 `anp-cli`
     的群组 E2EE 至今不可用（`anp-cli/docs/implementation-status.md:31`）。
     **这是"链不上库"的代价，是反面教材，不是可效仿的形态。**
   - 库化之后的串行化靠**文件锁**（`rust/src/group_e2ee/storage.rs` 的 `StateLock` /
     `state_locked`），不靠进程隔离——所以"一处落盘还是两处"的问题本来就只有一个答案：
     **一处，客户端进程。**

   照记代价：官方 **TS SDK 没有 `group_e2ee`**，`connectx` 走 (a) 需要自己写 Rust crate →
   Node 的 napi 绑定。**这条不影响 v1**——P5 / P6 的客户端密码学 v1 都不做。
   （`connectx` 已于 2026-10-03 退役删除，napi 那条代价随之消失；密码学仍在设备侧，
   今天的落点是 Rust 客户端的 `mls.rs`，见 [client-mls.md](client-mls.md)。）
2. ~~**限流的形状**~~（2026-10-01 定：本服务给默认值。§7.3 L598 只要求"按 hop / service 级
   认证限流"，没给数值，属部署策略。默认＝按**调用方 DID**计数的令牌桶，数值走配置，
   给一个保守默认；跨域时外层 hop 认证已提供调用方身份，同域时用 `meta.sender_did`）。
   **2026-10-01 落地**：范围、键、码与它的已知弱点见 §3 末尾。
3. **发往 `direct.send` 的 v2 请求由谁认证 —— 现在没有答案，这是一处已知缺口。**

   规范把这件事写成了两个 MUST（§7.1 L476–477）：调用方 **MUST** 跑在"已认证的本地会话
   或等价的 hop / service 级认证上下文"里，且**该上下文 MUST 认出确切的**
   `(meta.sender_did, meta.sender_device_id)`。而同一个 Profile 把业务层的证明关掉了：
   §3.8 L140 明写 v2 下 `params.auth` **MUST** 缺席——所以这条 MUST 只能靠**连接本身**
   来满足，不能靠请求里带点什么。

   本服务今天给不出那个连接：同域没有 hop，而唯一验过的外层身份是一个**服务** DID
   （锚点 `ANPMessageService` 条目里那个），不是 agent，更不是设备；跨域那条路的
   `verifyOuterIdentity` 在缺 `signature-input` 头时返回 `absent`。

   **选择：不为 P5 强制要求外层 hop。** 理由有两条，第二条是要害：
   - 强制它会把正常的设备客户端挡在外面——它们正是这个 Profile 的目标调用方，而且永远
     不会带一个服务身份来签名；
   - **它拦不住谎报。** 外层身份是一个服务 DID，"这个服务替 X 转发了"与"X 自己发的"
     在这条链路上不是同一个断言。真拿它当业务认证用，得到的是一层看起来像把关、
     实际不区分调用方的检查——比没有更坏，因为它会被当成已经有答案。

   因此 v2 的 `sender_did` / `sender_device_id` 是**自报**的，唯一把关的是 §4.1.1 的设备
   资格：自报的那对设备必须真的在自报的那个 DID 的当前清单里、且两个密钥引用都对得上。
   这挡得住"拿一台不存在的设备冒充"，**挡不住"拿一台真实设备滥发"**——后者靠第 2 条那套
   限流，而限流按**身份**计数：它挡得住"一个身份发得太快"，挡不住"换一串 DID 的洪泛"
   （§3 末尾）。它把问题缩小了，没有解决它。

   **待办**：`publish_prekey_bundle` / `get_prekey_bundle` 与 `direct.send` 三处共用同一套
   调用方身份判定，所以这件事应当一次做完——要么引入一个**设备级会话**（连接上先证明设备
   私钥，后续请求据此认人），要么把"自报身份"写进部署假设。在那之前，本服务对 P5 的受理
   **只保证资格判定，不保证来源**。
