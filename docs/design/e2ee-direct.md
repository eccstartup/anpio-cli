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
L147–154）。§6.2.2 L371 允许服务端在 grace period 内同时接受多个 `bundle_id`，那是
**MAY**；而 L362/L373 那个"接受窗口"是**接收设备**的窗口——它要留住旧 SPK 私钥，
那是客户端的事，不是服务端要存两份 Bundle。**新发布覆盖旧行**，就够对端拿到当前材料。

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
是"这一号推给谁"。这条改动同时影响 C6（取件面）与 C7（订阅路），所以它**不能**等 C12
才动；写在这里是为了让那两块**留出那一列**，别把 `ownerDid` 焊死成唯一路由键。

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

`prekey_bundles` 已经在 v3 里（schema.ts L147），`group_key_packages` 也在。要加的只有：

```sql
-- 逐设备 OPK 池。state 只有两个：available 被分配即变 assigned，且不回头（见 §3）
CREATE TABLE one_time_prekeys (
  owner_did TEXT NOT NULL, owner_device_id TEXT NOT NULL,
  opk_id TEXT NOT NULL, public_key_b64u TEXT NOT NULL,
  state TEXT NOT NULL,                 -- available | assigned
  assigned_to TEXT, assignment_key TEXT, assigned_at TEXT,
  uploaded_at TEXT NOT NULL,
  PRIMARY KEY (owner_did, owner_device_id, opk_id)
);

-- Mailbox 的设备维度。P3 消息这一列为 NULL
ALTER TABLE deliveries ADD COLUMN recipient_device_id TEXT;
```

`assignment_key` 存的就是 §7.2 L580 那个幂等键，于是"同一幂等键重试拿回同一个 OPK"
是一次主键之外的普通查表。

**不建 init replay 表**：它在客户端（§5）。

## 8. v1（C12）不做

- **任何 DH、AEAD、KDF、Ratchet**（§8–§10 全部）。服务端一行都没有，也不会去验密文。
- **Header Encryption**：§10.6 L1374 是 MAY，且要显式协商。
- **`Direct Init Accountability Extension`**：§3.5 L116、§3.8 L142——不协商扩展时收到
  `params.auth` **MUST** 拒绝，这条要落成校验，不是"忽略它"。
- **OPK 回收**：§6.6 L450，见 §3。
- **历史拉取 / 已读回执 / 设备同步**：§10.7 L1396 明说 Mailbox 不定义这些。
- **透明目录与 Bundle 可审计日志**：§14.3 L1596 是 SHOULD，属运维面。

## 9. 需要用户裁定

1. **客户端侧的密码学放哪。** 与 [TODO1.md](../TODO1.md) 的 `D4` 是同一个问题、同一份
   取舍：X3DH-like 与 Double Ratchet（以及 P6 的 MLS）都要在设备侧跑。内嵌进 `connectx`
   （Rust/JS 库）还是另起一个本地进程，决定"设备私钥 + 会话状态"是一处落盘还是两处。
2. **限流的形状**：§7.3 L598 要求按 hop / service 级认证做限流，但没给数值，也没说
   按调用方还是按目标设备计数。这属于部署策略，本服务给一个默认值即可，除非有别的偏好。
