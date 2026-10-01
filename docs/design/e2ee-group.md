# 群组端到端加密（P6）—— Host 排序、业主算、两台柜子

P6 是本仓库面对的四个 Profile 里最反直觉的一个：**它把密码学动作和业务动作彻底分开，
而本服务站在没有密码学的那一边。**

§3.6 L199–204 三句话把 Host 的位置钉死：

> 默认情况下，Group Host Service：**不应** 作为 MLS 控制者；**不应** 作为 MLS 群成员；
> **不应** 持有群应用明文的解密能力。

于是三件事不在本服务里：MLS group state、`epoch` secret、以及**任何**Commit/Welcome 的
生成。§11.11 L1386 又补一刀：连"替成员做最终 MLS 有效性判断"都不支持。

那本服务做什么？**排序、持有一份公开投影、以及两台柜子。** 这份文档写这四件事，
以及一条规范反复强调、最容易做错的线：**群 leaf 的身份不是 DID 的身份。**

## 1. 四个人，各持一半

| 角色 | 持有 | 生成 |
|---|---|---|
| **owner 设备**（客户端） | 自己的 MLS group state、**唯一**能产生 Commit/Welcome 的私钥 | `create` / `add` / `remove` 的三个 `*_b64u` |
| **active 成员设备**（客户端） | 自己的 MLS group state | `group.e2ee.send` 的一个 `PrivateMessage` |
| **Group Host**（**本服务**） | 排序位置、公开投影、投递队列 | `group_event_seq` / `group_state_version` / `group_receipt` / 每个 leaf 一份投递信封 |
| **ANPMessageService**（**本服务**） | KeyPackage 柜子 | 按次发放一个未消费 KeyPackage |

注意最后两行是**同一个进程**：本仓库里 `AgentXAgent` 同时是某个群的 Host 与各成员的
消息服务。这两顶帽子之间只通过**公开对象**说话（`group_key_package` 进、`group_cipher_object`
出），没有共享内存里的会话状态——因为本服务**没有**会话状态可共享。

**推论（这条决定了 C13 的形状）**：owner 的 MLS runtime 在**客户端**，与 P5 的
X3DH/Double Ratchet 同侧。§11.10.3 L1376 说 Host "默认**不要求**持久化可解密群消息的
MLS 私有状态"——本服务选**不持久化**，于是 [TODO1.md](../TODO1.md) 的 `D4` 从"P6 才有影响"
变成"P6 直接依赖它"。同一台设备要跑两种密码学，答案只能有一个。

## 2. 状态耦合：本服务只当见证者

§3.4 L109–116 否掉了"P4 方法直接映射 P6 方法"的写法。链条是：

```
P4 业务状态变化（group.create / member active / member left|removed / member-did-updated）
        │  owner 观察（§10.1 L1023：本地编排、订阅 group.state_changed、或等价机制）
        ▼
owner 生成 MLS 结果，调用 group.e2ee.create / add / remove
        ▼
Group Host 校验（§13.4 / §13.5）→ 排序 → 分发 group.e2ee.notice
```

**本服务的落点只有倒数第二步。** §10.1 L1031–1035 那三种"状态观察方式"是 **owner 的**
选择，不是我们的义务——我们既不替 owner 观察，也不替它触发。§10.2 / §10.3 / §10.4 里
每一个 `owner MUST 触发` 都落在客户端。

这不是推诿：本服务**做不到**。§13.4 L1649 说得很清楚——Host 的检查**MUST NOT** 取代成员
runtime 对 Commit/Welcome 的最终验证。Host 收下一串 `commit_b64u` 时，它能验的只有**形状、
归属与顺序**，验不了 `delta` 是否正确。**"验不了就当作验过了"是本 Profile 最贵的错误。**

## 3. 三档目标建模

§4.4 给 P6 的方法分了三档，与 P3/P4 的建模不同，方法表要照抄：

| 档 | 方法 | `meta.target` |
|---|---|---|
| service-scoped | `publish_key_package` / `get_key_package` / **`create`** | `kind = "service"`，`did` = Host 的 `serviceDid` |
| group-addressed | `add` / `remove` / `send` | `kind = "group"`，`did` = `group_did` |
| agent-addressed | `group.e2ee.notice` / P6 `group.incoming` | `kind = "agent"` + `recipient_device_id` |

`create` 走 service-scoped 是刻意的（§4.4.1 L292–293）：业务群刚建好、`group_did` 刚生成，
但这次调用仍然面向 Host 的服务入口做密码学初始化，所以 v2 统一按 service-scoped。
**照抄，不要"顺手纠正"成 group-addressed。**

§4.4.3 L320：本 Profile **不定义** `target.kind = "device"`。设备永远通过
`meta.target.did`（Agent DID）+ `meta.recipient_device_id` 表达。

安全档位（§4.3 L272–275）：两条 Key 方法与 `notice` 是 `transport-protected`；
`create` / `add` / `remove` / `send` 与 P6 `group.incoming` 是 `group-e2ee`。
§4.3 L266–268：每个设备发起的 P6 请求**MUST**带 `sender_device_id`，
每个设备定向的通知**MUST**带 `recipient_device_id`——而 **P4 Base 操作与通知 MUST NOT 继承它们**。

错误码：§17 L1918–1931 的 5000–5013，加 core 的四个设备码（§17 L1935）。
`group.e2ee.leaf_not_current`（5013）有一条**特殊义务**，见 §7。

## 4. KeyPackage 柜子

与 P5 的 Prekey 柜子同构，但**契约不同**，别复用代码：P5 的 OPK 是"按次发放、只出不进"，
P6 的 KeyPackage 有**三个状态**。

§8.2.4 L765–770：

```
available ──get 发放──▶ reserved ──对应 add 被 Host 接受──▶ consumed
                           └── 流程失败/取消/超时 ──▶ 是否释放由部署定，但 SHOULD NOT 并发复用
```

三处与 P5 不同的地方：

1. **`consumed` 的触发者是本服务自己**（L769：对应的 `group.e2ee.add` 被 Host 成功接受并完成
   密码学成员变更后 **MUST** 标记）。P5 那边我们**没有**这个信号（[e2ee-direct.md](e2ee-direct.md) §3），
   P6 有——因为 add 是**经过本服务**的控制动作。这是一条真实的、有信息量的差异。
2. **`reserved` 是 MAY**（L768）。但 §13.2 L1610 与 §10.3 L1066 都要求已消费的
   KeyPackage **MUST NOT** 复用（除非部署显式声明 last-resort），所以不做 `reserved`
   也得做"发放即登记"，否则并发两次 `add` 会拿到同一个 KeyPackage。**做。**
3. **一个 KeyPackage 只属于一台设备**（§7.3 L563），`get` 时
   `MUST NOT` 换成 sibling（§8.2.4 L766），返回前**MUST**按当前 Manifest 重验目标设备（L767）。

表已在 v3 里：`group_key_packages`，PK 是 `(owner_did, owner_device_id, key_package_id)`
（`schema.ts` L154–162），且已有 `state` 列——所以这块只差把它接上方法与状态机。

`publish` 侧（§8.1）有一条与 P5 同形的校验：`owner_did` = `meta.sender_did`、
`owner_device_id` = `did_wba_binding.device_id` = `meta.sender_device_id`（§8.1.2 L701–702），
且接受前**MUST**按 §6 验当前 Manifest 与绑定（L703）。§8.1.2 L709：v2 **不要求**额外的
业务层 `origin_proof`——它靠 hop 认证。

## 5. Host 的公开投影：`(DID, device_id) → leaf`

§11.10.3 L1372 列出 Host 要持久化的东西，其中最具设计含义的是这一条：

> 由已接受的 `create/add/remove` 形成的当前 `(DID, device_id)`-to-leaf 公共投影；
> 该投影 **MUST NOT** 包含 MLS 私有密钥或 epoch secret。

**这是 Host 侧唯一的"群密码学状态"，而它是投影，不是状态。** 它的每一条都是某次被接受的
控制动作的**结论**：谁在群里、以哪个 device 的身份、在哪一个 `epoch` 上成立。它**不含**
任何能参与运算的东西。

这个区分是可实现的支点。本服务因此可以说："我权威地知道**哪些 `(did, device)` 组合
当前是 leaf**，但我不知道也验不了任何一个 Commit 是不是正确。"两个断言不矛盾，
因为前者是 Host 自己按顺序记下来的账，后者需要 MLS runtime。

投影与 `epoch` / `crypto_group_id` 的外层绑定引用（L1371）是同一行的事，它们一起构成
"这个群现在到哪了"的 Host 侧答案。**权威值仍在客户端**——Host 记的是**最后一次被接受的**。

§14.5 L1737–1743 的分叉检测是 SHOULD：成员观察到多个不可调和的 `crypto_group_id`、
不一致的 `epoch_authenticator`、或同上下文下不同有效 Commit 时，**SHOULD** 标记
`fork-suspected` 并暂停新群消息。我们的落点是**接受 `group.e2ee.epoch_conflict`（5005）
并拒绝**（§17），以及把投影里"同一 `group_did` 出现第二个 `crypto_group_id`"判成
`group.e2ee.crypto_group_mismatch`（5006）——两条都是 Host 拿投影就能判的，
不需要 MLS。真正的分叉判定留给客户端。

## 6. Device Delivery Queue：第二个 Mailbox，同一条缝

§12.6 L1500 的论证值得抄一遍，因为它解释了**为什么不能"以后重发"**：

> 信封首次发出时处于离线的设备，之后仍然需要那一份精确信封，因为 Group Host
> 不持有 MLS 私有状态，无法为它重新加密或重新生成一份。

所以队列存的是**原样信封**，不是"待生成的消息"（§12.6 L1505：重投 **MUST** 无损复现
`meta.message_id` / `operation_id` / `content_type` / 排序字段 / `group_receipt` /
被保留的 `auth` / `body`；**MUST NOT** 改投、合并、拆分、重排或重新编号）。

按 `(recipient_did, recipient_device_id)` 键控（§12.6 L1502），两条 P6 路径共用它
（`group.e2ee.notice` 与 P6 `group.incoming`）。§12.6 L1508 划了存储边界：
**只**存公开元数据、被保留的公开 origin proof、与不可读密文。

**这就是 [e2ee-direct.md](e2ee-direct.md) §4 那条缝的第二次出现，而且是同一个键。**
P5 的 Mailbox 与 P6 的 Delivery Queue 是同一张表、同一个维度、同一个"只投给
`meta.recipient_device_id`"的要求。C6 / C7 要留的那一列，两处共用。**别建两张表**——
它们的差别只在**队列内的排序规则**（下一节）与**保留策略**，不在结构。

### 6.1 队列内的顺序（§12.6 L1512）

这是本服务真正要写的一段算法：

| 信封 | 规则 |
|---|---|
| P6 `group.incoming` | 按 `group_event_seq` 顺序投递与重投 |
| `commit-delivery` | 按 `epoch` 顺序 |
| `welcome-delivery` | **MAY** 越过待投的应用信封（它开的是新绑定，不是旧绑定的延续） |
| 最终 Remove 通知 | **MUST NOT** 越过 Host 仍打算投递的应用信封——它是该 leaf 收到的**最后一封** |

最后一条有两种正当实现（L1512）：**SHOULD** 按序投完此前已为该 leaf 入队的应用信封，
再把最终通知放在它们全部之后；或者 **MAY** 按已声明的部署策略取消该 leaf 全部剩余的
已入队应用信封，立即投最终通知。**我们选前者**——被移除的设备仍持有那些信封加密所用
epoch 的密钥，投完它不花我们任何密码学成本，只是多几行队列。

## 7. "最后一封"与终止终态

§12.3 L1444–1450：Remove Commit 除了给每个保留 leaf，**还要**给被移除的**精确 subject leaf**
一份最终信封，目标是 `(body.subject_did, body.subject_device_id)`，**MUST NOT** 改投给它的
sibling。理由是 L1450：

> MLS 不提供任何带内方式让被移除成员得知自己已被移除。

这份信封是 MLS `PublicMessage`，所以投它**不泄露任何 epoch secret**。它的投递**有界**：
L1456–1458 要求显式的部署上限，到限即连同该 leaf 的队列状态一起丢弃，
且**丢弃 MUST NOT 阻塞**该群后续 epoch、保留 leaf 的投递、或新 `group.e2ee.send` 的接受。

**这里本服务可以复用 C9 的做法**：[groups.md](groups.md) §7 已经为 P4 的
`member-removed` 最终投递做了同一件事——走已有 outbox、上限就是 outbox 的尝试上界、
到顶即删行。P6 的最终通知是**同一类**收尾，**但走的是另一个队列**（Delivery Queue 按设备，
outbox 按 DID），所以那是两处"到限即弃"，不是一处。

被移除设备**MUST NOT** 把"收到这封信"当作重新加入或判定终态的必要条件（L1460）。
§11.9.1 L1306 列了**五个等价权威信号**：送达的最终通知、P4 的 `member-removed` /
`member-left`、后续请求收到 `group.not_member`、**`group.e2ee.leaf_not_current`**、
以及 §11.9.2 的陈旧状态规则。

**第五个信号是本服务独有的义务。** §13.3 L1625 要求三种状态映射到三个**互不相同**的
稳定错误，且**按固定顺序、先于策略与载荷检查**判定：

1. `meta.sender_did` 不是 P4 `active` 成员 → P4 的 `group.not_member`；
2. 否则 `meta.sender_device_id` 不合当前 Manifest 资格 → core 的 `anp.device_not_eligible`
   或 `anp.device_state_changed`；
3. 否则该合格组合不在当前 leaf 投影里 → **`group.e2ee.leaf_not_current`（5013）**，
   **MUST NOT** 折叠进前两者。

第 3 条只管一件事：DID 仍是 `active`、只有这一个 leaf 被移除。此时前两个信号永远不会触发，
**5013 是唯一的拉取式终态信号**（L1308）。把它返回成别的码，等于让那台设备永远无法收敛。
所以方法表里 `group.e2ee.send` 的 `authCodes` 必须按这个次序表达，而 not_member 的判定
**不能**先查 leaf 投影。

## 8. 暂停与串行化：Host 状态机里唯一真状态

§10.5 给 Host 加了一段真正有状态的义务。成员 DID 更新编排期间：

- L1092：**MUST** 串行化 P6 成员变更控制动作，除当前步骤的幂等重试与
  "Add 成功后紧随的匹配 Remove"外，**MUST NOT** 接受无关的 `add` / `remove`；
- L1094：从 P4 事件被接受起、到最后一个 Remove 成功止，**MUST** 暂停该群新的
  `group.e2ee.send`；中间的 `epoch` **MUST NOT** 承载应用消息；某步失败时
  **MUST** 保持暂停并重试该步。

§11.10.3 L1374 说这个进度**不是**新的协议级成员状态，但它**要落库**——否则重启后
不知道暂停到哪了。

落地：

```sql
-- 每群至多一行。progress 记当前编排走到哪一步，不是协议字段
CREATE TABLE group_did_updates (
  group_did        TEXT PRIMARY KEY,
  event_ref_json   TEXT NOT NULL,   -- 被引用的 P4 member-did-updated 的 group_state_ref
  progress         TEXT NOT NULL,   -- add-pending | remove-pending
  expected_json    TEXT NOT NULL,   -- 待处理的确切 (did, device) 列表
  done_json        TEXT NOT NULL,   -- 已成功的
  started_at       TEXT NOT NULL
);
```

串行化不需要新机制：`BEGIN IMMEDIATE`（C4 已定）就是"同一时刻只有一个控制动作在改这个群"。
§13.4 L1646 的"拒绝或延后无关的 Add/Remove"落成事务内的一个检查——
**拒绝**比延后简单，且 L1647 只要求同一 P4 事件的重试有幂等语义。

**新 `group.e2ee.send` 的入口检查多一条**：该群若有未完成的 `group_did_updates` 行，
`send` 返回 `group.e2ee.state_not_ready`（5004）——§17 L1933 明确说 DID 更新编排
"状态尚未就绪"时复用这个码，**不新增专属错误码**。

被撤销单台设备那个例外**不进入这个状态**：§10.4 L1074 说此时 Host **MUST NOT**
仅因该 leaf 尚未移除就暂停其它合法 `group.e2ee.send`。所以 `group_did_updates` 只由
**整个 P4 成员**的 DID 更新建立，设备级撤销不建行。

## 9. `group.incoming` 要无损保存一份 proof

§12.5 L1491：P6 `group.incoming` **无损保留**原 `group.e2ee.send` 的 `scheme` 与
`origin_proof`，重投时同样如此，并额外携带 `origin_context`。§13.6 L1665 说清了这个设计：

> proof 的新鲜性与 proof 的有效性，在这两种语境下 **MUST** 用不同方式判定。

- **提交时**（Host 接受 `create/add/remove/send`）：完整新鲜性窗口 + 一次性 nonce（L1667）。
- **投递/重投时**（接收设备验证）：**MUST NOT** 因 `expires` 已过而拒绝，也
  **MUST NOT** 把重复出现的 nonce 判为重放（L1698）。防重放以
  `(group_did, group_event_seq)` + `meta.message_id` 配合 MLS 校验为准。

代价落在存储上：Device Delivery Queue 的每一行**必须**原样存住 `auth` 与
`origin_context`。`origin_context` 至少含提交时的 `meta.created_at`（L1681），
以及本 Profile 未要求信封保留的其它 meta 字段（`extra_meta`，且有保留字段黑名单）。

§13.6 L1696 还有一条实现上容易踩的：**keyid 引用的验证方法若已无法从当前文档解析，
MUST NOT 判为伪造**，而**MUST**按"未经证明"处理——P2 文档不是历史密钥日志。
这是客户端侧的义务，但它解释了为什么我们**不能**提供一个"帮客户端验 proof"的服务端接口：
我们既没有历史文档，也不是它。

§13.6 L1663 反过来给我们减负：**标准 `group.e2ee.notice` 不携带 `origin_proof`**，
也**MUST NOT** 被附加一个看似签名的 proof。它的真实性靠传输认证通道 + §12.2 的信封绑定 +
接收端对 Commit/Welcome 内部 MLS 签名的验证。所以我们的 `notice` 出站**不需要签**。

## 10. 跨域

- `group.e2ee.get_key_package` 是 P8 §5.3.1 **L261** 点名的跨域 getter：解析
  `body.target_did`、保留并校验 `body.target_device_id`、找到目标公开
  `ANPMessageService`、直接调用，不得换成 sibling。§5.3.1 L269 明确：v1 **不定义**
  独立的 `group.e2ee.get_join_info` 跨域路由，`welcome` / `ratchet_tree` 一律经
  `group.e2ee.notice` 交付。
- 顶层 `body.group_did` 同时是 P8 §6.2.2 要求的群 caller anchor（§12.5 L1496 明说）。
  C11 的 `callerAnchor()` 对 `group.incoming` / `group.state_changed` / `group.e2ee.notice`
  取 `body.group_did`——**P6 的两种通知各多出第三个成员**，这条要一起考虑。
- 出站：`add` / `remove` / `send` 是 group-addressed **请求**，按 [federation.md](federation.md)
  §3.2 同步转发；`group.e2ee.notice` 与 P6 `group.incoming` 是**通知**，走 outbox / 队列。
- **H5**：`group_did` 必须可解析才能找到 Host——[federation.md](federation.md) §5.1 记的同一条缺口。

## 11. 存储增量

`group_key_packages` 已在 v3。要加的：

```sql
-- §8 的编排进度。每群至多一行，不是协议状态
CREATE TABLE group_did_updates ( ... );   -- 见 §8

-- §11.10.3 L1372 的公开投影：谁在群里、以哪个设备身份、在哪个 epoch 上成立。
-- 无任何私钥、epoch secret 或能参与运算的材料——这一列都不该有。
CREATE TABLE group_leaves (
  group_did          TEXT NOT NULL,
  member_did         TEXT NOT NULL,
  member_device_id   TEXT NOT NULL,
  crypto_group_id    TEXT NOT NULL,
  epoch              TEXT NOT NULL,
  state              TEXT NOT NULL,   -- active | terminal
  added_by_ref_json  TEXT NOT NULL,   -- 哪次被接受的 add 建立了它
  updated_at         TEXT NOT NULL,
  PRIMARY KEY (group_did, member_did, member_device_id)
);

-- §12.6 的 Device Delivery Queue。与 P5 的 Mailbox 是同一条缝（§6）
CREATE TABLE device_envelopes (
  recipient_did        TEXT NOT NULL,
  recipient_device_id  TEXT NOT NULL,
  seq                  INTEGER NOT NULL,  -- 队列内序；排序规则见 §6.1
  envelope_json        TEXT NOT NULL,     -- 原样，重投必须逐字节复现
  origin_context_json  TEXT,              -- 仅 P6 group.incoming 有（§9）
  attempts             INTEGER NOT NULL,
  enqueued_at          TEXT NOT NULL,
  PRIMARY KEY (recipient_did, recipient_device_id, seq)
);
```

`group_leaves` 的 `state = terminal` 就是 §7 那个终态：该 leaf 已被 Remove，
队列里的最终通知投完即弃，但**行要留着**，否则同一 `(did, device)` 重新加入时
Host 无法区分"第一次进群"与"重新加入"（§10.3 L1066 的触发条件要用到
"该精确设备当前**没有** Leaf"）。

## 12. v1（C13）不做

- **任何 MLS 运算**：`KeyPackage` 解析、`Add` / `Remove` / `Commit` / `Welcome`
  的语义校验、`PrivateMessage` 的加解密、`epoch_authenticator` 的导出。
  §11.11 L1386 明说 Host 不做最终 MLS 有效性判断。
- **`Update` 作为协议级动作**（§11.11 L1382）、**External Commit**、
  `group_join_info` / `get_join_info` / `accept_welcome`（§3.8 L226–231）。
- **多控制者**：只有 owner DID 能 `create` / `add` / 通用 `remove`（§16.5 L1895）。
- **admin 作为控制者**：admin 的业务动作只改 P4 状态，最终由 owner 落到 MLS（§16.5 L1899）。
- **任何 P6 历史拉取 / 已读回执 / 设备同步方法**（§12.6 L1523）。
- **自动 owner MLS 恢复**：§11.12 L1402 要求 fail closed，Host **MUST NOT** 下发
  当前或历史 epoch secret。
- **`group_receipt.proof`**：同 C9 的结论（[groups.md](groups.md) §7），v1 不签。

## 13. 挡住 v1 的

1. **`anp_did_wba_device_binding` 的 ExtensionType 还是草案私有值 `0xF0A1`**
   （§6.3.1 L430）。规范说得很重：**ANP 在发布 v2 前 MUST 公布稳定的注册 code point**，
   改这个值属于 breaking draft revision。§20 L2457 把它列为待建注册表第 5 项。
   这不是本仓库能补的（[TODO1.md](../TODO1.md) 的 `D2`），但**它决定 P6 能不能对外声明**——
   `anp.get_capabilities` 里 P6 **不得**作为稳定 Profile 出现
   （[message-service.md](message-service.md) §15 已写）。
2. **群 DID 文档未发布**：`get_key_package` 之外的所有 group-addressed 方法都要先解析
   `group_did` 找 Host，同 [federation.md](federation.md) §8 第 1 条。
3. **`provider_asserted` 的取舍留给部署**（§10.5 L1082、L1098）：P6 业务策略接受还是拒绝
   由部署定，且 P6 拒绝时 **MUST** 保持 E2EE 消息面暂停——合规行为是 fail closed。

## 14. 需要用户裁定

1. **客户端侧的密码学放哪**——与 [TODO1.md](../TODO1.md) 的 `D4` 是同一个问题，
   而 P6 让它从"以后再说"变成"路线选择"：owner 的 MLS 状态、KeyPackage 私钥、
   epoch secret **全都**在设备侧，本服务一行都没有。见 [e2ee-direct.md](e2ee-direct.md) §9.1。
2. **被移除 leaf 的应用信封是投完还是取消**：§12.6 L1512 给了两个都合规的选项
   （见本文 §6.1）。本设计选了"投完"，因为它对用户更诚实——被移除前最后几条消息还能读到。
   若倾向"立即取消"，改动只在队列的收尾逻辑。
