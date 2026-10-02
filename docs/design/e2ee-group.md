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
MLS 私有状态"——本服务选**不持久化**，于是 [TODO1.md](../../TODO1.md) 的 `D4` 从"P6 才有影响"
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

### 4.1 接线时定下的几处（2026-10-01）

§4.3 的两档安全模式落到方法表上：`publish_key_package` / `get_key_package`（与将来的
`notice`）走 `transport-protected`（L272），四条控制方法走 `group-e2ee`（L273）。两种
`targetScope` 与 P5 那一对同形——§8.2 的幂等键元组比 §8.1 多一个 `target_did`。

1. **§6.4 那十一项里本服务做得了的是 1–8 中不需要解析 `mls_key_package_b64u` 的部分。**
   第 7、8 项（内嵌 extension 与 sibling 的 JCS 字节相同）与第 9–11 项（实际 Leaf 签名
   公钥、MLS `credential.identity`、suite 与时间窗口）都要那份 KeyPackage 的**内部**，
   归接收方的 MLS runtime（§11.11 L1386）。本服务判的是**包装对象的形状**（§7.3）与
   **绑定**（§6.3）。
2. **码的分派。** "这个对象**是**一个 KeyPackage 吗" → **5001**（§17 L1920）；
   "它的 owner / 绑定与这次调用对不上" → **5002**（§17 L1921）。分法与 P5 §13 L1547 把
   "P5 Bundle owner" 归进 `invalid_security_binding` 一致。清单那一半（§6.4 第 1–3 项）由
   资格门禁判，报 P1 那四个设备码——§17 L1930 逐字要求复用，"本 Profile 不定义第二套错误
   信封结构"。
3. **§6.4 第 6 项的读法。** 按附录 B，受保护文档就是"剥掉 `proof` 后的整个对象"，"覆盖"
   对**在场**的字段自动成立。所以这一项唯一有内容的要求是**它们得在场**——`issued_at` /
   `expires_at` 因此也进检查清单，尽管 §6.3 的推荐结构没给它们 MUST（第 11 项本来就以它们
   在场为前提）。
4. **`require_fresh` 规范没有给出语义**（§8.2.2 L743，全篇唯一一处提到它）。本实现只让它
   **收紧** §8.2.4 L763 已有的那条 SHOULD：默认把过期的排在后面、全是过期时才回落；调用方
   要求了新鲜的就 5000。不发明新的拒绝理由，于是这个字段要么不改变服务端行为、要么只让
   既有那条线更严。
5. **绑定在发布与领取两侧都验。** 只验发布的话有一个短窗口：设备换掉 `signing_key_id`
   之后、重新发布之前，柜子里存的那份已经**没有任何合规接收方会用它入群**（§13.2 的重定义
   检查会拒掉），而我们还在照发。§8.2.4 L767 的"返回前 MUST 按当前 Manifest 重验"正是这个
   窗口的封口，也是 `get` 这一档 `recheckOnReplay: true` 的理由（同 §7.2 L578）。
6. **同名重发是忽略，先写者赢。** §8.1.2 没有 P5 §6.2.2 L371 那条"`bundle_id` 不可重定义"，
   而"忽略"顺便封住另一个口子：一枚已经交出去的 KeyPackage 不会被换掉，一枚 `consumed`
   的也不会被复活（§13.2 L1610）。
7. **`params.auth` 既不要求也不禁止。** P5 §7.1 L472 有"未协商扩展时 MUST 缺省"，**P6 §8
   没有这句话**；自造一条禁令会拒掉规范允许的请求。它也不进 SRO 指纹，留下没有安全后果。
8. **`publish_key_package` 的认证由绑定 proof 承担。** §8.1.2 L706 说 v2 **不要求**为这条
   方法额外定义业务层 `origin_proof`，L704 把"调用方 MUST 运行在已认证的本域会话或等价
   hop / service 认证上下文中"交给部署。同域明文没有那一跳时，剩下的就是
   `did_wba_binding.proof`：§6.4 L443 第 3 项要求它由该设备清单里那条 `signing_key_id`
   签出，而那颗私钥只有那台设备有。于是"冒名发布"要拿到别人的设备钥才行——这条方法全部的
   认证就在这里。与 P5 `direct.send` 是**同一处缺口、同一个答案**
   （[e2ee-direct.md](e2ee-direct.md) §9 第 3 条：只保证资格、不保证来源）。

### 4.2 四条控制方法接线时定下的几处（2026-10-02）

四条控制方法（`create` / `add` / `remove` / `send`）与 §4.1 那两条 Key 方法合起来才是 P6
的全部。四条落到方法表上时，下面这几处规范没直说、或直说了但落地要选一个做法：

1. **目标建模的两档，`targetScope` 因此不同。** `create` 是 `service-scoped`（§4.4.1
   L292–293）：它的 `meta.target.did` 是**服务** DID，而幂等键那个元组需要的是它操作的
   `group_did`——所以 `targetScope` 取 `body.group_did`。`add` / `remove` / `send` 是
   `group-addressed`（§4.4.2）：`meta.target.did` **就是** `group_did`，`targetScope` 取它。
   这一档也不进 `checkMethod` 的 group-wide 分支，与两条 Key 方法同形。
2. **四条都要 `auth.origin_proof`，锚点是 `meta.sender_did`。** §9.2.3 / §9.3.3 / §9.4.3 /
   §9.5.3 逐字要求它 **MUST** 在场——这是与两条 Key 方法最大的差别（那两条靠 KeyPackage
   自己的 Object Proof）。它们**不在** `GROUP_ANCHORED` 里，所以 proof 由
   `meta.sender_did` 的钥签，而不是 §6.2.2 那三种通知的 `body.group_did` 群锚点。因此
   `send` 的 §13.3 第 6 项（"证明由该设备当前的 P2 签名钥做出"）要靠签名底里的 `keyid`
   比出来，core 的 `OriginProofOutcome` 为此多回一个 `keyid`。
3. **同 DID 的 Remove 分支 v1 不做，回 5003 `controller_required`。** §9.4.2 第二条 caller
   分支（"同一 DID 的另一台已撤销/已失去资格的设备由本 DID 的当前 leaf 移除"）的前置条件是
   一个**否定**的资格结论，而本服务的资格门禁（`eligibility.ts`）是**肯定**门禁，没有"要求
   它不合格"的表达；同一句还要 Host 权威验证"发送设备有当前设备管理授权"，而 P2 的清单里
   没有这个授权概念（只有 `signingAuthorizedBy` / `e2eeAuthorizedBy` 两个关系）。所以 v1
   只有 owner 分支。这是**收窄**不是放行：一个合规实现不会把该拒的收下，但那条合法路径
   暂时不可用。
   （2026-10-02 裁定按**甲**收下这个收窄，并补上出处：§13.4 L148 逐字写"设备管理授权是受信任的
   部署侧授权事实，不是新的 P6 请求字段。Group Host 若无法权威验证，**MUST** 拒绝该例外，且
   **MUST NOT** 信任调用方自报或展示缓存"。所以这不是"少做了一块"，而是规范为手里没有那份部署侧
   事实的实现**点名要求的**拒绝——现状即合规，没有合规压力。将来要做这条路，先得定出那份授权事实
   的来源（谁写、存哪、怎么签发与轮换），规范明说它不是协议字段；那个信任模型没定之前不开，
   因为定错等于给同 DID 下的设备开了互相移除的权限。）
4. **owner 分支还要一台当前 owner leaf（§13.4 L1640 第 2 项）。** `add` / `remove` 在
   `requireOwner` 之后追加 `requireCurrentOwnerLeaf`：`meta.sender_device_id` 必须是一台
   **合格的当前 owner leaf**。授权那一半（DID 是不是 owner）在事务里判，资格那一半（这台
   设备在不在当前清单里）由 `dispatch` 的设备门禁在事务外判。缺失回 **5013**
   `leaf_not_current` 而不是 5003——调用方**确实**是 owner，授权成立，错的是它这台设备在这个
   群里没有当前 leaf，而 5013 正是 §11.9.1 L1306 列的**发送方侧**终态信号，收到它的应该是
   那台设备自己。副作用：一个还没有任何 MLS 状态的群，owner 发 `add` / `remove` 也从 5004
   变成 5013（没有 leaf 的群，owner 这台设备当然不是当前 leaf）；§13.4 没有给这几项规定
   次序，这条读法站得住。
5. **一次性 nonce 落在 `perform` 内、事务里（§13.6 L1693）。** 那句话要求 Host 受理四条
   控制方法时施加"完整新鲜度窗口 **+** 一次性 nonce 检查"。时间窗那一半本来就在
   `auth.ts` 的 `authenticate()` 里跑；nonce 那一半由 `dispatch.ts` 的 `consumeProofNonce()`
   在 `perform` 内部兑——位置必须在那里，因为"**被拒的请求不该烧掉 nonce**"要靠
   `perform` 的事务回滚：一个 5003 的拒绝会把这次请求插入的 nonce 一起滚掉，同一 nonce
   的重试于是仍能成功。
6. **`send` 刻意不写 `validateBody`，另三条写。** §13.3 L1627 要求第 4/5/6 项（成员 →
   设备 → leaf）判在策略（7）与载荷（8）之前，而 `group_cipher_object` 正是第 8 项。给
   `send` 写 `validateBody` 会把载荷形状**提前**到成员判定之前，正好违反那条 MUST 的次序
   ——所以它只做 §9.5.3 的 `content_type` 检查（那是**请求**自己的形状，先于身份，
   与 `checkMethod` 里"Profile 规则先于 target 建模"是同一条次序）。`create` / `add` /
   `remove` 写了，另有原因：`add` 的 `deviceAddressed` 在处理器之前读 `body.member_did`，
   缺字段会在那里抛 `ConnectxError`（500）而不是一次干净的拒绝。
7. **控制动作一个计数器都不推，`send` 只推事件序。** §14.1 L1705 逐字说进排序链的只有
   `send`；L1707 紧接说 `create` / `add` / `remove` **MUST NOT** 独立产生新的 P4
   `group_state_version`，§9.2.4 连 `group_event_seq` 也一起排除。所以控制动作两个计数器都
   不动，`send` 只推 `group_event_seq`（与 P4 `group.send` 同级），`group_state_version`
   原样回给调用方。

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
所以"群级绑定"不另建一张表：MLS 的 Commit 本来就推进**所有**成员的 epoch，`add` / `remove`
的 `epoch` 按 §9.3.3 / §9.4.3 是"after this add/remove"，于是把新值写到每一条 active leaf
上，群级值就是这些行共同说的那句话。`create` 写下的第一行（owner 自己，§9.2.1）就是初始值。
这带来一条不变量，也是这块唯一的实现约束：

> 同一群的 active leaf 行上，`crypto_group_id` 与 `epoch` 恒等。

`advanceLeaves()` 是**唯一**维护它的地方，`currentBinding()` 是**唯一**读它的地方。
§13.5 第 5 项（"该群当前没有已被接受的 MLS 初始状态"）于是就是"这个群的 active 投影是空的"。

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

**（2026-10-01 更正）** 本节原先写的是"P5 的 Mailbox 与 P6 的 Delivery Queue 是同一张表，
**别建两张表**"——**那是错的**，§11 的 DDL 才是对的。两者共享的是那条**缝**（都以
`meta.recipient_device_id` 定址、都只投给那一台设备），不是**表**：

- P5 的 Mailbox 是**拉的**：`deliveries` 的一行进账号的序号流，订阅路推给在线设备，离线设备
  用 `sync.delta` / `inbox.get` 取回（[e2ee-direct.md](e2ee-direct.md) §4）。
- P6 的队列是**推的**：§12.6 的"传输确认后 Host **MAY** 出队"与"保留期到限即弃"描述的是
  一条重试到底、不成就丢的推送路径，而本 Profile **不定义**任何 P6 历史拉取方法（L1523
  逐字："该队列是投递机制，不是群历史"）。

而且 §12.6 末段把这条路堵死了：部署若提供返回**设备寻址的 P6 信封**的本地历史 API，
它 **MUST** 从**已认证的设备主体**推导 `meta.target.did` 与 `meta.recipient_device_id`，
并 **MUST NOT** 把调用方自述的设备字段当权威依据。本服务的取件面正是**自述**的
（`sync.delta` 的 `body.device_id`）——那是 [e2ee-direct.md](e2ee-direct.md) §9 第 3 条那处
缺口的另一个后果。P6 信封一旦进 `deliveries`，就等于用一条违反该段的路径把它们暴露出去。

所以是两张表。共用的仍然是那条缝，以及 C6 / C7 为它留下的那一列。

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

### 6.2 出站：`delivery/deviceQueue.ts`

§12.6 的入队发生在接受事务里（[§4.2](#42-四条控制方法接线时定下的几处2026-10-02)），
**投递**是另一条 worker，与 P4 的 `delivery/worker.ts` 并排、不共用。它拥有四件事：

**（一）队内顺序是严格队头优先。** §6.1 那张表要的是"一台设备的 `group.incoming` 按
`group_event_seq` 投"，也就是说队中一条投不出去，它**后面**的都不许走。这条规则做在
`dueDeviceEnvelopes` 的查询里，而不是循环里：

```sql
... WHERE d.next_attempt_at <= ?
      AND NOT EXISTS (SELECT 1 FROM device_envelopes e
                       WHERE e.recipient_did = d.recipient_did
                         AND e.recipient_device_id = d.recipient_device_id
                         AND e.seq < d.seq
                         AND e.next_attempt_at > ?)
```

"没有更早的一行还在等"才轮到这一行。它一次解决两个问题：不会在一条队列里跳着投；一条
卡住的队列也不会用它的积压把 `batchSize` 填满、饿死别的队列（每条队列最多贡献一行）。
worker 那一层再加一个已阻塞队列的集合，把"队头失败、它后面的行这一轮都别碰"表达出来——
两层是同一条规则的两种视图，不是重复。

**（二）投递前复核资格。** §12.6 第 3 条要的是**每次尝试前**都拿当前资格复核，让投递在
一台不再是当前合格 leaf 的设备上停下。复核是**两层**的，因为"这台设备还算不算数"有两个
互不包含的来源：

- **第一层是投影**（`group_leaves` / `group_members`）：它还是不是这个群当前的 leaf。
- **第二层是对方的当前 DID 文档**：它还是不是主人 `deviceManifest` 里的一台设备。这一层
  非做不可——一台设备被主人从清单里删掉，**不经过任何我们看得见的控制动作**（`group.e2ee.remove`
  是 owner 事后才做的另一件事，而且只是把一个已经不算数的设备从 MLS 里摘出去），所以投影
  在这件事上永远是旧的。P6 §10.4 L1074 逐字要求 Host "MUST stop authenticating and
  **delivering new service data to the revoked device**"。

| 队列行的处境 | 投不投 | 为什么 |
|---|---|---|
| `kind = final-notice` | 投 | 第 3 条的**第一个例外**：它生来就是发给一台已经不在群里的设备的（§7） |
| leaf 行 `terminal` | 投 | 第 3 条的**第二个例外**："已被移除的 leaf 队列里已经入队的信封"——§6.1 选定的 SHOULD 要它们按序投完。这一档**不看文档**：已经 Remove 的设备，看也是"不在清单里" |
| leaf 行 `active`，其成员不是 P4 `active` | 不投，留队 | §10.4 L1074 / §10.5 L1094：整个成员要在 MLS 那边收尾，中间的 epoch **MUST NOT** 承载应用消息。等 owner 把这条 leaf Remove 掉，第一、二行就接管了 |
| leaf 行 `active`、成员是，但**当前文档里没有这台设备** | **丢弃** | 主人的清单比我们的投影新。留着没有意义：它等的那一天不会来，而 `group.e2ee.remove` 到来时这条 leaf 会转成 `terminal`，落进上面那条"按序投完"的例外——那正是**不该**给一台已撤销设备的待遇 |
| leaf 行 `active`、成员是，设备也还在 | 投 | 正常情形 |
| 查不到 leaf 行 | 不投，留队 | 队列行与投影对不上，没有投递对象；由保留上限收掉 |
| 文档**取不回来** | 按投递失败处理 | 对端 DID 服务器不可达不是"这台设备没了"。混为一谈的代价是：一次网络抖动丢掉整条队列。所以它走既有的失败路径——记一次尝试、退避重试，直到保留上限收掉 |

第二层要读网络，所以它只在**第一层已经把行判成 `active` leaf + active 成员**时才付。这次
解析与"找对端的消息服务入口"共用同一份文档：`config.didResolution` 上挂着一张进程内缓存
（A3a，[message-service.md](message-service.md) §14），同一个 DID 在一个 TTL 窗口内只抓一次，
所以两层加起来仍然是一次抓取，不是两次。

解析成功但设备不在（或钥引用不再被授权）是一个**判定**，解析本身失败是一次**投递失败**——
两者的分界写在 `deliver()` 里：判定走 `drop`，失败落进 `catch`。

**这一层剩下的边界**（记在这里，别再当成漏洞重新发现一遍）：撤销与 `group.e2ee.remove`
之间如果正好有一次 `group.e2ee.send` 入队了信封，而 worker 还没跑到它，那么 `remove` 把 leaf
转成 `terminal` 之后，那条信封会落进"按序投完"的例外，被投给这台已经撤销的设备。窗口是
`[撤销, remove]`，只影响一台正在被移除的设备。收窄它需要在 remove 那一刻也去读一次文档
（`remove` 的受理路径上没有网络调用），那是 [TODO2](../TODO2.md) A3b 之后的事。

**"不投"刻意不动那一行**：既不改投、也不重排。重排会把它记成"我失败了"，而它其实只是在
"等我"——到期那一天由 owner 的 Remove 或保留上限来了结。

**（三）本地投递走订阅，不走 HTTP 回环。** 收件人住在本服务上时，P4 的做法是"已经在本机
躺着了"就丢掉，因为那条消息在 `deliveries` 里有行、`sync.delta` 能取回。P6 **没有**这一行
（[§6](#6-device-delivery-queue第二个-mailbox同一条缝)），所以没有第二条路：得真推给那条
WebSocket 订阅（`registry.publishDevice`）。推不到（设备没连着）**不算失败**——推一次很
廉价，每个 tick 重推换"设备一上线就收到"；真正的收尾交给在队时长闸门。

**（四）保留有界，两道闸门。** §12.6 逐字要求上限是"显式、由部署声明"的：

- **尝试次数**（默认 8，`AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS`）：管 HTTP 那头。与 C9 的 outbox
  同形、同一条理由（P3 §8.4 L477 交给本地策略），到顶丢弃并记一笔。
- **在队时长**（默认 24 小时，`AGENTX_DEVICE_QUEUE_MAX_AGE_MS`）：第二条闸门，也是**唯一**
  能收掉本地那条路的（它不记尝试）。超龄的行在**投递前**扫掉，所以一台长期卡住的设备不会
  把自己的队列永久冻住，MUST NOT 阻塞该群后续 epoch、保留 leaf 的投递、或新
  `group.e2ee.send` 的接受（§12.3 L1456–1458）。

两个数值都是**部署档位**（A5）：§12.6 只要求上限是"显式、由部署声明"的，没给数字，所以落在
`Config` 上（`config.ts` 的 `deviceQueue`，见 [message-service.md](message-service.md) §14）——
改它不用改代码。`deviceQueue.ts` 的 worker 选项只是让测试钉住它们，不再是唯一入口。

丢弃是**有意的放弃**，不是成功，日志里与投递成功分开写。丢弃之后队头让位，后面的行立刻
成为队头——§12.6 的"丢弃 MUST NOT 阻塞"就落在这一点上。丢弃的后果按信封类型各不相同
（丢 Welcome → Remove 再 Add 新 leaf；丢 Commit → Remove 让设备按 §10.3 重新加入；丢应用
信封 → 只丢那一条；丢最终通知 → Host 无动作），本服务只负责丢弃本身，不代客户端做后续。

**为什么它不是 P4 的 outbox。** 那张表按 **DID** 键控（一个账号一条队列），这张按
**`(recipient_did, recipient_device_id)`** 键控。同一 DID 的两台设备是两条独立队列，谁也
不知道对方在收什么——那正是 §12.6 第 4 条要的（`publishDevice` 只认精确的设备 ID，连
"没说代表哪台设备"的连接都不给）。

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

**一处已知偏离**：`dispatch` 的资格门禁在事务外、处理器之前跑（判资格要解析 DID 文档，
事务里不能有网络往返），所以"**既**不是成员**又**设备不合格"的请求拿到的是 core 的设备码
而不是 3000。这不破坏 §13.3 L1625 要的那件事——它要的是三种状态**互不相同**且**次序固定**，
而第 3 条（DID 仍 `active`、设备仍合格、只有 leaf 被移除）判得分毫不差，5013 是唯一的拉取式
终态信号。可达的三种状态里被折叠的是"两错叠加"那一种，它本来就不在 L1625 的三条之内。

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
  event_ref_json   TEXT NOT NULL,   -- 这次 member-did-updated：group_state_ref + 两个 DID
  progress         TEXT NOT NULL,   -- add-pending | remove-pending
  expected_json    TEXT NOT NULL,   -- 待处理的确切 (did, device) 列表
  done_json        TEXT NOT NULL,   -- 已成功的
  started_at       TEXT NOT NULL
);
```

`event_ref_json` 里除了被引用事件的 `group_state_ref`，还存着 `previous_subject_did` /
`subject_did` 两个 DID：编排每一步都要用到它们（新 DID 用来认出"这次更新的 Add"、旧 DID 用来
拒掉瞄向别处的 Remove），而从 `group_state_ref` 再推一次没有意义。

串行化不需要新机制：`BEGIN IMMEDIATE`（C4 已定）就是"同一时刻只有一个控制动作在改这个群"。
§13.4 L1646 的"拒绝或延后无关的 Add/Remove"落成事务内的一个检查——
**拒绝**比延后简单，且 L1647 只要求同一 P4 事件的重试有幂等语义。

**新 `group.e2ee.send` 的入口检查多一条**：该群若在编排中间态，`send` 返回
`group.e2ee.state_not_ready`（5004）——§17 L1933 明确说 DID 更新编排"状态尚未就绪"时复用
这个码，**不新增专属错误码**。

**落地（2026-10-02）：两个证人取或，编排行有写入者了。** 暂停由两处任一成立，`paused()`
（`rpc/groupControl.ts`）：

- **投影现算**。投影里有一条 active leaf，它的 `member_did` 已经不是 P4 `active` 成员——那
  正是"整个 P4 成员变 `removed` / `left`，而 MLS 那边还没收尾"这句话的可观测形态
  （`create` / `add` / `remove` 建立 leaf 时那个 DID 是 active 的）。§8.12 的改名**只换成员行、
  不动 leaf**，所以旧 DID 的 leaf 从改名那一刻起就落进这句话里，直到最后一次 Remove 把它转成
  `terminal`。这一条是**重建**出来的，重启后照样判得出来。
- **编排行剩余工作**。`applyMemberDidUpdate`（`rpc/groups.ts`）在"这次更新还留着旧 DID 的 leaf
  要退役"时开行，`expected` = 那批 leaf。它不是投影那条的替代而是补强：投影记的是"有一件没收尾
  的事"，编排行记的是**哪一次**更新、还差哪些 leaf——`add` / `remove` 的受理要用到后者。
  一行陈旧到没有剩余工作时不算数（读完还剩余为空的残留、或崩溃留下的），投影才是权威。

写入者不是 P4 的 `member-did-updated` 事件：§8.12 那个 `group.member_did_update` 是**宿主动作
标识符，不是 JSON-RPC 方法**（客户端调它 MUST 得 `-32601`）。行由 Host 自己执行改名的那一步
（`applyMemberDidUpdate`）就地写下。验收见 `rpc/groupControl.test.ts` 的 §10.5 那一节。

**那么谁会走到那一步**：§8.12 点名的三条触发路**都实现了**，且都收敛到同一个原子改名，所以
任一条发现的换 DID 都得到同一套编排与同一次暂停——**请求触发**（一个可能的新 DID 来发
`group.send` / `group.leave` / `group.update_profile` / `group.update_policy`，或来读私有群的
`group.get_info`）、**投递触发**（正要投给名册里的一个旧 DID 时先看一眼它有没有合规后继，挂在
设备队列投递前那次资格复核上）、**定时刷新**（`refresh/memberDidRefresh.ts`，低负载周期扫描，
见 [message-service.md](message-service.md) §14）。第三条是唯一能碰到**安静的成员**的：不请求、
也收不到信封的成员，前两条永远不会经过它。三条各自的取舍与界都记在
`rpc/memberDidUpdate.ts` 的文件头。

**设备级撤销那个例外不进入这个状态**：§10.4 L1074 说此时 Host **MUST NOT** 仅因该 leaf
尚未移除就暂停其它合法 `group.e2ee.send`。所以暂停态只由**整个 P4 成员**的 DID 更新建立——
投影现算只认"DID 已非 active 成员"这一条，编排行也只由换 DID 建行，单台设备被撤销两者都不触发。

**串行化的边界**：§10.5 要"全部 Add 成功之后才有第一个 Remove"，而 Host 数不出 owner 一共选了
几台新设备（那是 owner 按 §11.12 第 2 步自己枚举的）。所以第一次被接受的 Remove 被记成"Add
阶段结束"，而不是"Host 核对过 Add 都成功了"——那行随之翻成 `remove-pending`。

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

-- §12.6 的 Device Delivery Queue：推的、可重试、有界的队列，与 P5 的 Mailbox 只共享那条缝（§6）
CREATE TABLE device_envelopes (
  recipient_did        TEXT NOT NULL,
  recipient_device_id  TEXT NOT NULL,
  seq                  INTEGER NOT NULL,  -- 队列内序；排序规则见 §6.1
  group_did            TEXT NOT NULL,     -- §12.6 第 3 条每次尝试前要重查 leaf 投影
  kind                 TEXT NOT NULL,     -- incoming | commit | welcome | final-notice（§6.1）
  envelope_json        TEXT NOT NULL,     -- 原样，重投必须逐字节复现
  origin_context_json  TEXT,              -- 仅 P6 group.incoming 有（§9）
  attempts             INTEGER NOT NULL DEFAULT 0,
  next_attempt_at      TEXT NOT NULL,     -- 重试要退避，所以不是"入队即到期"
  last_error           TEXT,
  enqueued_at          TEXT NOT NULL,
  PRIMARY KEY (recipient_did, recipient_device_id, seq)
);
CREATE INDEX device_envelopes_due ON device_envelopes (next_attempt_at);
```

`kind` 不是分类学，是**§6.1 那张表要的例外**：只有 `welcome-delivery` 允许越过待投的应用
信封，其余一律排队头。`attempts` / `next_attempt_at` / `last_error` 与 `outbox` 同理——
一次投递失败要有下次，且要有证据。`group_did` 单列而不是从 `envelope_json` 里现取：§12.6
第 3 条要求**每次尝试前**重查该群的 leaf 投影，而 JSON 解析一次只为拿一个键没有理由。

队列只存**待投**的行：传输确认即删（§12.6 "MAY 出队"），到保留上限也删——两处"到限即弃"
与 C9 的 outbox 是同一类收尾，只是另一条队列（§7）。所以这里没有 `state` 列：一行在或不在
就是全部状态。取件走 `dueDeviceEnvelopes`，那条查询里带着**队头优先**的判据（[§6.2](#62-出站deliverydevicequeuets)）——
一台设备一条队列，最多返回它的队头。

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
- **同 DID 的 Remove 分支**（§9.4.2 第二条 caller）：撤销本 DID 自己另一台设备的 leaf。
  前置是否定资格结论，与肯定资格门禁不合；见 §4.2 第 3 条。走这条分支的请求回 5003。
  （2026-10-02 裁定保留此收窄：§13.4 L148 明写 Host 无法权威验证那份部署侧授权事实时
  **MUST** 拒绝，故现状即规范要求的拒绝。）
- **admin 作为控制者**：admin 的业务动作只改 P4 状态，最终由 owner 落到 MLS（§16.5 L1899）。
- **任何 P6 历史拉取 / 已读回执 / 设备同步方法**（§12.6 L1523）。
- **自动 owner MLS 恢复**：§11.12 L1402 要求 fail closed，Host **MUST NOT** 下发
  当前或历史 epoch secret。

## 13. 挡住 v1 的

1. **`anp_did_wba_device_binding` 的 ExtensionType 还是草案私有值 `0xF0A1`**
   （§6.3.1 L430）。规范说得很重：**ANP 在发布 v2 前 MUST 公布稳定的注册 code point**，
   改这个值属于 breaking draft revision。§20 L2457 把它列为待建注册表第 5 项。
   **官方 SDK 已经把这条做成显式门禁**：Rust crate 里 `DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2
   = 0xF0A1`（`rust/src/group_e2ee/v2_models.rs:13`），并定义了 `ErrP6V2PublicReleaseBlocked`
   ——"P6 v2 public release is blocked until the draft MLS extension has a stable registered
   codepoint"（`rust/src/group_e2ee/v2_errors.rs:84`）。本仓库照抄这个位置：
   **代码可以写，`anp.get_capabilities` 里 P6 不得作为稳定 Profile 出现**，直到上游公布
   稳定 codepoint。（[TODO1.md](../../TODO1.md) 的 `D2` 已按此裁定。）
2. ~~**群 DID 文档未发布**~~（2026-10-02 收）：`get_key_package` 之外的所有
   group-addressed 方法都要先解析 `group_did` 找 Host，而那份文档此前没有人发布。B1b 把
   发布义务落在**群自己所在的域**（`group_did = serviceDid + ":g:" + <id>`，本服务发布自己
   名下的那些），同 [federation.md](federation.md) §8 第 1 条。别人名下的群仍要靠它自己的
   Host 发布，那部分从来不在本仓库。
3. **`provider_asserted` 的取舍留给部署**（§10.5 L1082、L1098）：P6 业务策略接受还是拒绝
   由部署定，且 P6 拒绝时 **MUST** 保持 E2EE 消息面暂停——合规行为是 fail closed。

## 14. 已定的两件事

1. ~~**客户端侧的密码学放哪**~~（2026-10-01 定：**(a) 内嵌**，见 [e2ee-direct.md](e2ee-direct.md)
   §9.1 —— 与 [TODO1.md](../../TODO1.md) 的 `D4` 同一个问题、同一个答案。owner 的 MLS 状态、
   KeyPackage 私钥、epoch secret **全都**在设备侧，本服务一行都没有；官方方向是库调用而非子进程）。
   **方案见 [client-mls.md](client-mls.md)**（[TODO4.md](../../TODO4.md) §B2，2026-10-02 落）——
   那一块今天在本仓库里一行都不存在，是 P6 唯一还空着的一半。
2. ~~**被移除 leaf 的应用信封是投完还是取消**~~（2026-10-01 用户裁定：**按序投完 (a)**。
   用户同时指出一个事实，记在这里：**已经送达并被读到的消息，无法再收回**——最终通知只能
   告诉设备"你已被移除"，不能让已经解密的明文消失。这是产品取舍，不是技术限制；
   若改"立即取消"，改动只在队列的收尾逻辑。）
