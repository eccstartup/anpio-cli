# 群组（P4）—— Group Host 语义设计

`AgentXAgent` 就是 P4 说的 **Group Host Service**：§3.2 L86–90 要求所有会改变群状态的操作
**MUST** 经它接受与排序，每次已接受的状态变更分配一个新的 `group_state_version`。

[message-service.md](message-service.md) §4 只列了方法名。这份写它背后的东西：两个单调量、
成员状态机、权限判定、群消息怎么落进收件箱、以及回执为什么在 v1 里没有签名。

## 1. 两个单调量与"什么推进什么"

P4 最容易混的是三件事（§6.2–§6.3 与图 P4-1）：状态变更推进 `group_state_version`、
群消息**不**推进、而两者都推进 `group_event_seq`。

| 动作 | `group_state_version` | `group_event_seq` | 出处 |
|---|---|---|---|
| `group.create` | 1（初值） | 1（初值） | §6.2 L237、§15.1 L1315–1316 的示例 |
| `group.join` / `group.add` | +1 | +1 | §7.10.1 L570 |
| `group.remove` / `group.leave` | +1 | +1 | §7.10.1 L572–573 |
| `group.update_profile` / `group.update_policy` | +1 | +1 | §7.10.2 L583–584 |
| Host 动作 `group.member_did_update` | +1 | +1 | §8.12 L946 |
| `group.send` | **不变** | +1 | §6.2 L238–239、§10.2 L1031–1033 |

落在 `groups` 表那两列上（[message-service.md](message-service.md) §7），并且**与成员、
事件的写入同一个事务**：§10.1 L1015 要的是"线性顺序"，两个事务里各取一次序号得到的不是
顺序，是两次独立的取值。`BEGIN IMMEDIATE` 已经在那边设好。

`group_event_seq` 是一个**共用**计数器，而 `group_events` 表只记状态变化事件——群消息的
重放来源是 `deliveries`。于是 `group_events.event_seq` 是**不连续**的，这是有意的，也正是
§6.3 L248 "**MUST** 覆盖群控制操作与群消息"要的形状：**一个序号空间，两张表各记自己那半。**

## 2. `group_did` 的形状

规范只说"由 Group Host 分配"（§6.1 L221–227），没说形状，也没规定它必须可解析。本服务的
选择（**这是本服务的选择，不是规范转述**）：

```
group_did = serviceDid + ":g:" + <id>
```

`<id>` 是 128 位随机数的无填充 base64url，`serviceDid` 原样保留——群住在给它发号的那个服务
自己的命名空间里，而不是另起一个域名。对 `did:web` 而言它正好是一条子路径
（`did:web:groups.example:g:XXXX` → `https://groups.example/g/XXXX/did.json`）。

两条依据：

- §6.1 L227：`group_did` **MUST NOT** 等同于任何密码学实现里的内部 `group_id`。这里给的是
  随机不透明串，与 P6 的 MLS group id 没有任何推导关系。
- §13.3 L1178–1180 要求公共发现不暴露不必要的状态。随机 id 而不是自增序号，就是这条落在
  标识符上的部分——自增的话，一个陌生人能靠猜出这个服务建过多少个群、按什么顺序建的。

形状上不带 fragment 也**是**我们的选择（规范没为 `group_did` 写 P2 §8.7 L512 那条对
`serviceDid` 的约束）：同一条理由在这里一样成立，`#` 会把"这个群"悄悄变成"它的某个 key"。

**这个 DID 的文档 v1 不发布。** 本服务不托管 DID 文档，与
[message-service.md](message-service.md) §13 那条服务条目是同一条接缝：`did:web` 的文档由
真正托管 DID 的服务（`awiki-open-server`）发布，里面再放一条指向本服务的 `ANPMessageService`
条目——[cli.md](cli.md) §3.4 说的"群与 Agent 收敛到同一条发现路径"（P2 L546–548）就是它。
v1 同域调用不需要解析它，所以这条缺口不挡 C9；它挡的是本文 §7 的回执签名与 C11 的跨域。

## 3. 成员、角色与状态机

`group_members` 每行是一个 **DID 级**成员：§3.4 L98–100 规定设备、副本、工作器都不进 P4
语义，`group_member` 也 **MUST NOT** 携带任何设备标识（§7.2 L393）。

```
(不存在) --join(add)--> active --leave--> left
                          |
                          '--remove--> removed
```

- 角色取 §6.4 L279–291 那三档，层级固定 `owner > admin > member`；`role` 缺省解释为
  `member`（§7.2 L384）。
- `group.add` 的目标若**当前**已是 `active` → 3001 `group.already_member`：§12 L1156 那句
  话就是"目标已经是群成员"。
- `group.add` 的目标若是 `left` / `removed` → **重新激活**。§8.4 只要求"确认目标当前活动"，
  而 3001 说的是"已经是成员"——曾经是成员不是现在是成员。重新激活覆盖 `joined_at` /
  `added_by`：它们是这条成员关系的属性，不是那个 DID 的属性。
- `group.remove` 的目标不是 `active`（含不存在）→ §8.5.3 L725 要求 **MUST** 拒绝但没给码。
  本服务用 3005 `group.member_conflict`，**不用** 3000：3000 的定义是"**调用方**不是该群
  成员"（§12 L1155），而这里调用方是成员，冲突的是目标的成员状态。
- `group.leave` 只要求 `meta.sender_did` 是当前成员（§8.6.2 L749），没有权限键。

**不发明"最后一个 owner 不能走"这类规则。** §8.5 / §8.6 都没说不许，加上去就是替 Profile
立规矩（同 [message-service.md](message-service.md) §5.1 对年龄上限的处理）。代价是写出群
可能失去 `update_policy` 的授权者——这是规范留白，记在这里，而不是偷偷补一个 3003。

**存储**：`group_members` 现在缺 §7.2 L379–380 的 `joined_at` / `added_by` 两列，而它们是
`group_member` 对象的一部分（`group.get_info` 返回它）。C9 随一次 v3 迁移补上，`ALTER TABLE
ADD COLUMN` 加可空列不需要重建表。

## 4. 权限判定

判定全部走 `group_policy`（§11.3 L1074–1085），不接受"服务端的隐含规则"：

| 方法 | 依据 |
|---|---|
| `group.create` | 无（创建者成为 `owner`，§8.1.2 L632） |
| `group.get_info` | 无权限键；`discoverability` 决定要不要身份（§8.2.2 L658–660） |
| `group.join` | `admission_mode == "open-join"`（§7.1 L366–367） |
| `group.add` | `permissions.add` |
| `group.remove` | `permissions.remove` |
| `group.update_profile` | `permissions.update_profile` |
| `group.update_policy` | `permissions.update_policy` |
| `group.send` | `permissions.send`，且当前是 `active`（§17 L1582） |
| `group.leave` | 无（是当前成员即可） |

角色满足规则用 §6.4 L289–290 的层级：要求 `member` 时 `admin` / `owner` 自动满足，要求
`admin` 时 `owner` 自动满足。

- 权限不足 → 3003 `group.policy_violation`。
- `group.get_info` 的**投影**也是授权问题：`member_list` 只给有权看的调用方（本服务按"是当前
  `active` 成员"判，非成员或匿名者只拿到资料快照），请求超出可见范围 → 3003（§8.2.2 L660）；
  `member_count` 是**十进制字符串**，数的是 `active` DID（§8.2.3 L674）。
- `group.join` 在非 `open-join` 时 → **也是 3003**，尽管 3002 `group.admission_not_allowed`
  看起来更贴：§8.3.2 L686 明写 "**SHOULD** 返回 `group.policy_violation`"，照它。
- 于是 **3002 在本服务里没有产生它的路径**。它的定义里还有"入群前置条件不满足"，而 v1 的
  入群没有带外凭据这类前置——§3.7 L135 明确把邀请链接 / Join Token 划出核心，§7.3 L399–403
  又要求它们 **MUST NOT** 在 `group.join` 成功前制造标准成员状态。留着一个不发的码，比造一个
  场景去用上它诚实。
- `max_members`（§7.1 L370）超限 → 3003；数的是 `active` **DID** 数，不是设备数（L370 后半句）。

**缺省 `discoverability` 取 `private`。** §7.4 L414 只列了 `private` / `listed` / `public`
三个推荐值，没说缺省。取最紧的那个：§8.2.2 L659 要求私有群必须提供身份，缺省成 `public`
等于把一个刚建好的群默认公开，而这个错误是**安静**的——暴露的是资料与成员列表，不是一条报错。

## 5. 认证与锚点

- 除 `group.get_info` 外全部要 `auth.origin_proof`（§8 L590–594、§7.7 L455），锚点是
  `meta.sender_did`，即 `callerAnchor()` 的普通请求那一栏（[message-service.md](message-service.md) §5.1）。
- `group.get_info` 是**第一个 proof 可选、由群状态决定**的方法：§8.2.2 L658 允许
  `public` / `listed` 群匿名读。所以它的 `requiresOriginProof` 返回 `false`，"私有群必须有
  身份"落到 handler——这一条判不进方法表，因为它取决于库里的那一行。
  匿名省的是**身份**，不是**定址**：它的 `meta.target` 仍然必填（§8.2.2 L648–649），
  `kind` 仍然是 `group`。
- 认证失败的码走 P4 自己那对：3008 `group.invalid_origin_proof` / 3009
  `group.origin_did_mismatch`，正是 §11.2 L1067–1068 的两条 MUST，也正好对上
  `AuthErrorCodes` 的结构。
- **两种通知的 sender 不是一回事**，这是 P4 里最容易写错的一行：`group.state_changed` 的
  `meta.sender_did` 是 `body.group_did`（§8.11 L921），而 `group.incoming` 的
  `meta.sender_did` 是**原始发送者**（§8.10 L880）。`callerAnchor()` 的群通知分支按
  `body.group_did` 取锚点，就是为前者准备的。

## 6. 群消息怎么落进收件箱

`group.send` 被接受后，在**同一个事务**里：

1. 写一行 `messages`（`target_did` = `group_did`）；
2. 为每个**当前 `active`** 成员写一行 `deliveries`，`method` 是 `group.incoming`（§8.10）；
3. 推进 `group_event_seq`，**不动** `group_state_version`（§10.2 L1031–1032）。

**不给发送者写投递行**——与 `direct.send` 同一套模型：`inbox.get` 用 `messages` 补出站那一半
（[message-service.md](message-service.md) §9.3），给发送者也写一行会让同一条消息在两条路上
各出现一次，而客户端没有理由去重。于是 `group.incoming` 只发给**其余** active 成员。

推送照 [message-service.md](message-service.md) §8 的三段：事务提交之后交给 outbox，目标按
`recipient_did` 现推 endpoint；解析出来就是本服务时不做 HTTP——`deliveries` 那行已经持久，
同域成员靠拉取。

`group.incoming` 是 Notification，信封形状逐条照 §8.10 L874–883（含 `meta.target.kind =
"agent"`、`meta.target.did` = 收件人、`meta.operation_id` / `meta.message_id` /
`meta.content_type` 与原始请求一致），`body` 照 L887–899。

## 7. 状态变化通知与"最后一封"

`group.state_changed` 的 `body` **直接且只**承载一个 §7.10 的事件对象（§8.11 L922），并且
与它锚定的 `group_event_seq` 同序（§7.10.1 L569）。事件与 `group_receipt` 的形状照 §7.10.1
与 §7.9。

§8.11 L926–928 那条例外是这一节的实现重点：`member-removed` / `member-left` **MUST** 额外给
`subject_did` 发一份**最终**的自身作用域 envelope，而它的重试与保留 **MUST** 受显式的部署上限
约束，到限 **MAY** 丢弃，且 **MUST NOT** 为已移除 / 已离群成员无限期保留投递状态。

本服务**不新造一套机制**：这封走已有的 outbox，而 outbox 本来就有尝试上界
（[message-service.md](message-service.md) §8.4 的 fail-closed：到顶丢弃）。于是"显式上限"
就是那个上界，"不无限期保留"由"到顶即删行"满足。移除 / 离群之后那个 DID 不再是 `active`，
新的 `group.incoming` 不会再生成——需要收尾的只有这一封。

`deliveries` 里那些**已经投递过**的历史行不属于"投递状态"：它们是收件箱内容，按 owner 自己
的策略清理，与成员资格无关。删成员时顺手清空他的收件箱，等于用一次治理动作抹掉他自己的历史。

`group_receipt.proof` **v1 不签**。§7.9 L516 只在回执会离开 Host 所在域并被别的域依赖时才
**MUST** 有 proof，§8 开头 L598–599 把这条与跨域绑在一起。同域 v1 的回执**字段齐全、`proof`
缺席**：它证明的是排序位置，而那个位置在同域内没有第二个验证方。要签它需要 `group_did` 的
`assertionMethod` 私钥与一份可解析的群 DID 文档（本文 §2 的缺口），两件都是 C11 的活。

## 8. merge patch 校验的是**合并之后**的对象

`group.update_profile` / `group.update_policy` 的 patch 走 RFC 7386（§8.7.2 L780、
§8.8.2 L806）。§7.1 给 `group_policy` 的结构是硬的：`permissions` **MUST** 包含**且仅包含**
五个标准键（L353–358），`admission_mode` **MUST** 取两值之一（L349–351）。

- 校验 patch **不是**校验结果：一个 patch 可以塞进第六个键，或把 `admission_mode` 改成任意
  串，而 patch 本身完全合法。
- 所以顺序是 **apply → validate**，失败就不落库（在一个事务里天然回滚）。
- 分码：patch 不是 JSON 对象 → 1003 `anp.invalid_params_shape`；合并后的对象违反 §7.1 的结构
  → **也是 1003**，因为它违反的是**对象定义**，不是群策略的授权规则——3003 留给"你没这个
  权限"。

`group_profile_patch` 同理，但 §7.4 的字段全是 MAY，没有可违反的结构。

## 9. 幂等

§10.3 L1037–1044 给的键是 `(sender_did, group_did, method, operation_id)`，正是 core
`idempotencyKey()` 的形状，`target_scope` 取 `meta.target.did`：

- 面向既有群的操作用 `group_did`；
- `group.create` 取 `serviceDid`——那时群还不存在，而 §10.3 的四元组显然假定它存在。**这一处
  是本实现的读法**，规范没为它给形状。

`group.send` 的**消息级**重复识别（§10.3 L1046–1052）由 `messages` 的三元组主键兜住，与
`direct.send` 完全同形。

**DID 更新后旧 DID 的重放**（§14.15 L1202 要求"在旧 DID 被拒绝前返回其精确幂等重放结果"）
不需要额外代码：C4 的 `acceptOperation()` 先查幂等台账、命中就不进 `perform`，而"旧 DID 被拒"
发生在 `perform` 里——它根本不会被调用。

## 10. 错误码

§12 L1153–1164 那一段（**无 3004**，[message-service.md](message-service.md) §4.1 已记）。
它不在 P1 那张公共表里，所以走 `profileRejection(code, anpCode, …)` 而不是 `anpRejection`。

## 11. 能力清单不用手写

群方法加进 `rpc/methods.ts` 的表之后，`anp.group.base.v2` 会自动出现在
`/.well-known/anp-message-service.json` 与 `anp.get_capabilities` 里——两份清单同源于方法表的
规则见 [message-service.md](message-service.md) §13，不需要为群单开一条。

## 12. v1（C9）不做

- `group_receipt.proof`：见本文 §7。
- 跨域 fan-out：C11。
- **"目标 DID 已被替代"这条拒绝**：`group.create` 的 `initial_members` 与 `group.add` 的目标
  若已被替代，§8.1.2 L634 / §8.4.2 L700 要求回 `anp.did_superseded` 且 **MUST NOT** 改写已
  签名请求。能判的只有"解析不到 / 文档声明停用"那一类；"解析得到，但它是同一个主体的后继"
  需要 P2 的迁移验证，与 [message-service.md](message-service.md) §10 那条 DID 停用路径同批
  ——都在 C11。在此之前不假装判过。
- E2EE：群策略要求 `message_security_profile = "group-e2ee"` 时，`group.send` 与 member-only
  群操作 **MUST** 被拒（§11.7 L1114–1117），本服务回 3006 `group.security_mode_required`。
  这与"客户端自己把 `meta.security_profile` 写成 `group-e2ee`"是两件事：后者由方法表回
  1002 `anp.unsupported_security_profile`——本服务根本没实现那个 Profile，与群策略无关。
  P6 是 C13。
- **`group.member_did_update` 永远不是可调用方法**（§8.12 L934）：`lookupMethod()` 里没有它，
  落到默认分支就是 `-32601`。
- 历史回放、强同步、设备级成员关系与投递：§3.5 L104–113 的非目标。

## 13. 与 CLI 的接口

[cli.md](cli.md) §3.4 已经定下命令面（`create` / `info` / `members` / `join` / `leave` /
`send`），服务端要收下的正是那六条的形状：`meta.target` 两档、`--policy` 的浅合并发生在客户端、
`members` 就是 `group.get_info` 带 `include_member_list = true`。

`group.add` / `group.remove` **没有命令但必须有实现**：§14 L1191–1192 的最小互通要求里它们
都在，而命令面少动词是客户端的取舍（[cli.md](cli.md) §3.4 记了代价：没有 `--policy
admin-add` 的群从命令行填不满）。
