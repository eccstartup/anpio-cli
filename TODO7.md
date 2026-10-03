# TODO7 —— 读本地、取远程

这份接 [`TODO6.md`](TODO6.md)（文档、测试、通讯录——把"至少我要能跑通"补上）。
TODO6 写完了一整轮**写**侧：本机消息库 `messages.db` 的写入侧落地，服务端投递进来的每一条、
以及本机发出去的每一条，都落库。这一轮动的是它**刻意没碰**的那一侧——**读**。

范围由用户 2026-10-03 的一句话定死：

> 读聊天记录就是读本地，远程是 fetch，把交互重新设计，先放着，记下来

于是这一轮是两半，而且第二半不是"顺手"：**客户端**（§2 读侧重画）与**服务端**（§3 ack /
保留 / 补拉 / 换钥）。TODO5 §8 D 把话撂在那儿了——「**这不是客户端单方面能解决的。**」

`~~划掉~~` / `- [x]` 表示做完或有结论。

---

## 1. 现状（2026-10-03 量出来的）

| 事实 | 量法 |
| --- | --- |
| `messages.db` **写入**侧已落地，**读**侧一行没动 | `MessageStore` 的公开面只有 `open` / `record` / `applied_seq` / `message_count` |
| 后两个**谁也没在用** | `grep -rn 'message_count\|applied_seq' rust/crates/agentx-cli/src` → 除 `messages.rs` 自己与单测外 **0 行** |
| 全仓只有两处打开本地库，**都是写** | `MessageStore::open` → `cmd_msg_listen`（[main.rs:3247](rust/crates/agentx-cli/src/main.rs#L3247)）与 `record_outgoing`（[main.rs:2727](rust/crates/agentx-cli/src/main.rs#L2727)） |
| `msg inbox` / `msg show` / `msg read` 仍然**只问服务端** | 读这一族的语义写在 [client-messages.md](docs/design/client-messages.md) §8；当时是"读侧还没动——`msg inbox` 仍然只问服务端" |
| 服务端**从不裁剪** `deliveries` | `grep -rn -i 'delete.*from deliveries' packages/service/src` → **0 行** |
| `delivery_cursor` 的**唯一**写入者是 `stream.ack` | [sqlite.ts:653](packages/service/src/storage/sqlite.ts#L653) `advanceCursor` |
| P6 设备队列有界保留：**8 次 / 30 天** | [config.ts:46-47](packages/service/src/config.ts#L46) |
| 取件面可读窗口：**30 天**（不删，只是看不见） | [config.ts:59](packages/service/src/config.ts#L59) |
| 取件面 `x_agentx.inbox.v1` 是**本服务的扩展**，规范里没有 | [inbox.ts](packages/service/src/rpc/inbox.ts) 抬头；规范 P3 §1 / P5 §10.7 / P6 / P8 §35 都排除 |
| `direct.get_history` 有形状、**v1 不实现** | [message-service.md:785](docs/design/message-service.md#L785)（`since_seq` 没有定义） |
| 换钥后 `deliveries.owner_did` **不跟着迁** | [message-service.md:914](docs/design/message-service.md#L914)——「这一条是已知的、还没解的问题」 |

**两句话**：

1. 本地库今天是**一支笔，不是一个书架**——它在收，但没人能从它里头问出任何东西。
   `msg inbox` 打出的是**服务端还有什么**，不是**我有什么**。这两句在离线、在服务端重装之后、
   在设备队列过期之后，会给出不同的答案。
2. 读被挪到本地，牵出的不是"加个查询"，而是**服务端一侧的一串决定**：ack 之后能不能删、
   设备队列留多久、历史怎么补拉、换钥之后那批投递挂在谁名下。**光改客户端只会把一份真相
   分成两份不一致的真相。**

---

## 2. 读侧：重画交互，不是加旗标

先说清这一条**为什么是一整节**而不是一行：用户裁定的是**方向**（读 = 本地，远程 = `fetch`），
而 `docs/design/client-messages.md` §8 里那三条候选（`msg inbox` 本地优先 / 新增 `msg history`
/ `--local`）**不是可以挑的菜单**——它们都是在旧的命令面上打补丁。真动时按新方向**重画命令面**。

- [x] **先把交互画完，再动一丁点代码。** 画的产物是一份"读这一族命令长什么样"的说明，
      落回 `docs/design/client-messages.md` §8（**唯一**的落点——`cli.md` 2026-10-03 随 TS 客户端
      退役缩成 101 行 6 节，读这一族不再在那里）。**2026-10-03 画完了**，形状是：
      - **`msg inbox` 名字不变、语义变**（服务端有什么 → 我有什么）。不改名是因为它说的
        本来就是"我的收件箱"，而改名是破坏性动作；变的是**它回答的问题**。
      - **新增 `msg history <peer_did>`**：读一个会话（一条线，正序），与读一个收件箱
        （全部会话按时间摊平）是两个问题。**只收 DID、不收名字**——名字只活在服务端册子里，
        收名字就等于让读命令联网。
      - **"列会话"不在这一轮**：那是按会话聚合的另一个形状，还没有消费者。
      - **`msg show <message_id>` 读本地那一行**，不联网。
      - **只有 `fetch` 联网**，它是一次写（走 `sync.delta`，复用 `msg listen` 的
        `records_from` + `MessageStore::record`，靠去重键与游标单调双重重幂等）。
      - **`msg read` 的归属 2026-10-03 已裁定**（§4）：**只放本地**，所以它是这一族里的
        一次**本地写**。详见 [client-messages.md](docs/design/client-messages.md) §8 与其
        8.1/8.2/8.3/8.4/**8.5（已读归本地）**/8.6。
- [x] **`fetch` 是一次显式的写，不是一次读。** 语义是"把服务端**还有的**搬进本地库"。
      要定死：
      - 它落到哪张表、是不是**与 `msg listen` 同一条写入路径**（`MessageStore::record` + 去重键
        `(conversation_id, sender_did, message_id)`），还是另开一条；
      - **重复调用是幂等的**——靠已有的去重键，还是靠游标（`fetch` 之后本地游标推不推？）；
      - 它和 `msg listen` 的补齐是**同一次搬**还是两条路（`msg listen --once` 今天等于 `inbox`，
        `fetch` 落地后这个"等于"还成不成立）。

      **2026-10-03 三条都有答案，而且是同一句话的三个面**（设计见
      [client-messages.md](docs/design/client-messages.md) §8.3，代码在
      [main.rs](rust/crates/agentx-cli/src/main.rs) `cmd_msg_fetch`）：
      - **同一条写入路径**，不是另开一条。`sync.delta` 的每一项本来就是订阅路会推的那一帧
        `{seq, method, params}`，所以 `decode_message(&frame, seq)` → `records_from` →
        `MessageStore::record` 三行就是 `msg listen` 的那三行。为此 `records_from` 从
        `pub(crate)` 提到 `pub`——**它是 lib，bin 是另一个 crate**，"给 bin 用"必须是 `pub`。
      - **幂等是两重的**：行一级靠去重键（`INSERT OR IGNORE`），游标一级靠
        `sync_state.applied_seq` 的 `MAX(...)` 单调。**游标推**，因为搬的就是投递——`record`
        一见到 `service_seq` 就推进它。于是**不带 `--since` 的 `fetch` 是"从我上次停下的地方
        接着搬"**，`--since` 是显式重搬（排查用）。
      - **是同一次搬。** `msg listen --once` 之后**等于 `fetch` 再加打印**：两者都走 §8.3 的
        同一个 `sync.delta` 分页循环（`since` / `limit: DELTA_PAGE` / `device_id`，页到
        `has_more` 为假，守卫 `next_since > cursor`）。差在**消费者**：listener 把帧交给
        `RecordingView`（打印 + 落库，并让 §12 的帧走 MLS 收端），`fetch` 直接落库。因此
        `fetch` 遇到 `meta.security_profile == "group-e2ee"` 的帧**跳过并点名**——它没有 MLS
        收端，既解不了也不能把密文当成消息记下来（`is_group_e2ee_frame` / `unfetchable`）。
- [x] **只有 `fetch` 会联网，其余读都不联网。** 这条是上面那句裁定的直接推论，要写成
      **可断言的行为**：断网时 `msg inbox` 照样答（除非真的本地什么都没有），
      而 `fetch` 断网要明确失败并说清"这是要联网的那一条"。

      **2026-10-03 写成了 `scripts/e2e.sh` 最后那一节**（"only msg fetch goes online — the read
      family answers with the service killed"）：把服务**杀掉**之后再跑，carol（有身份、库里
      一行没有）的 `msg inbox --json` 退出 0 并说 `"messages": []`，bob（有记录）的
      `msg inbox` / `history` / `show` / `read` 全部退出 0 并答出内容，而 `msg fetch` 退出 1
      且**第一行**就点名自己。那句点名是**加出来的**：`cmd_msg_fetch` 的两处联网步骤各带一句
      `with_context`（发现信道、`sync.delta` 调用），否则断网时的 `error sending request` 读起来
      像是"本地记录坏了"——而记录恰恰是还好着的那件东西。
- [x] **`--json` 的输出不落盘**（TODO4 §E 那条规矩：`messages.db` 按密钥对待）。
      读侧一开，这条边界要重新说一遍——今天它只约束写，读侧的输出管道是新的口子。

      **2026-10-03：写进 [client-messages.md](docs/design/client-messages.md) §8.4，并在脚本里钉了
      一条断言。** 断言用的是 carol（一次都没连过服务的身份）：`msg inbox --json` 跑完
      `$WORK/home/carol/default/messages.db` **不存在**——"读不落盘"只有在库还没被创建的身份上
      才查得出来，bob 的库早就在了，光看存在与否分不出读和写。

> **2026-10-03 起，读侧代码开始动**（原话"先放着"指的是"先别急着动手"，交互画完了就该落地）。
> 落地以本节与 client-messages.md §8 为准，不是从三条旧候选里挑。

---

## 3. 服务端要跟着改的那半（TODO5 §8 D）

读 = 本地之后，"服务端还把消息留多久、什么时候能删"从一件无所谓的事变成读侧的**上界**：
服务端删掉的东西，`fetch` 再也搬不回来。四条都落在 `packages/service`。

- [x] **补一条明确的 ack / 保留契约。** 现状是**永不裁剪**（§1 量出来的：没有任何
      `DELETE FROM deliveries`）。要么把"不删"写成**契约**（那 `deliveries` 会随收件箱无限长，
      要为它设一个上限或一条运维说明），要么定**什么时候能删**——而 ack（`stream.ack` 推进
      `delivery_cursor`）正是那个"客户端说读到了"的信号。这里的问题是：**ack 到哪一档才允许删？**
      账号级只被一台设备 ack，另一台还没读，就不能删。所以这多半不是"ack 后删"，而是
      "**所有设备都 ack 过**才删"，那需要一个跨设备的**下界**。

      **2026-10-03 查清了做不到的地方，需要裁定。** 事实（都在
      [sqlite.ts](packages/service/src/storage/sqlite.ts)）：
      - `delivery_cursor` 是**按 `(owner_did, device_id)` 一行**的（`cursor` / `advanceCursor`，
        约 641/653 行），没有任何地方记"这个账号一共有几台设备"。
      - 所以"所有设备都 ack 过"这个下界**今天算不出来**：`MIN(last_seq) OVER (owner_did)` 会把
        **从没连过的设备**算成 0（它没有行），下界立刻塌到 0，一条也删不掉；而"只对出现过的设备
        取 MIN"则会把一台**生来没出现过**的设备当成"已 ack"，删掉它还没读的东西。
      - 两条出路各自要一个新事实：**(甲) 有一张设备名册**（谁属于这个账号），下界 = 名册上每台
        设备的 `cursor` 的 MIN；**(乙) 不删**，把"永不裁剪"写成契约并配一条运维说明
        （`deliveries` 随收件箱无限长，磁盘是部署的事）。
      **建议先走 (乙)**：它今天就是真的，写下来不改一行代码；而 (甲) 要的设备名册本身是一条新的
      真相（账号里有哪些设备），属于换钥 / 设备撤销那条线，不该在这一轮顺手造。
      **这条要用户裁定。**

      **2026-10-03 用户裁定：「可以设置成不删除，但是只能访问 30 天内的数据。」** 于是这一条
      分成两半，而且是两个不同的东西：
      - **保留 = 永不裁剪**，写成了契约。`message-service.md` §7 的 `deliveries` 建表处逐字写着
        没有任何 DELETE 会到这张表，以及为什么 ack **不是**能删的信号（就是上面那个算不出来的
        下界：本服务没有设备名册）。纸面上它可逆——想删随时能加。
      - **能见度 = 30 天**，这一半是新的：`AGENTX_DELIVERY_READ_WINDOW_MS`（缺省 30 天，
        [config.ts](packages/service/src/config.ts)），`sync.delta` 只答窗口内的行。
        `Storage::deliveriesSince` 多了个 `notBefore`（`string | undefined`，`undefined` = 无界，
        storage 层的测试与非取件面的读者用这个值）；下界按**这次请求自己的** `acceptedAt` 算，
        不是 `Date.now()`，所以同一批里两次读不会因为跨了一个毫秒而不同。
      - 窗口对 `seq` 是**前缀**（序号按追加分配、`accepted_at` 就是那次请求的时刻），所以
        "空页回 `since` 本身"那条规则仍然成立：整条信箱都过期时游标停在原地，而不是被推到
        `headSeq`——那等于替客户端宣告"这一段你看过了"。三条断言钉住了它
        （[dispatch.test.ts](packages/service/src/rpc/dispatch.test.ts) 的"取件面的可读窗口"那一组
        与 [sqlite.test.ts](packages/service/src/storage/sqlite.test.ts) 的 `drops rows accepted
        before the floor`）。
      - **没做**：窗口不承诺告诉客户端"窗外还有 N 条"，所以 `fetch` 的 "brought in: 0" 仍然
        分不出"真的没有了"和"有，但在窗外"。这一条挂在 §4 那条换钥诊断旁边。
- [x] **P6 设备队列的有界保留要不要为持久客户端放宽。** 今天是 8 次尝试 / 24 小时
      （[config.ts:41-42](packages/service/src/config.ts#L41)，[deviceQueue.ts](packages/service/src/delivery/deviceQueue.ts) 文件头）。
      24 小时对**推**是合理的（推是尽力而为的优化，拉才是事实），但对一个**离线一天以上**的
      客户端，那批 P6 帧就过期了。要定的不是"调大数字"，是**这批帧过期后 `fetch` 能不能把它们补回来**
      ——能，则 24 小时无妨；不能，则要么放宽，要么让 `fetch` 覆盖这一段。

      **2026-10-03 答案是"不能"，而且理由在服务端自己写着。** `sync.delta` 读的是
      `storage.deliveriesSince(...)`（[inbox.ts:200](packages/service/src/rpc/inbox.ts#L200)），
      也就是 `deliveries` 表；而 P6 的信封**根本不往那张表写行**——[deviceQueue.ts](packages/service/src/delivery/deviceQueue.ts)
      文件头第 3 条逐字写着「P6 的信封在 `deliveries` 里没有行，所以这里没有第二条路可走」。
      于是过期的设备队列帧是**真的没了**：`fetch` 搬不到，本地也没有过，客户端只能把"这条群消息
      我没收到"如实说成没收到（`unfetchable` 那条打印的是**还在队里**的帧；过期的连名字都没有）。
      要改的话是两条，都要裁定：**放宽保留**（数字是部署档位，改 `AGENTX_DEVICE_QUEUE_MAX_AGE_MS`
      即可，但那只是把窗口推远），或者**给 P6 帧也写一条可补拉的记录**（那是让设备队列与
      `deliveries` 共享一条持久路径，等于改 §12.6 的发射面）。**这条要用户裁定。**

      **2026-10-03 用户裁定：「你要么把它写成 30 天吧。」** 走了"放宽"那一支，没走"给 P6 帧
      写可补拉记录"（那会动 §12.6 的发射面，而 §12.6 明说不给它写行）。落法：
      `DEFAULT_DEVICE_QUEUE_MAX_AGE_MS` 从 24 小时改成 **30 天**
      （[config.ts](packages/service/src/config.ts)），`config.test.ts` 的缺省断言跟上，
      三处散文（[deviceQueue.ts](packages/service/src/delivery/deviceQueue.ts) 文件头、
      [e2ee-group.md](docs/design/e2ee-group.md) §6.2、[client-messages.md](docs/design/client-messages.md)
      §8.3）与新变量的文档（`message-service.md` §14、[e2ee.md](vercel/guide/e2ee.md)）同步。
      **取 30 天而不是别的数，是为了与取件面可读窗口对齐**：两个窗口说的是同一句"一条消息在
      这里活多久"，一个管 `deliveries`（拉得到的那半），一个管设备队列（只有推能到的那半）；
      不一样就会出现"`sync.delta` 说没有、队列里其实还有一条"这条缝。
- [x] **补拉历史的接口**（现在**没有规范位**）。两个候选，要先选：
      - `direct.get_history {peer_did, since_seq?, limit?}`——§9.3 表里有形状，
        **v1 不实现**，因为 `since_seq` 没有定义：序号是**收件箱级**的交付计数器，而 `peer_did`
        问的是**一个会话里**的历史，"会话内第 N 条"本服务手上没有（[message-service.md:785](docs/design/message-service.md#L785)）。
        要发这个，得先给"会话内序号"一个定义，而它**不能是**按 `created_at` 排名的私有游标；
      - 或者**不收 `direct.get_history`**，让 `fetch` 直接走 `sync.delta`（`seq` 已经是对的语义）。
        这条更省事，但 `sync.delta` 是**补齐**语义、"从 `since` 之后全部"，不是"某个会话的历史"。
      **建议先按第二条做（`fetch` = 一次带游标的 `sync.delta` 落库），把 `direct.get_history`
      继续挂着**，因为"会话级历史"在本地库成为记录之源之后，由**本地查询**回答更自然——
      那正是 §2 要画的东西。

      **2026-10-03 按建议做了，而且做完了。** `fetch` 走 `sync.delta`，`direct.get_history`
      **继续挂着**（服务端仍然不实现，[message-service.md](docs/design/message-service.md)
      §9.3 那条注不用改）。"会话级历史"落成了 `msg history <peer_did>`——**本地查询**
      （`MessageStore::conversation_with`，按 peer DID 取一条线、正序），正如这一条预测的那样。
- [x] **换钥之后 `deliveries.owner_did` 不被挪到新 DID 名下**（[message-service.md:914](docs/design/message-service.md#L914)）。
      这不是"还没做"，是一条**已知的没解的问题**：对端一直不再写信时，本地的 `did` 停在新钥之前，
      按 DID 发信失败、按名字解析出的还是旧 DID。读 = 本地之后它更刺眼——本地库按**槽位**组织
      （所以历史还在），而服务端那批投递仍挂在旧 DID 下，`fetch` 于是搬不到。要一个裁定。

      **2026-10-03 补一条量出来的事实**：`fetch` 搬的是**自己账号在 `deliveries` 里的行**，而那批
      行的 `owner_did` 是**旧 DID**；客户端解析出来的则是**新 DID**（本地的 `did` 已经换过）。
      `deliveriesSince(ownerOf(meta), …)` 于是查的是新 DID，一行都查不到——**不是"搬不全"，
      是"一条都搬不到"**，且失败方式是一次**退出 0 的空搬**（"brought in: 0"），最难被发现的
      那一种。要不要在这里补一个"旧 DID 名下还有多少条没搬"的诊断，或者等 §3 那条换钥迁移一起
      解决，**要用户裁定**。

      **2026-10-03 用户裁定：「服务端换钥时把投递挪到新 DID 名下」。** 做了，形状与 §8.12 那三条
      触发路同一个（没有客户端能"上报换钥"，只能在别的事的路上顺手做完）：
      - **新表 `account_dids`（schema v14）**，键取 `subjectOf(did)`（换钥不动的那个），值是这个主体
        最后一次被认下的 DID。它就是 §8.12 从**群名册**拿到、而账号没有的那个"记下来的旧 DID"。
      - **触发面**：这次调用是账号**以自己的身份对自己的信箱**发起的（`meta.target.did` 等于验过签的
        调用方 DID）——`sync.delta` 正是那一类，也正是发现不了旧投递的那条路
        （[dispatch.ts](packages/service/src/rpc/dispatch.ts) 的钩子，实现在
        [ownerDidUpdate.ts](packages/service/src/rpc/ownerDidUpdate.ts)）。
      - **采信**：从水位线上那个 DID 出发、用 P2 验到调用方，档位**逐字复用**
        `memberDidUpdate.ts` 的 `ACCEPTED_ASSURANCES`（同一个问题不能有两套答案）。链断了、后继
        不是它、档位不够，三种都不采纳，而且**不动水位线**——动了下一次就没得对照了。
        于是发现是**按需的**，一次换钥最多解析一次转移链。
      - **动作**：`deliveries` / `delivery_cursor` / `device_envelopes` / `message_reads` 挪到新
        DID 名下，一个事务里做完，然后才写水位线。**序号规则是要紧的一处**：`deliveries` 序号按
        owner 各自从 1 起，所以先把**新 DID 自己那批**抬到旧 DID 的最高号之上——旧的那批**一个号
        都不动**，客户端本地游标（`app_state.applied_seq`）指的仍是同一行。游标合并取 `MAX`。
        **一行都没删**，保留契约（§3 第 1 条）不受影响。
      - **没覆盖的**：`did:web` / CAIP-10 不换 DID；`did:webvh` 的 SCID 语义还是本仓库的本地约定，
        保守处理（链解析不出来就不搬）。设计在
        [message-service.md](docs/design/message-service.md) §9.6，客户端那半的结论回写在
        [client-messages.md](docs/design/client-messages.md) §4.3。
      - 测试：`sqlite.test.ts` 五条（水位线、序号不动、游标合并、队列顺序、空操作）+
        `dispatch.test.ts` 六条（同一次调用里搬完并作答、只记水位线不解析、链不通不搬、解析不出不搬、
        拒 `provider_asserted`、非自寻址不碰）。

---

## 4. 两份真相要对账（TODO5 §8 C）

本地库成为记录之源之后，"服务端的收件箱"和"我本地的库"是**两份记录同一件事的真相**。
它们会分叉（离线读过、服务端重装、设备换了），所以要定**谁说了算**。

- [x] **`x_agentx.inbox.v1` 这套扩展面的去留。** `inbox.get` / `inbox.mark_read` /
      `message.get_batch` 是本服务自己的扩展（规范里不存在）。读 = 本地之后它们还有没有存在的理由？
      至少要区分：**`fetch` 需要的那几个**留下（如果 `fetch` 走 `sync.delta`，那连 `inbox.get`
      都不必留），**其余**是历史包袱。别让"读 = 本地"和"服务端还在答 `inbox.get`"同时为真。

      **2026-10-03 客户端这一侧已经落定，服务端那一侧卡在一个不是我的裁定上。** 事实：
      - **Rust 客户端只剩一个调用者。** `sync.delta`（`msg fetch` 与 `msg listen` 的补齐）是
        `x_agentx.inbox.v1` 里**唯一**还有客户端的成员。`INBOX_MARK_READ` 已从
        [listen.rs](rust/crates/agentx-cli/src/message/listen.rs) 删掉（已读改由本地写），
        `inbox.get` / `message.get_batch` 更早就没有 Rust 侧调用者了。
      - **但 `packages/cli`（TS 那个客户端）还在调这三个**
        （[msg.ts:54-56](packages/cli/src/commands/msg.ts#L54)），服务端的
        `INBOX_GET` / `INBOX_MARK_READ` / `MESSAGE_GET_BATCH` 是**为它**留着的。
      - 所以"读 = 本地"与"服务端还在答 `inbox.get`"今天**并不矛盾**——矛盾的只是 Rust 那半，
        而那半已经不调了。真要退场，问题就变成"**TS 客户端还活着吗**"，那是另一条线
        （[TODO6](TODO6.md) 已经把文档站与二进制名从它那儿挪走了）。**这一条要用户裁定**：
        是把 TS 客户端也搬过来/退役，还是把 `inbox.get` 一族当成"给别的客户端的扩展"长期留着。

      **2026-10-03 用户裁定：「把 TS 客户端退役，服务端摘掉这三个方法」。** 两句都做了：
      - **客户端退役**：`packages/cli/`（`connectx`）与 `packages/e2e/` 整包删除。仓库从此是
        **core + service**，唯一的客户端是 Rust 的 `anp`。
      - **服务端摘掉三个方法**：`INBOX_GET` / `INBOX_MARK_READ` / `MESSAGE_GET_BATCH` 从
        `METHODS` 移除（[methods.ts](packages/service/src/rpc/methods.ts) 驱动分发表与广告出的能力面，
        所以摘一处两边同时变），`x_agentx.inbox.v1` 只剩 `sync.delta`。
      - 现在"读 = 本地"与"服务端还答 `inbox.get`"**不可能同时为真**了——那个方法不存在了。
- [x] **read 状态归谁。** 今天已读是**服务端按 (owner, device) 记的**（`inbox.mark_read` /
      `read_state`）。本地库有 `messages` 表，加一列 `read_at` 是最省事的做法，但那就有了
      **两个已读状态**——正是 realtime.md §5.4 那条"存了就变成两处状态，而它们一定会不一致"
      警告的情形。要么已读**只在本地**（服务端的 read 面随之退场），要么**只在服务端**
      （本地读的时候要联网问一次）。**这条要用户裁定。**

      **2026-10-03 用户裁定："只放本地"。** 于是：
      - `messages.read_at` **本来就在 v1 里**（`messages` 表建表时就有这一列），所以**没有迁移**。
      - `msg read` 变成一次**本地写**：它不需要解析服务、不需要设备、更不该为此联网，
        所以走的是新加的 `MessageStore::open_unsynced`（建库、游标键留空），而不是 `open`。
      - **服务端的 read 面随之退场**：Rust 侧对 `inbox.mark_read` 的调用已经删了。
        服务端那个 handler 还与 `inbox.get` 一族同上——去留见上一条。

---

## 5. 其余待办

都在别处记着、都已经被裁定"以后做"，但它们是**待办**，不是"不做"。每条的详情在指到的地方。

- [x] **通讯录：对端换钥后一直不来信的那一半**。已经答掉的一半是"再写一封信就回来了"
      （`rememberContact` 挪 `did`）。**2026-10-03 量完并落地**，量出来的东西和这条原先
      写的不一样，所以先把错的划掉：
      - **"按 DID 发信失败"不成立。** 按旧 DID 发信**照收**（收件人是那个 DID 本身，一个
        还在服务手上的字符串）。失败的是**回信**：那批信挂在旧 DID 名下，对端读自己的新
        DID 时一条都取不到，而且要等到他下次取件才知道。
      - **答掉的那一半在 §9.6**（服务端换钥时把投递挪到新 DID 名下，用户 2026-10-03 裁定），
        触发在对端**自己的下一次自址请求**上——`sync.delta` 正是那一类，本地 `messages.db`
        与名字册子**不因此改**（它记的仍是"上次见到他是谁"）。
      - **覆盖**：`scripts/e2e.sh` 新增两节（"did update — a peer rotates its key" 与
        "the mailbox follows the key"），`did_host.py` 补上了 ANP-03 §2.5.3 的更新端点
        ——少了它就没有一个"换过钥之后的世界"可跑。断言包括旧的发送被接受、`did resolve`
        退出 2 说"superseded: yes"、`--chain` 走出后继与 `assurance: verified`、以及那
        两条信最终回到对端自己的信箱里（并且服务日志里记着它挪了什么）。
      - **发现不再等缓存**（2026-10-03 用户裁定"走乙"）。上面那句"上界就是 TTL"描述的是
        **当时**的实现，现在不成立了：迁移这一步改走 `chainResolverFor(config, { fresh: true })`
        ——`fresh` 不传 `documentStore`，core 那边"ABSENT 就是完全不缓存"，于是这条链每一跳
        实时抓取，换钥在他**下一次自址请求**上就被看见。代价只落在"水位线对不上"这一种状态，
        而它一次真换钥之后只出现一次（迁移成功水位线就跟上）。群名册那三条触发路仍走缓存档。
        `scripts/e2e.sh` 那一节里的 1 毫秒 TTL 重启随之删掉，跑的是出厂值；两条单测
        （`ownerDidUpdate.test.ts`）把"缓存档不联网 / `fresh` 档绕过缓存去抓"咬住。设计回写在
        [message-service.md](docs/design/message-service.md) §9.6 与 §14、`config.ts` 的 TTL
        注释。
- [ ] **"我在群里的昵称"**：本地表存，还是提一个 Profile 扩展？协议里今天没有这一层，
      所以这是一次**设计选择**（[TODO6](TODO6.md) §4）。用户 2026-10-02 裁定**以后做**。
      真动时再来选，别每个客户端各存各的。
- [ ] **验签玩具主机**：一台**会验签**的玩具主机，能咬住"签名到底对不对"。
      这**不是**某条待办的收尾，是能独立成立的一件事——但也不记成"必须做"
      （[TODO6](TODO6.md) §5.3，用户 2026-10-03："五以后再说"）。
- [x] **覆盖：`did update` / `--resume` / `anp login` 的 401 挑战**（[TODO6](TODO6.md) §5.3）。
      **2026-10-03 三条都进脚本了**，而这一条原先的判断有一处是错的。
      - `did update` 那一半：`did_host.py` 加了 ANP-03 §2.5.3 的更新端点，`scripts/e2e.sh`
        的"换钥"两节真的换了一次钥。
      - **`--resume` 三档结局各一条**（详见上面那节的记录）：不可知（玩具主机演了两种半路
        失败）、确定没落地（主机答 403）、落地了（`--resume` 走链确认后继并提升）。
      - **`anp login` 的 401 挑战也进脚本了——它不需要"第二个设备"。** 原先写的是"要一台愿意
        配合的主机或第二个设备，不是能顺手塞进去的"，而**那台主机就是玩具主机自己**：ANP-02
        的登录是两次往返（先 401 给 nonce，客户端拿它重签再来），玩具主机多演一步就够了
        （`did_host.py` 的 `LOGIN_PATH` = 根路径，正是 `main.rs::host_and_token` 让用户跑的
        那个 URL）。断言读的是**服务端看见了什么**（主机 stdout 打进 `host.log`：发了挑战、
        并且收到的正是那个 nonce），以及一个主机从没发过的 nonce 会被当成**拒绝**报出来、
        不会第三次重签。**2026-10-03 止，这一条没有剩下的了。**
- [x] **`packages/e2e` 的跨域中继覆盖**：`groupFederation` 是两台真服务 + 真中继跨域
      `group.send`，本仓别处没有；`msg listen` 那两条是**真 WebSocket**（脚本只补上了回填那半）。
      迁移判据：等中继那半有了别处的覆盖（或 Rust 侧也起两台服务）再谈搬
      （[TODO6](TODO6.md) §7）。**`directSend` 那两条不要照搬**——脚本跑得更真。

      **2026-10-03 补：判据的前提被 §4 那条退役裁掉了一半，所以搬了。** `packages/e2e` 随 TS
      客户端整包删除（§4 第 1 条），而这一条原本说"等别处有了覆盖再谈搬"——**删的那一刻别处
      还没有**。搬的是**服务端那半边**（驱动原本是 TS 客户端命令 `call` / `senderFor` /
      `runGroup`，那半边已经不在了）：
      - 落点 [crossDomain.test.ts](packages/service/src/federation/crossDomain.test.ts)：
        两台真 `createServer`（各自 `AGENTX_SERVICE_DID` / 真 HTTP / 真的群文档路由），一次
        **真**的跨域 `group.send`——A 的 `relay` 真的去取 `http://127.0.0.1:<portB>/g/<id>/did.json`、
        真的 POST 到 B，回执由 **B** 的群钥签发再带回来；另有一条钉住"A 不替对端记一行群"、
        一条钉住够不着时是 1012 而不是任何 `group.*` 码。
      - 驱动改用 core 的 `buildMessageRequest`；**外层签名故意没走**（同原注释：P8 §2.3 按本地
        调用处理，`origin_proof` 才是授权依据）。
      - **`directSend` 那两条仍然不搬**（脚本跑得更真）。
      - **顺带发现的一件，2026-10-03 已修**：`group.get_info` 在 `RELAYED_METHODS` 里但
        **永远中继不到**（它没有 `targetScope`，`dispatch.ts` 在 `relayFor` 之前就从无状态
        分支返回了），于是 `dispatch.test.ts` 那条"returns the peer refusal unchanged"是
        **空过**的——本地处理器对未知群答的正是同一句 `group.not_member`。修法是让无状态
        那一支也先过 `relayFor`（自家的群与自己的 `serviceDid` 仍在里面短路成本地），表里那
        一行因此不再是一句空话；两条单测把它咬住（跨域的读**被转发**、自家的读**不转发**）。
        顺手把 `relayFor` 那个谁也没用的 `key` 参数删掉——无状态方法根本没有幂等键可给。
- [ ] **覆盖率**：132 个单测长在库侧，命令面一层几乎没有测试；脚本 + CI 是第三档的载体
      （已裁定，[TODO6](TODO6.md) §5.3）。这一条 2026-10-03 用户原话"以后再说"。
- [x] **§2、§3、§4 每一条命令，落地时同时写文档**——命令面和文档在同一次改动里。
      这是既有的做法，TODO5 攒过一次，结果就是 `did publish` / `me` 至今无文档
      （[TODO6](TODO6.md) §2，唯一剩下的那条）。

      **2026-10-03：这一条自己过时了，两处都对不上，记下来免得下次再引。**
      - `did publish` / `me` **已经有文档了**——[TODO6](TODO6.md) §2 那条 2026-10-02 就打了
        `[x]`（`rust/README.md` 的 `did`/`me` 条 + 文档站的参考页）。"至今无文档"是引用它时
        没回头核。
      - **读这一族是照这条做的**：`msg inbox` / `history` / `show` / `read` / `fetch` 五条
        的实现（[main.rs](rust/crates/agentx-cli/src/main.rs) 的 `cmd_msg_*`）与文档
        （[rust/README.md](rust/README.md) 那张参数表、那几条负结果、以及
        [client-messages.md](docs/design/client-messages.md) §8 的设计）在**同一批**里落的，
        没有攒。所以这条到此为止——留着的是那句规矩，不是一件待办。

---

## 6. 这一轮做完的样子

- **读不联网**：断网时 `msg inbox` / 看某条 / 看会话都能答，因为读的是**我本地的库**。
  要联网的是另一条命令（`fetch`），而它**明说自己要联网**。
- **`fetch` 只说真话**：它搬的是"服务端**还有的**"——搬不回来的（服务端删了、设备队列过期了、
  换钥后挂在旧 DID 下）它会**说清搬不回来**，而不是假装本地就是全部。
- **一份真相**：已读状态只有**一个**归属，`inbox.get` 那套扩展面要么退场要么被说明为什么还留着，
  不存在"服务端一套、本地一套、它们不一致"。
- **服务端的那四条有结论**：保留契约写下来了（删或不删，以及为什么），设备队列会对离线客户端
  说得出话，补拉历史有了明确的承载，换钥后的投递归属有了裁定。
- 文档描述的是**在动的那个二进制**——读这一族的语义从"服务端有什么"改成了"我有什么"，
  文档站与 `rust/README.md` 同批跟上。
