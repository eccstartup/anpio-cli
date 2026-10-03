# 客户端的消息库 `messages.db` —— 记录之源，以及它与 `mls/` 的界

[client-mls.md](client-mls.md) 写的是设备侧的**密码学状态**（`<agent>/<profile>/mls/`）。
这一份写它的**兄弟**：同一层目录下的 `messages.db`，即 TODO5 §4 那条"本地消息库"——
TODO5 定了方向（§0.1 第 2、3 条），具体形状留到动手时落，这份就是那个形状。

口径同样是**方案，不是落地记录**。表结构、列名、游标规则核过本仓两侧的现状
（服务端的 `deliveries` / `delivery_cursor`，客户端的 `msg listen` 与 P6 收包路径），
但一行代码还没写；动手第一步见 §7。

## 1. 为什么有这一块

先纠正一个容易跑偏的前提：**消息今天不是没人存**——它存在**服务端**。`deliveries` 是一条
每 (owner, device) 单调递增游标的收件箱，`msg listen` 用 `sync.delta` 补拉，服务端的
`inbox.get` 分页翻。**客户端一行都不存**：那条路自己也是这么写的
（[realtime.md](realtime.md) §5.4 的"**本地不存游标**——存了就变成两处状态，而它们一定会
不一致"；2026-10-02 已在那句下面补了改口，见 §1.1）。

所以真正的问题不是"要不要存"，是**本地存下来比服务端那份多解决什么**。三条：

1. **E2EE 的明文。** P6 服务端**不落明文**（[e2ee-group.md](e2ee-group.md) §12.6）。要显示群历史，
   设备得在本地留明文——或者留能解出明文的 MLS 状态，而后者是"不留"的另一种说法。
2. **记录之源。** 一个身份的聊天历史今天只活在托管它的那台服务上。服务没了、`deliveries`
   清理了，历史就没了。本地库让它变成客户端自己的资产——这条与在 TODO5 里记着的
   "§8-D"（本地库成为记录之源，服务端就得配合）是一体两面：**ack、保留期、补拉接口是服务端
   那一半**，这正是"把 message service 做好"的落点。
3. **聚合与离线。** 本地库是所有会话汇到一处的地方，也是"服务端关着也能读"的那一份。

**还有第四条，是动手时才会踩到的**：解密的这半步**必须有个地方落**。一帧群消息到达时，本地
先有密文、后有明文；`decrypt_received` 落在 `mls/` 里，而**明文没有家**——今天它只被渲染成
一行字然后丢掉（`group_receive.rs` 的 `GroupEvent::Message`）。所以本地库不只是"顺便存一下"，
它是收包路径上**唯一**能把明文留下来的位置。

### 1.1 与 realtime.md §5.4 那句"本地不存游标"的关系

那句话不是错的，它说的是**服务端的交付游标**：`delivery_cursor(owner_did, device_id)` 记的是
"服务端可以停止重放哪些"，一个账号一份，换台机器接着读——**这仍然归服务端**（那句已经在原位
补了说明，指向这一份）。

本地要的是**另一件事**：`sync_state`，记的是"哪些已经落进`messages.db`"。两者不是对同一个
事实的两种意见，而是两个不同的事实（**投递到哪了** vs **记录到哪了**），且只在一个方向上必须
一致：**没有落库的序号，不许 ack**。§4 把这条写成不变式。

## 2. 与 `mls/` 的分工：两个文件，三种重建性

`messages.db` 是 `mls/` 的**兄弟**（同目录，同一个"一个身份的状态放哪"的答案），但不是它的
一部分。它们是**两件资产**，差别不是"一个是密钥一个是内容"这么简单，而是三种重建性：

| | `mls/local_state.sqlite` | `messages.db` |
|---|---|---|
| 装什么 | ratchet / 群成员密钥 / epoch | 明文、投递记账、已读、本地游标 |
| 归谁 | crate（`ImCoreSqliteGroupMlsStore`），我们只经它读写 | 我们（`crate::messages`） |
| 丢了以后 | **解不开以后**的群消息；不可重建 | 历史没了；**以后照常** |
| 泄露以后 | 能解**以后**的群消息 | 能读**过去**的内容 |
| 备份的含义 | 备份密钥 | 备份内容 |

两条结论直接落在这张表上：

- **必须能分别备份。** 备份 `mls/` 是备份密钥（要按 TODO4 §E 那条规矩对待），备份
  `messages.db` 是备份内容。把两者塞进同一个 sqlite 文件，就没有"只导出一份聊天记录"这个
  动作了；而那是这个功能**最日常**的一个用途。
- **两个文件、两个生命周期。** 谁也不该在对方的文件上开事务（§2.1 是这条的推论）。

### 2.1 没有跨库事务，所以顺序就是契约

两个 sqlite 文件之间**没有**共享事务，而"解密一条群消息"这件事要同时动两个文件。顺序因此不是
实现细节，是设计的一部分：

```
1. crate 的 decrypt_received / process_notice         → 落在 mls/
2. INSERT OR IGNORE 一行 messages（明文 + 群版本）      → 落在 messages.db
3. UPDATE sync_state.applied_seq                      → 同一事务，最后一步
```

**崩溃在 2 与 3 之间是可恢复的**，这是第 3 步放最后、而且与第 2 步同一个事务的理由：本地游标
还停在那一帧之前，重连时服务端会把它重放一遍（一帧没被 ack 就是没被 ack），而
`decrypt_received` 正是**允许重复输入**的那个变体（[client-mls.md](client-mls.md) §2.1，
P6 §12.6 让服务端在写 socket 成功后才删队列行，重连本就会重放）。第 2 步的
`INSERT OR IGNORE` 让重放写第二遍是空操作。

顺序反过来（先推游标再落库）就**静默丢消息**：崩溃后那一帧不会再来。这与 [realtime.md](realtime.md)
§6 那条"默认不自动 ack，因为'忘了 ack'可恢复、'自动 ack 而人没看'不可恢复"是同一条判断，
只是层次更低一层：**落库先于 acknowledging，acknowledging 先于"已读"**。

## 3. 表结构

```sql
PRAGMA user_version = 1;      -- 起点；口径照抄服务端（见 §3.1）
PRAGMA journal_mode = WAL;    -- 长驻的 listen 在写，另一个进程可能在读
PRAGMA foreign_keys = ON;

-- 一个身份下的一个会话：对端 agent 或一个群。
CREATE TABLE conversations (
  id        INTEGER PRIMARY KEY,
  kind      TEXT NOT NULL CHECK (kind IN ('direct', 'group')),
  peer_did  TEXT NOT NULL,          -- 对端 DID，或群 DID
  last_at   TEXT,                   -- 冗余的高水位，只为按会话排序
  UNIQUE (kind, peer_did)
);

-- 一行就是一条消息（收到的和发出的都在这里）。
CREATE TABLE messages (
  id              INTEGER PRIMARY KEY,       -- 本地行号，只在本库里有意义
  conversation_id INTEGER NOT NULL REFERENCES conversations(id),
  direction       TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  sender_did      TEXT NOT NULL,             -- 双方的消息都要：发出的那条 sender 是我
  message_id      TEXT NOT NULL,             -- 发送方作用域的那条 id
  content_type    TEXT,
  text            TEXT,                      -- §7.4 的 exactly-one-of
  payload_json    TEXT,                      --   第二支；两列恰好一个非空
  service_seq     INTEGER,                   -- 服务端 deliveries.seq，发出的消息没有
  endpoint        TEXT NOT NULL,             -- 哪一个 inbox（见 §4.2）；service_seq 的命名空间
  accepted_at     TEXT,                      -- 服务端给的时间
  group_event_seq INTEGER,                   -- 群才有：P6 的 group_event_seq
  group_state_version INTEGER,               -- 群才有：密文加密时对面的 group_state_version
  received_at     TEXT NOT NULL,             -- 落到本库的时间（本地钟）
  read_at         TEXT,                      -- 本地已读
  UNIQUE (conversation_id, sender_did, message_id)
);

CREATE INDEX messages_by_conversation ON messages(conversation_id, id);

-- 本地游标：这个 inbox 已经落库到哪个 seq。名字不叫 cursor，就是为了不和
-- 服务端那张 delivery_cursor 混成一个东西（§1.1）。
CREATE TABLE sync_state (
  endpoint    TEXT NOT NULL,
  owner_did   TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  applied_seq INTEGER NOT NULL,              -- 只进不退
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (endpoint, owner_did, device_id)
);
```

逐个说清楚为什么是这些列：

- **去重键是协议身份，不是本地到达。** `UNIQUE(conversation_id, sender_did, message_id)` 是那条
  唯一索引，也是全部幂等性所在。它必须带 `sender_did`：`message_id` 是**发送方作用域**的，
  两个发件人挑同一个串是完全合法的（服务端的幂等键 `(sender_did, target, method, operation_id)`
  也带发送方，同一条理由）。本地行号 `id` 只用来排序，不是身份。
- **群消息多两列，理由不是"顺便记一下"。** `group_event_seq` 是服务端给的群内序号，
  `group_state_version` 是**密文自己指名**的那一版群状态（P6 §12.5 的
  `group_state_ref.group_state_version`，`anp` 1.0.5 的 `V2GroupStateRef`）。记它而不是
  记本地的 epoch：本地 epoch 是 crate 的状态，两个文件各有一份且会各自回滚，而对账要问的
  恰恰是"这一行是**对面**在哪一版上加的密"。价值在**对账**：`messages.db` 与 `mls/` 会分别
  被恢复（§2），一旦 `mls/` 从更早的备份回来，那些版本高于当前状态的行就是"读得出来、但接着
  聊不下去"的证据。没有这一列，出问题时两个文件无法互相解释。
  两列**在库里都是 INTEGER**，尽管线上是十进制字符串（§7.3）：服务端自己的
  `messages.group_event_seq` / `group_state_version` 就是整数列，它还得**自增**前一个，
  而且字符串排序不是排序。转换在写入时做，转不动就拒绝整行（宁可什么都不记，也不要记一个
  悄悄截断的计数器）。
- **`direction` 与"发出的消息"同表。** 聊天客户端两个方向都要显示，所以发出的消息也落一行，
  在 `msg send` / `group send` / `group e2ee send` **成功之后**写（**已实现**）。没有 `outbox`、
  没有重试队列：`operation_id`
  那套重试归调用方（[cli.md](cli.md) §3.3 说得明白，旗标存在的唯一理由就是重试），本地库
  不替它排队。
- **`text` / `payload_json` 两列而不是一列 JSON。** §7.4 的 exactly-one-of 是协议形状；两列让
  它落在 CHECK 上（写的时候就能判），也让"按会话翻"这条最常走的查询不用解 JSON。
- **`read_at` 在行上。** 已读是每行一个时刻，不是一张表。理由：本服务的 `inbox.mark_read` 是
  **服务端**那份已读（扩展面 `x_agentx.inbox.v1`），而 TODO5 §4 第 4 条把 read 状态判给了本地。
  两个都存在，各答各的问题：行上这个答"这台设备的用户看过没有"，`--ack` 喂给服务端的那个是
  交付侧的记账。它们的先后跟 §2.1 一致——**落库 → acknowledging → 已读**。

### 3.1 版本与"拒绝更新的库"

服务端那份存储把这个动作做对了，照抄它的姿态（`packages/service/src/storage/sqlite.ts`）：
`PRAGMA user_version` 是版本，**发现文件比自己新就拒绝打开**，而不是"尽量写写看"。理由是
二进制的生命周期比文件长——一个旧 `agentx-cli` 打开一个新库并照老 schema 写，损坏是静默的。
新库要升级时按版本号逐级迁移，不猜。

## 4. 游标

### 4.1 三个数，别混

| 数 | 谁写 | 含义 |
|---|---|---|
| 服务端 `delivery_cursor(owner_did, device_id)` | **只有** `stream.ack` | 服务端可以停止重放哪些 |
| 本地 `sync_state.applied_seq` | 落库那一步（§2.1 第 3 步） | 哪些已经进了 `messages.db` |
| 实时帧上的"第 n 条" | 客户端从 `stream.ready` 的 `head_seq` 自己数 | 服务端**不推** seq（realtime.md §5.5） |

实时期的那一段序号是**数出来**的（帧上没有 seq），补齐那一段是服务端给的——两边接在 `H` 上。
`messages.db` 接收的是**已经重建过的**那个值，与 `msg listen --json` 打出来的 `seq` 是同一个
来源（`realtime.md` §7.1 那条 `seq` 就是这么来的）。**重建逻辑只该有一份**，落在
`message::listen`，不进这个模块。

### 4.2 键为什么多一个 `endpoint`

`sync_state` 的主键 `(endpoint, owner_did, device_id)` 比服务端 `delivery_cursor` 的
`(owner_did, device_id)` 多一个 `endpoint`。服务端知道"是谁的收件箱"就够了，客户端却可能同时
面对多个服务——一个身份在多台服务上都有收件箱是正常状态（TODO5 §4 那条"聚合与离线"，这也是
本地库存在的理由之一），而两个不同 inbox 的 `seq` 是两个独立的计数，用同一行走是错的。

在键里就有一个**代价**，得说清楚：服务换了个 `serviceEndpoint`（同一个服务，只是搬了地址）
会被认成**新** inbox，于是从 0 重拉一遍。这个方向是安全的，因为猜错的代价只是多拉——§3 那条
唯一索引让重放与重复都是空操作。反过来把 `endpoint` 从键里拿掉，代价是**静默跳过**一个真
不同的 inbox，那个不可恢复。所以：**游标宁可多拉，不可少读**；`endpoint` 变动时唯一真正要
小心的是"换了服务要不要把老游标删掉"——答案是**不删**，删了就丢了"我读到过哪"这个事实，
而重拉一遍本来就没有副作用。

### 4.3 `did update` 之后游标会怎样（一个要写下来的洞）

`mls.rs` 的 owner scope 用的是 `(agent/profile, device_id)`——**故意是本地槽位而不是 DID**，
就是为了跨换钥活着。`messages.db` 跟着同一个理由：会话与消息都不带"owner 的 DID"作为键，
`identity.json` 换了 DID 不改变任何一行的含义。

但**服务端那一半没这么走**：`deliveries.owner_did` 是投递时的那个 DID，仓库里没有任何东西在
`did update` 之后把这些行挪到新 DID 名下。所以换钥之后：

- **本地**：历史还在，照读。
- **服务端**：新 DID 名下的收件箱是空的（`sync.delta` 从 0 开始什么也不给）。
- 于是"新消息还到不到"取决于服务端——**这是服务端要补的一笔，不是客户端能解决的**，记在这里
  当作 TODO5 §8-D 的一个具体落点。

这条恰好解释了本地库的价值：**换钥之后还能读到的历史，只存在于本地库里。**

### 4.4 不变式（写成一条，因为它只有一条）

> **`applied_seq` 只在那一行已提交之后推进；`stream.ack` 只在 `applied_seq` 之后发。**

换句话说 `applied_seq` 永远是 `delivery_cursor` 的**下界**。默认不 ack（realtime.md §6）时两者
差得远，那是对的——服务端继续重放，本地库去重。反过来（ack 超前于落库）就是 §2.1 说的静默丢。

## 5. 坑，现在就得说

1. **时间轴有两个钟。** 收到的消息有 `accepted_at`（服务端的钟），发出的消息只有
   `received_at`（本地的钟），而"我说的话"与"他说的话"之间的顺序**只能拿这两个钟比**。
   所以时间轴的排序是近似的，这一点要在实现里写明，别让人以为它是精确的。会话内按 `id`
   排序是精确的（本地落库序），跨会话不是；`group_event_seq` 是群内序，跨会话更没有可比性。
2. **明文是密钥资产。** TODO4 §E 那条规矩（"数据库文件、它的备份、以及任何'把 db 发过来看看'
   的调试，全部按密钥对待"）在这里比在 `mls/` 那边**更容易被违反**——`mls/` 一看就知道是密钥，
   而 `messages.db` 长得像个普通数据库。所以：文件 0600（与 `identity.json` 同档）、默认没有
   "导出"命令、`--json` 的输出不落盘、以及在文档里明说**备份 `messages.db` 等于备份聊天内容**。
3. **加入之前的群历史永远解不开。** MLS 的前向保密是这个特性的物理边界，不是实现缺陷。由此
   一条产品纪律：**本地库不是"完整历史"**，界面与文档都不许这么暗示——一条只从入群那天开始的
   历史，与一条被清理过的历史，看起来一样，但原因不同，说清原因是这个仓库的惯例
   （[cli.md](cli.md) §5 那条"扩展面负结果要说明白"是同一类要求）。
4. **单进程。** crate 的 MLS store 用 fs2 的 `StateLock::try_acquire` 把状态锁成单进程
   （[client-mls.md](client-mls.md) §2.1）。`messages.db` 是同一个人写的、可能同时被
   `msg listen` 与另一个 `msg inbox` 打开——WAL 让"一写多读"成立，但**两个 `msg listen` 指向
   同一个身份**是配置错误而不是并发场景（两个进程抢同一条 stream、同一个游标）。要不要也上
   同一把锁，动手时定；这里先记下"这不是多进程安全的库"。
5. **socket 重放与投递重放是两件事。** 重连后服务端会重放没 ack 的帧（投递重放），而
   realtime.md §5.2 那段"注册与补齐之间落库的消息会同时出现在补齐结果和缓冲区里"也会造成
   重复（socket 重放）。两者都靠 §3 那条唯一索引吸收，但**它们是不同的路径**，测试要分别造。

## 6. 不做的事（明确记录）

| 不做 | 理由 |
|---|---|
| 发件队列 / outbox / 自动重试 | `operation_id` 的重试归调用方（[cli.md](cli.md) §3.3）；本地库不排队 |
| 设备间同步 | 规范**排除**（P3 §1、P5 §10.7、P6、P8 §35）；多设备一致靠服务端游标 |
| 历史拉取（从服务端翻旧消息） | 规范**不存在**这个接口（[message-service.md](message-service.md) §9）；只有扩展面的 `inbox.get`，且它只够到自己那台服务 |
| 通讯录 / 群备注进这张库 | 它们是**当前状态**不是历史，各有自己的扩展面与存储（`x_agentx.contacts.v1` / `x_agentx.group_remarks.v1`，今天都读服务端）。放进来会让"备注改了"变成"历史改了" |
| 全文检索（FTS） | 读了才有的需求，且 FTS 会**再复制一份明文索引**——第二个密钥资产。要做就是另一个决定 |
| 加密这张库 | TODO5 §0.1 第 2 条已裁定**留明文**；静态加密是另一个决定，不为它顺手加一层 |

## 7. 动手前

> **2026-10-02 状态。** 下面第 1、2 条已经落地：`crate::messages` 是库本身（`MessageStore`），
> `RecordingView` 是第 2 条说的那个挂法（包在 `ListenView` 外面，`cmd_msg_listen` 里装配）；
> 发出的一侧也已落地——`msg send` / `group send` / `group e2ee send` 在 `accepted: true` 那一支
> 里各落一行（`record_outgoing`，`payload_from` 是 `payload_of` 的逆）。
> 第 3 条（`msg inbox` 要不要本地优先）**2026-10-03 已裁定方向**：**读 = 本地、远程 = fetch**，
> 而 §8 已经把那条方向的**命令面**画完了（`msg inbox` 改语义、新增 `msg history`、`fetch`
> 单独一条）。落地按 §8，不再回头挑了。
> 落地的过程中改掉了这份文档两处：`epoch` → `group_state_version`（P6 的每消息版本是密文自己
> 指名的 `group_state_ref.group_state_version`，不是本地 epoch），以及补上 `messages.endpoint`
> ——没有它 `service_seq` 是一串没有命名空间的数字。

1. **依赖面是零成本。** `rusqlite 0.32.1`（bundled）已经在树里——`anp` 的 `mls` feature 用的就是
   它。所以写这张库不需要引入第二份 SQLite 的 C 源，只是把 `rusqlite.workspace = true` 提出来，
   **版本与 `Cargo.lock` 里那个一致**（`client-mls.md` §5 第 1 条担心的构建成本已经付过了）。
2. **写入口只有一个。** `cmd_msg_listen` 今天把 `GroupReceiver` 交给 `run_listen`，事件从
   `ListenEvent` / `GroupEvent` 回来（`main.rs` 的 `cmd_msg_listen`、`group_receive.rs`）。
   本地库要挂在**事件消费那一侧**，不是收包那一侧：`message::listen` 是传输与游标，它按
   realtime.md §7 的设计"故意不懂 MLS"，也不该懂 sqlite。
3. **一件已经裁定、但形状要重画的**：`msg inbox` 那一族要不要变成**本地**。2026-10-03 已裁定
   **读 = 本地、远程 = `fetch`**，所以"要不要"不是悬念了；要画的是**重画后的命令面长什么样**
   ——§8 就是那个形状（`msg inbox` 改语义、新增 `msg history`、`fetch` 单独一条）。

## 8. 读侧：读 = 本地，远程 = `fetch`

> **2026-10-03 用户裁定（原话）：「读聊天记录就是读本地，远程是 fetch，把交互重新设计，
> 先放着，记下来。」** 这一节是那句裁定的**落地形状**：命令面按它重画过，不是从上一版留的
> 三条候选（改 `msg inbox` 语义 / 加 `msg history` / 加 `--local`）里挑一条——那三条都是在
> 旧命令面上打补丁，而裁定改的是**这一族回答的问题**。

### 8.1 一条界线：读不开连接

读这一族命令**都不开连接**，它们只 `SELECT` 本地的 `messages.db`。会联网的只有一条：`fetch`
——而它是一次**写**（把服务端**还有的**搬进本地库），所以它明说自己要联网。

可断言的样子：**服务停掉、网络断掉，`msg inbox` / `msg history` / `msg show` 照样答**；
`fetch` 在那时明确失败，并说清"这是要联网的那一条"。这条不是文档里的志愿，是 e2e 脚本要
按住的地方（服务先 kill 掉，再读一遍）。

### 8.2 命令面

| 命令 | 读的是 | 联网 |
| --- | --- | --- |
| `msg inbox [--limit] [--unread]` | 本地：我有什么，最近在前 | 否 |
| `msg history <peer_did> [--limit]` | 本地：和一个对端、或一个群的那条线 | 否 |
| `msg show <message_id>` | 本地：这一条 | 否 |
| `msg fetch [--since <seq>] [--limit]` | 服务端 → 写进本地 | **是** |
| `msg read <message_id>... \| --all` | 见 §4（**待裁定**） | 待裁定 |

**`msg inbox` 的名字不变，变的是它回答的问题。** 它从"问服务端有什么"变成"我有什么"。
不改名，是因为它说的本来就是"我的收件箱"——**没有一个更准的名字跑赢它**，而改名是破坏性动作
（`cli_surface.rs` 那条冻结清单的原话："加是增量、改名与删除才是破坏性"）。所以这里做的是
**改语义 + 加一条新命令**，不是重命名。

**`msg history` 是新的，因为"读一个会话"和"读一个收件箱"是两个问题。** 收件箱是**全部会话
按时间**摊平（像邮件），会话是**一条线按时间**（正序，像聊天记录）。本地库今天有
`conversation_id`，却没有任何"按会话取"的查询——这正是要补的那一半。

**"列会话"（每个会话一行、带最后一条与未读数）不在这一轮。** 那是一个**不同的形状**
（按会话聚合，而不是按消息），今天也还没有一个消费者要它；现在冻结它只会锁住一个还没人问的
问题。真需要时它是一条新命令，不是 `msg inbox` 的一个旗标。

**`msg history` 收 DID，不收名字。** 本地库的会话键是 `peer_did`，而名字只活在**服务端的册子**
里（`contacts.list`）——让 `msg history Bob` 能跑，就等于让一条读命令联网查册子，8.1 那条界线
当场破掉。要名字就先 `agentx-cli contacts resolve Bob`（那是查册子，不是读消息），把 DID 接给
`msg history`；两个命令用管道拼起来是脚本本来就该有的样子。

### 8.3 `fetch` 是一次写，走 `msg listen` 那条路径

`fetch` 走 **`sync.delta`**（§9.3 已有），**不引入 `direct.get_history`**：后者问的是"某个会话
的历史"，而序号是**收件箱级**的交付计数器，本服务手上没有"会话内第 N 条"这个量
（[message-service.md](message-service.md) §9.3）。要发它得先给"会话内序号"一个定义，而本地库
成为记录之源之后，那个问题由**本地查询**回答更自然——那正是 §8.2 的 `msg history`。

`sync.delta` 拿回来的每一项就是订阅路会推的那一帧 `{seq, method, params}`，于是 `fetch` **复用
`msg listen` 的写入路径**：同一支 `records_from` 把帧变成 `Record`，同一个 `MessageStore::record`
落库。三点因此是定的：

- **落在 `messages` 表**，与 `msg listen` 完全同一处，不另开一条。
- **幂等，而且是两重**：行一级靠去重键 `(conversation_id, sender_did, message_id)`
  （`INSERT OR IGNORE`），游标一级靠 `sync_state.applied_seq` 的 `MAX(...)` 单调。
  重复 `fetch` 既不重复行，也不回退游标。
- **游标会推**，因为它搬的就是**投递**：`record` 一见到 `service_seq` 就推进 `applied_seq`
  （§2.1 的顺序：先落行、再推游标）。所以**不带 `--since` 的 `fetch` 就是"从我上次停下的地方
  接着搬"**，`--since` 是显式的重搬（排查用），不是常规用法。

**它与 `msg listen` 的补齐是同一次搬，不是两条路。** `msg listen --once` 今天是"回填 + 打印 +
退出"，回填那半本来就是 `sync.delta`；`fetch` 是把那半**单独拿出来、可重复地**做一次。
落地后"`msg listen --once` = `fetch` 再加打印"这个关系要写下来，别让两条路各写各的。

**它搬不回来的东西要说清。** `deliveries` 之外还有一条 **P6 设备队列**（§12 的帧），那批帧有
自己的有界保留（8 次尝试 / 24 小时）。`sync.delta` 答的是 `deliveries`，所以设备队列里过期的
那些 `fetch` **补不回来**——这是服务端那一半要给的答案（TODO7 §3），不是客户端补得了的。

### 8.4 `--json` 的输出不落盘

TODO4 §E 那条规矩（`messages.db` 按密钥对待：明文、0600）今天只约束**写**。读侧一开，输出管道
是**新开的口子**，所以这条要重新说一遍：`--json` 把行的内容打到 stdout，**不落任何文件**；
要留痕是调用方自己重定向，CLI 不替它决定（与 [cli.md](cli.md) §8 "`msg` 族不新增存储"是同一条）。

### 8.5 这一节不做的事

- **不做"本地优先、失败再问服务端"的两段式。** 那正是"两份真相"的和稀泥，而裁定是**读就是
  本地**，不是"本地优先"。
- **不新增 `--local` 旗标。** 没有"远程那一档"要跟它配对——远程是另一条命令（`fetch`）。
- **不做"跨服务端重放"。** 本地库是*我这台设备*的历史，不是"全网历史"；服务端删掉的、
  设备队列过期的，本地没有就是没有，`fetch` 会说清这一点。
