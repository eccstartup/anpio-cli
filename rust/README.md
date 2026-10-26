# `anpio-cli` —— Rust 客户端

[TODO5.md](../TODO5.md) 落地的那个客户端。**与服务端分开**：`packages/service` 继续是 TS 的
ANPMessageService，这一份是它的客户端。**它有自己的 store 根**（`ANPIOCLI_HOME`，缺省
`~/.anpio-cli`）。

> 本仓库曾经有一个 TypeScript 客户端（`packages/cli`，二进制名 `connectx`，store 根
> `~/.connectx/`），2026-10-03 用户裁定**退役并删除**（[cli.md](../docs/design/cli.md) §1）。
> 所以下面凡提到与它并存、或"不碰 `~/.connectx/`"的地方，都已经没有第二个客户端了——
> 那句话保留只是因为 store 布局本身是那个形状。

## 为什么在这里、为什么是 Rust

客户端做群 E2EE 需要 MLS。官方的 MLS 实现**只在 Rust crate `anp` 里**
（[client-mls.md](../docs/design/client-mls.md) §2）。把客户端写成 Rust，就能**直接调用**它，
不必走任何绑定层。

## 布局

```
rust/
  Cargo.toml                     # workspace
  crates/anpio-cli/
    src/lib.rs                   # 库 `anpio_cli` —— 协议与状态都在这
    src/main.rs                  # bin `anpio-cli` —— 命令面（薄壳）
    src/error.rs
    src/group.rs                 # P4 `anp.group.base.v2` 的策略与 target
    src/mls.rs                   # P6 的设备半边：MLS store 与它造出来的对象
    src/group_e2ee.rs            # P6 的线上半边：请求体的形状
    src/identity/                # 身份库（store / did 文档 / host 注册 / 更新链）
    src/message/                 # 信封装配 + 那一跳 HTTP + 发现 + 流
    examples/phase0_key_package.rs
```

`docs/design/cli.md` §1 的那条线在这个布局里是**物理的**：命令面只解析参数、调库、渲染；
凡是带持续状态的东西（身份库、MLS store、消息库）都在库里。

## 依赖

`anp = "1.0.5"`（crates.io，2026-09-24），**默认 features**（`jwt-pem` + `mls` + `network`）。
注意本地 `~/code/github/anp` 那份检出的 Rust 版本号与 crates.io 不同步——**以 Cargo.toml 里的
pin 为准**，源码阅读用 `git show origin/release/0929:rust/...`。

## 现在有什么

store 根是 `ANPIOCLI_HOME`（缺省 `~/.anpio-cli`），一条身份由 `--agent` / `--profile`
命名——两个都可以不写：`--agent` > `$ANPIOCLI_AGENT` > 当前 agent（`agent use` 选的）>
`default`，`--profile` > `$ANPIOCLI_PROFILE` > `default`。`cargo test` 全绿（147 个单测）。

- **`did create | show | list | register`** —— 身份存储 + DID 文档。
  `list` 与 `agent list` 不是一回事：后者答"现在是谁"（选择），前者答"这里有哪些 DID"（身份），
  所以第三列是 DID 而**不是** handle，也不带 `current` 标记；`did create` 注册失败留下的那个
  有目录、没 DID 的身份不会被藏起来，它写 `not registered`——那一行正是这个命令存在的理由。
  没有 `curve` 列：这边绑定钥永远是 `e1_` 的 Ed25519，每行都一样的列是噪音。
  `create` 与 `register` 都会把主机随受理一起发下来的 **bearer token** 存进 `session.json`
  （同目录，明文 `0600`）——它是唯一能喂给主机自己那几个方法的凭据，下面两条读它。
- **`did publish [--agent] [--profile] [--json]`** —— 把本地的文档推给主机，走的是主机的
  `update_document` 而不是 ANP 的签名路。三件事按这个顺序：`get_me` 取回主机**正在服务**的那份
  文档、哈希它（`sha256:` + base64url sha256(JCS(doc))，正是主机算 CAS 的方式）、
  然后拿这个值当 `expected_document_hash` 发出去。文档在本地改过就得**重签**（proof 覆盖文档
  自己的字节，改一笔就作废，主机回 `did_document_proof_invalid`），所以 `resign_document`
  用 key-1 重签，成功后把主机回的那份**写回 store**——不写回，磁盘上就留着一份 proof 盖不住
  自己的文档。本地与在册两份的比对**忽略 `proof`**：没有两份 proof 是逐字节相等的（`created`
  是时间戳），照整体比会把每次发布都当成一次变更。`register` 的响应丢了（主机有、本地不确定）
  也是这条命令的理由。
- **`did resolve | restore`** —— `resolve` 是解析面：不给 `--chain` 就取那一份文档
  （`document_is_superseded` 时退出 2，并提示 `--chain`），给 `--chain` 就按 crate 的
  `resolve_current_did` 走完更新链，把"当前的是哪个 DID、中间每一跳的 assurance"打出来
  （`identity/chain.rs` 只是那条同步 fetcher 与本客户端异步取文档之间的适配器）。
  `restore` 是**明说的拒绝**：`anp` 没有恢复路径，更新链把钥往前推、推不回来，所以它
  退出 1 并说清"什么都没读、什么都没恢复"。
- **`did update [--target <uri>] [--resume]`** —— 写的那半：把 DID 换到一把后继钥
  （ANP-03 §2.5.3）。后继钥在**任何字节出门之前**先写进 `successor.json`（0600），因为
  服务器接受之后、store 搬过去之前，那个文件是 DID 已经搬过去的钥的**唯一**副本。
  投递失败分两型：证明没落地的（本地拒绝、服务器回错误状态）丢掉暂存钥；不能断言的
  （连接被掐、超时）**留着**并把文件名与 `--resume` 打出来。`--resume` 走一次更新链问
  服务器"现在服务的是哪个 DID"：是暂存的继任者就提升，还是旧的就没落地、丢掉，是第三个
  就什么都不动——这是那种"一个字都可能把唯一一份钥弄丢"的地方。`--target` 必须点名：
  §2.5.3 没有定义管理接口，往哪投是服务器自己的契约。
- **`anp show | sign`** —— 应用层看这份身份的两个角度，都**不连网**。
  `show` 摊开一次换钥会分开的那对名字：稳定的 `subject` 与当前的 `did`（把会话挂在 `did`
  上的依赖方会在换钥时丢账号），外加 peer 要找的 `keyid` 与 key 文件的权限。
  `sign` 打出这个身份**会**放上线的整条 ANP-02 请求（body + RFC 9421 头 + DID 文档），
  一行都不发——所以它是核一个 target 契约的工具。`anp/request.rs` 是那条字节的唯一出处，
  与 `did update` 那一跳共用；单测把它的产出递给 crate 自己的 `verify_http_message_signature`
  验，因为两端都自己的验签等于没验。
- **`anp login --target <url>`** —— `sign` 那份请求，发出去，把服务器发的凭据拿回来。
  401 挑战只答一次，而且只在服务器报了一个**不同的** nonce 时才重签：同一个 nonce 再挑战一次
  是在拒绝。409 `did_superseded` 是一个**结论**而不是一次被拒的证明，所以它不走"登录失败"那条
  路——`currentDid` 只是 peer 的提示（ANP-03 §3.2），这个客户端拿**自己的**链（`resolve_chain`）
  说哪个 DID 才算数，`--target` 的 rig 说了谎也会被当场拆穿。token 从 `Authentication-Info`
  或 body 里取，缓存进 `session.json`（同目录，明文 `0600`，和私钥一样），键是 **`host:port`**
  而不是 host——同一台机器两个端口是两个签发方，共用一条等于后一次登录吃掉前一次；
  写失败只警告不失败，token 已经在手里了。`--no-save-session` / `--session-ttl 7d` / `--json`。
- **`me show | set`** —— 主机给这条身份记的资料：昵称、简介、头像。
  这一族**不是 ANP 协议**：协议里根本没有昵称这一类东西（`member_list` 的每一项只有
  `{agent_did, role, status, joined_at}`，群自己的名字是 `group_profile.display_name`，
  走 `group.update_profile`）。资料落在**服务该 DID 的那台主机**上，`get_me` / `update_me`
  收的是 `display_name` / `description` / `avatar_uri` / `profile_uri`；旗标按人话命名
  （`--name` / `--bio` / `--avatar` / `--profile-url`），只有点过名的才发出去，所以改昵称
  不会顺手清掉头像。它与 `did publish` 是缓存里那个 token **仅有的**两个消费者。
- **`version`** —— 词形的版本号（`--json` 给 `{"version": …}`），与 `--version` 是同一个事实。
- **`agent show | use | list`** —— 本机现在是谁（当前 agent 存在 store 根的一个文件里，
  所以是整机范围而不是单进程）。`use` 允许点名一个还没存身份的 agent——先选 agent、
  再造它的钥，正是一个新 agent 出生的顺序——但会说出来。
- **`discover <endpoint>`** —— `anp.get_capabilities` 是唯一不需要 auth 的方法（P1 §8.2），
  所以它不需要身份，也就成了最省的"端点活着吗、说的是这个协议吗"检查。端点只给主机时
  自动补 `/anp-im/rpc`。

```bash
cargo run --manifest-path rust/Cargo.toml -- discover http://127.0.0.1:8787
```

- **`msg send | caps | inbox | show | read`** —— `src/message/channel.rs` 是那条消息层的
  一跳（`Sender` / `Endpoint` / `Channel`、`call` / `call_extension` / `call_group`）。
  `msg send --to` 收 **DID 或通讯录里的名字**：DID 形状的参数（`looks_like_a_did` 是语法
  测试，不是方法白名单）直接进发现，其余当名字查通讯录（见下面 `contacts` 那条），
  两个名字指向同一人时**退出 1 并列出候选**，不随便挑一个。
  **三条 `send` 都往本地留一行**（[client-messages.md](../docs/design/client-messages.md)）：
  在服务端回 `accepted: true` **之后**写，`message_id` 就是 `--operation-id` 那个值。
  留不下只是 stderr 一句话——信已经发出去了，一个满盘不该让脚本以为没发成。
  `msg send` 两个本机身份**双向** `direct.send` 跑通（两边都回 `accepted: true`）；
  `msg fetch` 与 `msg listen` 走的是 `x_agentx.inbox.v1` 扩展面（`fetch` 用 `sync.delta`、
  `listen` 用 `stream.*`），仅实现规范的对端回 `-32601` 是**正确的负结果**（cli.md §5），
  不是缺陷：它报成 `unsupported_extension` 并退出 1，
  与"对端拒绝了"（`message_send_failed`）分开——两句话要能分开，脚本才分得出"该换个对端"
  和"这次没成"。这两条各有单测咬住，真主机那半在
  `scripts/e2e.sh --with-awiki` 里断言。
- **`contacts list | add | set-remark | remove | resolve`** —— 名字 ↔ DID 那一层（TODO6 §3）。
  表不在本地文件里，在**本仓 `packages/service` 的库**里（`x_agentx.contacts.v1`），
  按**请求的已验证签名者** `owner_did` 分行，所以一个身份的备注对另一个身份天然不可见，
  不需要文件权限来保证。行按 **`subject`** 存、不按 `did`——`did update` 会把 DID 挪走
  （它内嵌钥指纹），备注挂 `did` 上就会在换钥时静默消失，这正是 `anp show` 非要把
  subject / did 摊开成一对的原因。
  `resolve` 是**给 Agent 用的那条**：名字进、DID 出，`--json` 给机读；DID 形状的参数
  直接原样返回（`source: "argument"`，不连网、不读 store）。
  `set-remark` 与 `remove` 的 `<name>` 收**名字或 DID**，解名字的路子和 `msg send --to`
  是同一条（所以重名在这里也照样拒，不会改错人）。
  `add` 的 `--remark` 缺席时**保留原有备注**（清空要显式 `--clear-remark`），因为线上
  缺字段就是清空，而 `contacts add <did>` 本意常是"确认这个人已在册"。
  `add` 收非 DID 的输入会**在开身份之前**就拒掉：`subject_of` 是全函数，否则
  `contacts add Alice --remark Alice` 会落一行键是字面量 `Alice`、永远发不出去的记录。
  **收到一条私聊也会让发件人落一行**（写入路径 ②），但没有备注、且**绝不碰已有的备注**
  ——一封来信对名字没有说任何话。所以 `contacts list` 顺带就是"谁跟我说过话"，
  而对端换钥后再写一封信，新 DID 就落回那一行的 `did` 列。
  没有 nickname / 头像字段：那是对方自己的说法、存在**对方**的主机上，存到这儿就是一份
  没有失效机制的缓存。判定逻辑是 `src/contacts.rs` 里对 book 的**纯函数**（11 个单测）。
- **`msg listen`** —— 唯一那条常驻契约（[realtime.md](../docs/design/realtime.md)）。
  `message/stream.rs` 是传输（地址推导 + WebSocket 拆成读写两条任务），`message/listen.rs`
  是状态机。游标在服务端按 `(owner_did, device_id)` 存，`stream.ack` 是唯一写入者；
  Ctrl-C 退出 0，掉线按 2s→30s 退避重连；`--once` 只补拉。
  **它同时是 `messages.db` 的写入侧**（[client-messages.md](../docs/design/client-messages.md)）：
  每消费一条就往 `<agent>/<profile>/messages.db` 落一行，同时推进本地游标
  `sync_state.applied_seq`。录制挂在 `ListenView` 上（`RecordingView`），所以**到消费侧才落库**，
  终端看到的东西一个字不变；写失败只在 stderr 说一句、不退出——那一行的游标没有前进，
  下次重连服务端会重放。P6 的 §12 帧走**设备队列**，没有交付号，所以它只落行、不动游标。
  文件明文 0600，**按密钥对待**（TODO4 §E）：没有导出命令，备份它就是备份聊天记录。
- **读那一侧：`messages.db` 的读，与 `msg fetch`** —— `inbox` / `history` / `show` 都只有
  `MessageStore` 的查询，**一个连接都不开**：`open_read_only` 不解析服务、不建文件，
  真没有就答"这儿还没有"。所以这一族的**可断言行为**是断网照答（e2e 里真把服务端杀掉再读
  一次）。`msg fetch` 是唯一联网的那条，而且它是一次**写**：`sync.delta` 的每条 entry
  本来就是流会推的那个通知，`decode_message` 把它变成监听会看到的那一帧，
  `records_from` + `MessageStore::record` 是**监听自己那条写入路径**——一份映射，
  两半才不会对"什么算一条投递"各说各话。幂等是双重的：去重键
  `(conversation, sender, message_id)` 管行、单调游标管序。搬不回来的（服务端裁掉的、
  设备队列过期的、比服务端可读窗口更早因而"不删但看不见"的、换钥后挂在旧 DID 下的、
  以及它没有 MLS 接收侧解不开的 P6 密文）**点名说清**，不假装本地就是全部——其中窗口外
  那一类由 `sync.delta` 的 `aged_out` 数出来（`--json` 里是 `aged_out` 字段），
  `fetch` 于是不把"还有 N 条够不着"打印成一句"brought in: 0"。
- **`group create | info | members | join | leave | send | update-profile | set-remark`** —— P4 `anp.group.base.v2`。
  `src/group.rs` 放策略逻辑（§7.1 的推荐策略、`--policy` 的浅合并、封闭集合校验）。
  `update-profile --name` 改的是**群自己的名字** `group_profile.display_name`（§7.4），
  正文是 `group_profile_patch`（RFC 7386 合并，§8.7.2），要走 `permissions.update_profile`——
  这是 CLI 里唯一能写群名的地方；`group info` 把它读出来。
  **`members` 的名字有两档**（TODO6 §4.2）：默认读一次通讯录（`contacts.list`），
  认得的成员在 DID 后面跟**你给他起的备注**——名字挂在 `subject` 上（§3.2），
  对端换钥也不会丢；认不得的就只出 DID，那正是 `--names` 存在的理由，
  它逐个别名成员去**各自的主机**取对方给自己起的名字。两处都只做**非 `--json`** 的那一档：
  `--json` 始终是服务的答复原文，名字属于给人看的那一层（和 `msg send --json` 的 `named:` 同一条规矩）。
  `--names` 有两条要说清的：一是**备注优先**——`--names` 只补通讯录不认得的那几个，
  已经起过名的成员不会被对方改过的昵称顶掉；二是**它读的是 awiki 的公开资料路由，不是 ANP**
  （协议里根本没有昵称，见 `me show | set` 那条）。所以对端主机不是 awiki 时，这个成员就
  退回只出 DID，末尾打一行 `note: N member(s) could not be named`——**不是失败**，
  可执行的那一半（DID）照样在。
  **`set-remark` 是同一件事的另一半**（TODO6 §4.2）：`update-profile --name` 写的是**群自己的**
  名字，存在群的主机上、对所有人一样；`set-remark <group_did> <名字>` 起的是**只有我看得见**的
  那个，存进服务里另一张表（`x_agentx.group_remarks.v1`，`docs/design/message-service.md` §9.5），
  `group info` 把它印在 `name:` 的下一行。
  **两本书不合并**：通讯录是"`msg send --to` 能到谁"，键的另一头是一个 agent；并进一本书就会让
  一个名字解析成群 DID，再让 `msg send --to <那个名字>` 把消息投进一个群读不了的邮箱。
  表的键是 `group_did` 本身、不是 `subject`——群 DID 是本服务命名空间里的 `did:web:…:g:<id>`，
  不含钥指纹、也不会轮换（`subject_of` 在它身上是恒等函数），这是它和通讯录表唯一的结构分歧。
  `--clear` 是同一个动词的取反（对照 `contacts add --clear-remark`，不为清空另开一条子命令），
  服务**不检查**这个群是否托管在本机——"记得一个联邦那头的群"恰恰是本地这本册子该管的事。
  **端到端要打本仓的 `packages/service`**：本机 awiki host 对 `group create` 回 HTTP 401，
  是它自己不许 public RPC 建群的策略（`group.remote_create_not_allowed`），
  详见 [TODO5.md](../TODO5.md) §6 Phase 1。
- **`group e2ee publish | get-key-package | create | add | remove | send`** —— P6 `anp.group.e2ee.v2`。
  `src/mls.rs` 是设备半边（造 KeyPackage、跑 prepare/finalize/abort），`src/group_e2ee.rs`
  是线上半边（请求体的形状）。前两条是**服务作用域**的 KeyPackage 方法；
  `create` / `add` / `remove` 是四条控制方法里已落的前三条，也是那条让三条共用的三阶段
  （prepare → 发送 → finalize 或 abort，§13.6）露出来的地方：服务拒绝就 abort，
  传输失败则留给 crate 的 `reconcile_pending_v2`，因为那时"服务到底收没收"是不知道的。
  `add`、`remove` 按 §4.4.2 群寻址（`target.did == group_did`），`create` 不是。
  `add` 的成员那一对取自 KeyPackage 的 owner、KeyPackage 去**成员自己的** service 取
  （成员的文档指名它的 Host，§8.2.3 允许跨域）；`remove` 少一半：目标 leaf 是点名的、
  没有包可取，被移除的设备也**不必**合格（失去资格正是移除它的理由），所以只读它的 DID 文档。
  `send`（§9.5）是四条里唯一**不是三阶段**的一条：它按当前 epoch 造一个 `PrivateMessage`，
  要么产出 cipher object、要么失败，没有 pending 行；而它的 origin proof 必须由**设备**的钥
  签（§13.3 第 6 项，服务拿 `keyid` 比文档里的 `signing_key_id`），所以只有这一条把 signer
  换成 `{device_id}-sign` 那一半。
  这几条正是这个客户端用 Rust 写的理由：`awiki` 托管的身份对 P6 回 `anp.not_supported`
  （它没有 P6），所以它们**只对本仓的 `packages/service` 有意义**。已端到端跑通（发布 →
  取出 → 取空后回 `key_package_not_found`；`group create` 建群 → `e2ee create` → 服务落
  owner leaf、本地 pending 转 `finalized`；`e2ee add` → 源成员 leaf 进到 epoch 1，新成员
  leaf 落 `active`、包转 `consumed`；`e2ee remove` → 目标 leaf 转 `terminal`、其余 leaf 进到
  epoch 2、被移除的设备收到 `final-notice`；`e2ee send` → 回 `accepted: true`、收件进设备队列、
  只推 `group_event_seq`），控制方法都**不动** P4 的 `group_state_version`。
  做法见 [TODO5.md](../TODO5.md) §6 Phase 3。
- **`examples/phase0_key_package.rs`** —— Phase 0 的 spike，仍可复跑（它是怎么验证 crate
  能驱动 P6 设备半边的记录，结论在 TODO5 §6）：

```bash
cargo run --manifest-path rust/Cargo.toml --example phase0_key_package -- /tmp/agentx-spike
```

### 约定（每条命令都适用）

上面那些是**为什么**；从这里往下是**怎么用**：先一次说清所有命令共有的东西，再逐族列旗标
与默认值。`anpio-cli <族> --help` / `anpio-cli <族> <子命令> --help` 打印同一份东西。

**这一层是定稿的（2026-10-02，TODO6 §7）。** 下面这张表与六个族的表共同组成命令面的契约，
**权威是 `--help`**，文档与它不一致时以 `--help` 为准（不一致本身就是 bug）。"定稿"在这里
指一件具体的事：**加命令是加法，改名与删命令是破坏性的**——`rust/crates/anpio-cli/
tests/cli_surface.rs` 里逐字列着今天每一个页面，删一个或改一个名字，那一格就红，
必须有人**故意**去改那份清单。旗标**没有**被这样钉住，是刻意的：它们会随协议长出来，
把每个旗标抄进测试只会让每次加法都要改测试，而它换不来"某个旗标被改名"之外的东西。

| 旗标 | 作用 |
| --- | --- |
| `--allow-private-host <host>` | 把一个**不以 loopback 拼法出现**的本地主机当成"本机"。`localhost` / `127.0.0.1` / `::1` 已经算本机，不需要它；它管的是"是本机但没这么拼"（一个 LAN 地址、一个往里解析的名字）。放行之后**同时**允许私网地址与明文 `http`（ANP-02 的 TLS 要求针对真部署，本机开发服务器是它存在的理由）。 |
| `--json` | stdout 变成机读：多数命令一个 JSON 对象，`msg listen` 是每行一个（[realtime.md](../docs/design/realtime.md)）。状态、进度与错误**始终**走 stderr，所以 `> file` 拿到的是纯结果。 |

**身份怎么选。** `--agent` > `$ANPIOCLI_AGENT` > 当前 agent（`agent use` 选的）> `default`；
`--profile` > `$ANPIOCLI_PROFILE` > `default`。**`did create` 是唯一不走这条链的**：它造的是
**新的**身份，"谁当前被选中"不该决定第二份身份写在哪，所以缺省用 `--handle`。

**退出码。** 0 成功、1 失败，只有 `did resolve` 例外——它按**答案**而不是按成败给码：
**2** 这份文档已不是当前（链走过了，或是退役声明），**3** 更新链没验过，**0** 当前；
取不到文档是普通失败，给 1。

**失败长什么样。** stderr 上一行 `Error: <稳定码>: <人话>`，退出 1。稳定码沿用旧 TS 客户端
`ConnectxError.code` 的那套拼写（`message_invalid` / `message_send_failed` /
`unsupported_extension` / `did_resolve_blocked` / `message_service_not_found` …），
所以脚本按它分支，不必解析人话——那套拼写比那个客户端活得久。

### `did` 与 `agent`

| 命令 | 位置参数 | 旗标（默认值） |
| --- | --- | --- |
| `did create` | — | `--host <URL>`（必填）、`--handle <NAME>`（必填）、`--agent`（缺省=handle）、`--profile`（`default`） |
| `did attach-anpio-key` | — | `--did <DID>`（必填）、`--key-root <DIR>`、`--socket <PATH>`、`--kid <FRAGMENT>`、`--host <URL>`、`--agent`（缺省=handle）、`--profile`、`--force`、`--json` |
| `did show` | — | `--agent`、`--profile`、`--json` |
| `did list` | — | `--json` |
| `did register` | — | `--agent`、`--profile` |
| `did publish` | — | `--agent`、`--profile`、`--json` |
| `did update` | — | `--target <URI>` 与 `--resume` **二选一**（都给、都不给都拒）、`--json` |
| `did resolve` | `<DID>` | `--chain`、`--json` |
| `did restore` | — | —（调用即以 1 退出） |
| `agent show` | — | `--json` |
| `agent use` | `<ID>` | `--json` |
| `agent list` | — | `--json` |

失败时说什么（挑不显然的，其余都是 `Error: <码>: <人话>` 那一句）：

- **`did publish` 没有可用 token**：退出 1，并把回程路写出来：

  ```text
  no usable access token for <host> — run `anpio-cli did register --agent <agent>` or `anpio-cli anp login --target …`
  ```

  token 就在 `session.json` 里（`did create` / `did register` / `anp login` 都会写它）；
  删掉这个文件，等于"register 这一步从没发生过"。
- **`did create` 注册失败**（handle 已被占、主机不通…）：退出 1，并且**明说身份已经落盘**——
  `the identity was saved, but publishing it failed: …` 加一行 `retry with: anpio-cli did
  register --agent <agent>`。所以本地那半是好的：目录在、DID 不在，`did list` 如实写
  `not registered`（那个命令存在的理由就是这个状态），补一次 `did register` 即可。
- **`did update` 的两种拒绝**：`--resume` 与 `--target` 一起给 → `--resume settles an update
  that was already attempted, so it takes no --target`；两个都不给 → `missing --target: …`。
  另有一条更重的：本地**已经暂存了一个后继钥**时再要投一次新的，会被拒而不是覆盖——
  那次投递的结果不知道，暂存的那个可能是 DID 已经搬过去的那把钥的**唯一**副本。
- **`did restore`**：一律退出 1，并且说清**什么都没读、什么都没恢复**。`anp` 没有恢复路径，
  更新链只往前推（ANP-03 §2.5.3）——这是"明说的拒绝"，不是缺实现。
- **`did resolve <did>` 不带 `--chain`，而文档已被取代**：照常打印文档，然后**退出 2**，
  并提示 `--chain`。取代的文档是**证据**，不是错误。

### 私钥放在 anpio-key 里：`did attach-anpio-key`

`did create` 把私钥写进 `<store>/<agent>/<profile>/identity.json`。另一条路是把钥匙交给
[`anpio-key`](https://github.com/open-agentx/anpio-key) 那台本地守护进程：**身份文件里一个私钥字节都没有**，
每次要签名时由 CLI 通过 socket 请它签。

```text
anpio-cli did attach-anpio-key --did did:wba:example.com:user:bob:e1_…
```

前提是守护进程在跑、那把钥已 `unlock`。命令先向守护进程要文档（`anpio-key document --did`），
文档里必须真有这把钥，然后才写身份——要么守护进程确实持有这把钥，要么 store 一点没动。
`--kid` 收的是 fragment（`key-1`），给整条 `did:wba:…#key-1` 也认（`anpio-key list` 打出来
的就是整条）。`--agent` 缺省是 handle，`--host` 缺省由 DID 的 authority 推出来
（`localhost` / `127.0.0.1` 用 `http://`，其余 `https://`）——host 只服务 `register` /
`publish` / `me` 这类控制面，签名不用它。

**能的**：`anp sign` / `anp login` / `anp show`、`did show` / `did register` / `did publish`。
签名时文档是从守护进程现取的，不是身份文件里那份快照——密钥轮换过也不会拿着旧文档去签。
`did register` / `did publish` 同样先取当前文档。

**不能的**：`msg`、`group`（含 E2EE）、`did update`。这不是没接线，是守护进程的合同里
没有这条路：`anpio-key` 只签**整条 RFC 9421 HTTP 请求**，默认构建里没有任何"签任意字节"的
命令。`msg` / `group` 的 origin proof 是对 CLI 自己拼的字节签的，MLS 设备钥也是 CLI 自己
mint 的，`did update` 的退役文档还得由 key-1 签——三处都拿不到 daemon 手里的钥，所以
命令在动手之前就拒，并列出这条身份**能**做什么。

环境：`$ANPIOCLI_ANPIO_KEY` 指定二进制（缺省 `anpio-key`，走 `PATH`），`--key-root` /
`--socket` 指定守护进程的库（缺省交给 `anpio-key` 自己的 `~/.anpio-key`）。

> crates.io 上的 `anpio-cli` 是**别人的包**（`open-agentx/anpio-cli`），和这个仓不是同一份
> 代码，所以这份文档不写 `cargo install anpio-cli`；要从源码装就 `cargo install --path
> rust/crates/anpio-cli`。

### `msg`

**读这一族读的是本地。** `msg inbox` / `msg history` / `msg show` 打开的是这台机器上的
`messages.db`，**不是服务端**，所以服务端关着它们照样答（2026-10-03 用户裁定"读聊天记录
就是读本地，远程是 `fetch`"；完整的重画在
[client-messages.md](../docs/design/client-messages.md) §8）。`msg inbox` 的名字没变，
**变的是它回答的问题**：从"服务端有什么"变成"我有什么"。要联网的是**另一条**命令
`msg fetch`，而且它是一次**写**（把服务端**还有的**搬进本地库）。

| 命令 | 位置参数 | 旗标（默认值） |
| --- | --- | --- |
| `msg send` | — | `--to <DID\|NAME>`（必填）、`--text` 与 `--body` **二选一**、`--content-type`（`--text` 缺省 `text/plain`，`--body` 缺省 `application/json`）、`--operation-id`、`--json`、`--agent`、`--profile` |
| `msg caps` | `<DID>` | `--json` |
| `msg inbox` | — | `--limit <N>`（20）、`--unread`、`--json`、`--agent`、`--profile` |
| `msg history` | `<PEER_DID>` | `--limit <N>`（20）、`--json`、`--agent`、`--profile` |
| `msg show` | `<MESSAGE_ID>` | `--json`、`--agent`、`--profile` |
| `msg read` | `[MESSAGE_ID]…` 或 `--all` | `--all`、`--json`、`--agent`、`--profile` |
| `msg fetch` | — | `--since <SEQ>`、`--limit <N>`（100）、`--json`、`--agent`、`--profile` |
| `msg listen` | — | `--device <ID>`（缺省=本机 `agent/profile`）、`--since <SEQ>`、`--ack`、`--once`、`--json`、`--agent`、`--profile` |

`msg history` 要的是**一个 DID**，不是一个名字：名字只活在服务端的通讯录里，收名字就等于
让这条读命令联网。手上有名字就先 `contacts resolve`。同理，`msg read` 是**本地写**——
已读状态只有**一个**归属，就在这一台机器的 `messages.db` 里，所以服务端的
`inbox.mark_read` 不再有客户端（TODO7 §4，2026-10-03 裁定）。

失败时说什么：

- **正文的形状是三方约束，两处拒绝**：`--text` 与 `--body` 一起给是
  `--text and --body are two spellings of the same thing; pass one`；都不给是
  `missing required option --text or --body`。再加上 `--content-type` 的四种组合里只有两种
  合法（`text/plain` 配 `--text`、`application/json` 配 `--body`），另外两种各有一句话
  说清"该换哪个旗标"。同一个 `payload_of` 同时伺候 `msg send` 与 `group send`——
  规范里两处的引文不同、约束相同，写两遍就是两次漂移的机会。
- **`--to` 是名字而名字有歧义**：退出 1，**逐个列出**候选的 DID 与备注，不挑"拼写更准"的
  那个。所以 `Alice` 与 `alice` 同时在册时，`msg send --to Alice` 不会猜。
- **`msg inbox --limit 0`**（或任何不能解析成正整数的值）：`--limit must be a positive
  integer (got "0")`。默认 20，`msg fetch` 与 `msg history` 同理。
- **`msg history <name>` 给的是名字**：退出 1，并指到 `contacts resolve`。本地库按 DID 归档，
  而查名字要读服务端的册子——这条命令不联网。
- **`msg show <id>` 这台机器上没有这一行**：`no message <id> in the local record`，退出 1，
  并说明 `msg fetch` 补的是"服务端**还有的**"。不渲染成"空收件箱"——"这条消息这台机器
  没见过"与"我用错了 id"的观感在别处是一样的，所以要分开。
- **`msg read` 的两种说错**：既没给 `<message_id>` 也没有 `--all` →
  `missing required argument <message_id>, or --all`；两个都给 →
  `--all and <message_id> are two spellings of the same thing; pass one`。
  `--all` 落的是**问的那一刻**未读的那些行。标不动的 id（已读、不在本地、或自己发出去的
  那些）不计数：报成"标了"会让这个数字什么都不说明。
- **`msg fetch` 断网**：明确失败，而且**第一行就点名自己**——
  `msg fetch` is the one read that goes online: it asks <endpoint> for its sync.delta page.
  `msg inbox` / `history` / `show` answer from the local record and need no network.
  不这么写的话，断网时的 `error sending request` 读起来像是"本地记录坏了"，而记录恰恰是还好着
  的那件东西。它对**只实现规范**的对端报 `unsupported_extension`（`sync.delta` 是实现扩展、
  规范未定义），退出 1，**这是正确答案**不是缺陷。
- **`msg fetch` 搬不回来的**：已经 ack 掉又被服务端裁掉的、设备队列过期了的、换钥后仍挂在
  旧 DID 下的，都搬不回来。P6 的密文帧尤其——这台命令没有 MLS 接收侧，解不开，所以它会
  **点名**说哪些没取，而不是把密文当成正文记下来。
- **`msg listen`**：Ctrl-C 退出 **0**；掉线按 2s→30s 退避重连；`--once` 补拉完就退出 0；
  `--json` 强制 NDJSON（不给时"管道也是机器"）。不支持 stream 的对端在握手上就终止，
  报 `unsupported_extension` 而**不重连**——答案是同一个，重连只会看起来像在工作。
  `--ack` 除了给服务端发 `stream.ack`，还**把刚落的那一行标成本地已读**（已读只有一个归属）。

### `group`（含 `group e2ee`）

| 命令 | 位置参数 | 旗标（默认值） |
| --- | --- | --- |
| `group create` | — | `--name <NAME>`、`--policy <JSON>`（在 P4 §7.1 的推荐结构上**浅合并**）、`--json`、`--agent`、`--profile` |
| `group info` | `<GROUP_DID>` | `--json`、`--agent`、`--profile` |
| `group members` | `<GROUP_DID>` | `--names`、`--json`、`--agent`、`--profile` |
| `group join` / `group leave` | `<GROUP_DID>` | `--json`、`--agent`、`--profile` |
| `group send` | `<GROUP_DID>` | `--text` / `--body`（二选一，规则同 `msg send`）、`--content-type`、`--operation-id`、`--json` |
| `group update-profile` | `<GROUP_DID>` | `--name <NAME>`（**必填**）、`--json`、`--agent`、`--profile` |
| `group set-remark` | `<GROUP_DID> [REMARK]` | `--clear`（与 `REMARK` 互为取反）、`--json`、`--agent`、`--profile` |
| `group e2ee publish` | — | `--key-package-id <ID>`、`--valid-days <DAYS>`（7）、`--json` |
| `group e2ee get-key-package` | — | `--target-did <DID>`、`--target-device <ID>`（都必填）、`--suite <SUITE>`、`--require-fresh`、`--json` |
| `group e2ee create` | `<GROUP_DID>` | `--key-package-id <ID>`、`--operation-id <UUID>`、`--json` |
| `group e2ee add` / `remove` | `<GROUP_DID>` | `--member-did <DID>`、`--member-device <ID>`（都必填）、`--operation-id`、`--json` |
| `group e2ee send` | `<GROUP_DID>` | `--text` / `--body`、`--content-type`（**自由**，见下）、`--operation-id`、`--json` |

失败时说什么：

- **`group set-remark` 既没给 REMARK 也没给 `--clear`**：clap 的用法错误，**退出 2**，
  stderr 上是 `error: the following required arguments were not provided: <REMARK>` 加一行
  `Usage:`。给了空串是另一种：`a remark cannot be empty; --clear is how one is dropped`，
  退出 1。两条都写出来，是因为"用错了"与"内容不合格"是两件事，而**它们的退出码不同**。
- **`group create --policy` 越界**：封闭集合先校验再联网，例如
  `Error: message_invalid: --policy admission_mode must be one of admin-add, open-join
  (P4 §7.1 L349)`，退出 1，**一个字节都没发**。默认策略里 `admission_mode` 是 `open-join`。
- **`group join` 而群不是 `open-join`**：服务按 §8.3.2 拒，错误里带 `policyViolation`
  （3003）。这不是客户端的毛病——"这个群不让自助加入"是群策略在说话。
- **`group e2ee` 的四条控制方法**：服务答得"不像成功"时**不当作成功**——`publish` 要
  `published: true`、`create` 要 `created: true`、`add` / `remove` / `send` 要
  `accepted: true`，少了就退出 1 并引规范条款。服务拒绝则 abort，传输失败留给 crate 的
  `reconcile_pending_v2`（那时"服务到底收没收"是不知道的）。
- **`group e2ee send --content-type`**：这是**加密内容**的类型（P6 §7.4
  `application_content_type`），是自由的；外层 `meta.content_type` 才是被 §9.5.3 钉死成
  一个值的那一个。两者不是一回事，别按 `msg send` 那套去理解。
- **`group members --names` 取不到名字**：末尾多一行，**不是失败**——可执行的那一半（DID）
  照样在：

  ```text
  note: N member(s) could not be named (no public profile on their host); their DID is printed instead
  ```

  名字在这一族里只走**非 `--json`** 那一档。

### `contacts` / `me` / `anp` / `discover` / `version`

这五族的旗标只剩共有的那几个：`--agent` / `--profile`（身份怎么选见上文）与 `--json`；
`--allow-private-host` 也每条都在，不再逐行重复。

| 命令 | 位置参数 | 旗标（默认值） |
| --- | --- | --- |
| `contacts list` | — | `--json` |
| `contacts add` | `<DID>` | `--remark <NAME>`（缺席=保留原有备注）、`--clear-remark`、`--json` |
| `contacts set-remark` | `<NAME> <REMARK>` | `--json` |
| `contacts remove` | `<NAME>` | `--json` |
| `contacts resolve` | `<NAME>` | `--json`（整行，含 `subject`，而不只是裸 DID） |
| `me show` | — | `--json` |
| `me set` | — | `--name <TEXT>` / `--bio <TEXT>` / `--avatar <URI>` / `--profile-url <URI>`（**至少给一个**）、`--json` |
| `anp show` | — | `--json`（整条记录，含 DID 文档） |
| `anp sign` | — | `--target <URI>`（**必填**）、`--method <VERB>`（`POST`）、`--nonce <NONCE>`（`""` = 请对端挑战） |
| `anp login` | — | `--target <URI>`（**必填**）、`--nonce <NONCE>`（`""`）、`--session-ttl <SPEC>`（`7d` / `24h` / `30m` / 裸秒，**服务器自己的到期更短时以它为准**）、`--no-save-session`、`--json` |
| `discover` | `<ENDPOINT>` | 无（裸主机自动补 `/anp-im/rpc`；也**不需要身份**） |
| `version` | — | `--json` |

失败时说什么：

- **`contacts add` 收到的不是 DID**：退出 1，**在开身份之前**就拒——不读 store、不连网：

  ```text
  Error: message_invalid: "Alice" is not a DID: `contacts add` takes the DID, and the name goes in --remark (`anpio-cli contacts add did:wba:… --remark Alice`)
  ```

  不这么拦，`subject_of`（全函数）会把字面量 `Alice` 原样存成一个键，落一行永远发不出去、也永远
  匹配不上任何 DID 的记录。
- **名字对上了不止一个联系人**：退出 1，**逐个列出**候选（`DID\t备注` 一行一个），末尾点名
  `contacts set-remark`。`msg send --to` 用的是同一个判定，所以同一处歧义在这里也照拒。
- **名字不在册**：退出 1。读这句话的是被交代了"发给 Alice"的那个 agent，所以它给的是**能照做的
  下一步**，不是一个解析成了空的字符串：

  ```text
  no contact named "Alice": add one with `anpio-cli contacts add <did> --remark Alice`, or use the DID directly
  ```
- **`contacts set-remark` / `remove` 的 `<name>` 收名字或 DID**，解名字的路子与 `msg send --to`
  同一条（所以重名在这里也拒）。`remove` 一个册上没有的 DID：
  `{did} was not in the book; nothing to remove`，退出 1。
- **`contacts resolve` 收到 DID 形状的参数**：原样返回，**不读 store、不连网**，`--json` 里
  `"source": "argument"` 把这件事说出来（从册里来的那档是 `"source": "contacts"`）。
- **`me set` 一个字段都没点**：`nothing to set — pass at least one of --name, --bio, --avatar,
  --profile-url`，退出 1。**只有点过名的字段才发出去**，所以改昵称不会顺手清掉头像。
- **`anp login` 的 401 挑战只答一次**，而且只在服务器点了**另一个** nonce 时才重签——同一个
  nonce 再挑战一次是在拒绝，不是要求再签一遍。**409 `did_superseded` 是一个结论**，不是一次
  被拒的证明：它不走"登录失败"那条路，客户端拿**自己的**链（`resolve_chain`）说哪个 DID 才算数，
  所以 `--target` 的 rig 说了谎也会被当场拆穿。token 从 `Authentication-Info` 或 body 里取，
  缓存进 `session.json`，键是 **`host:port`**；**写失败只警告不失败**（`session not saved — the
  token above is the only copy`），因为 token 已经在手里了。`--no-save-session` 打出来但不缓存。
- **`anp sign` 一行都不发**：它打出这个身份**会**放上线的整条 ANP-02 请求（body + RFC 9421 头 +
  DID 文档），是核一个 target 契约的工具。
- **`discover`**：`anp.get_capabilities` 是唯一不需要 auth 的方法（P1 §8.2），所以它是最省的
  "端点活着吗、说的是这个协议吗"检查。端点只给主机时自动补 `/anp-im/rpc`。

## 还没有

身份这块只剩"换设备"，而它核下来是**对端没有这条路**（本机 awiki host 对改设备清单回
`device_*_not_supported`，`replace_did` 回 `not_supported`），不是待办。
命令面本身没有测试长的第三档之外的东西：覆盖是库侧单测 + `scripts/e2e.sh`（真服务、真
socket、真 WebSocket），顺序见 TODO5 §6 的 Phase 3/4。

> 本仓的 `packages/e2e`（对着真服务跑 `connectx` 命令函数的那套 TS 端到端）2026-10-03
> 随 TS 客户端一起删了。它没覆盖这个客户端，所以这里少掉的不是这条；少掉的那一条独有覆盖
> （跨域中继的 `groupFederation`）记在 [TODO7.md](../TODO7.md) §5。
