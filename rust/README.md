# `agentx-cli` —— Rust 客户端

[TODO5.md](../TODO5.md) 落地的那个客户端。**与服务端分开**：`packages/service` 继续是 TS 的
ANPMessageService，`packages/cli` 是旧的 TS 客户端（冻结，见 TODO5 §0.1 第 5 条），
这一份是新的。**它也有自己的 store 根**，不碰 `CONNECTX_HOME`（TODO5 §0.1 第 1 条）。

## 为什么在这里、为什么是 Rust

客户端做群 E2EE 需要 MLS。官方的 MLS 实现**只在 Rust crate `anp` 里**
（[client-mls.md](../docs/design/client-mls.md) §2）。把客户端写成 Rust，就能**直接调用**它，
不必走任何绑定层。

## 布局

```
rust/
  Cargo.toml                     # workspace
  crates/agentx-cli/
    src/lib.rs                   # 库 `agentx` —— 协议与状态都在这
    src/main.rs                  # bin `agentx-cli` —— 命令面（薄壳）
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

store 根是 `AGENTXCLI_HOME`（缺省 `~/.agentx-cli`），一条身份由 `--agent` / `--profile`
命名——两个都可以不写：`--agent` > `$AGENTXCLI_AGENT` > 当前 agent（`agent use` 选的）>
`default`，`--profile` > `$AGENTXCLI_PROFILE` > `default`。`cargo test` 全绿（143 个单测）。

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

- **`msg send | caps | inbox | show | read`** —— `src/message/channel.rs` 是 `channel.ts`
  的移植（`Sender` / `Endpoint` / `Channel`、`call` / `call_extension` / `call_group`）。
  `msg send --to` 收 **DID 或通讯录里的名字**：DID 形状的参数（`looks_like_a_did` 是语法
  测试，不是方法白名单）直接进发现，其余当名字查通讯录（见下面 `contacts` 那条），
  两个名字指向同一人时**退出 1 并列出候选**，不随便挑一个。
  `msg send` 两个本机身份**双向** `direct.send` 跑通（两边都回 `accepted: true`）；
  `inbox` / `show` / `read` 是 `x_agentx.inbox.v1` 扩展面，仅实现规范的对端回 `-32601`
  是**正确的负结果**（cli.md §5），不是缺陷。
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
- **`group create | info | members | join | leave | send | update-profile`** —— P4 `anp.group.base.v2`。
  `src/group.rs` 放策略逻辑（§7.1 的推荐策略、`--policy` 的浅合并、封闭集合校验）。
  `update-profile --name` 改的是**群自己的名字** `group_profile.display_name`（§7.4），
  正文是 `group_profile_patch`（RFC 7386 合并，§8.7.2），要走 `permissions.update_profile`——
  这是 CLI 里唯一能写群名的地方；`group info` 把它读出来。
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

## 还没有

Phase 2 的消息库（`messages.db`，TODO5 §4）；以及 Phase 4 的覆盖与收束——本仓的
`packages/e2e` **不覆盖这个客户端**。身份这块只剩"换设备"，而它核下来是**对端没有这条路**
（本机 awiki host 对改设备清单回 `device_*_not_supported`，`replace_did` 回 `not_supported`），
不是待办。六族 24 条的命令面之外新增了 `did publish` 与 `me`。顺序见 TODO5 §6 的 Phase 3/4。
