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
`default`，`--profile` > `$AGENTXCLI_PROFILE` > `default`。`cargo test` 全绿（116 个单测）。

- **`did create | show | register`** —— 身份存储 + DID 文档。
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
  `msg send` 两个本机身份**双向** `direct.send` 跑通（两边都回 `accepted: true`）；
  `inbox` / `show` / `read` 是 `x_agentx.inbox.v1` 扩展面，仅实现规范的对端回 `-32601`
  是**正确的负结果**（cli.md §5），不是缺陷。
- **`msg listen`** —— 唯一那条常驻契约（[realtime.md](../docs/design/realtime.md)）。
  `message/stream.rs` 是传输（地址推导 + WebSocket 拆成读写两条任务），`message/listen.rs`
  是状态机。游标在服务端按 `(owner_did, device_id)` 存，`stream.ack` 是唯一写入者；
  Ctrl-C 退出 0，掉线按 2s→30s 退避重连；`--once` 只补拉。
- **`group create | info | members | join | leave | send`** —— P4 `anp.group.base.v2`。
  `src/group.rs` 放策略逻辑（§7.1 的推荐策略、`--policy` 的浅合并、封闭集合校验）。
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

`did` 剩下的写那半（`update`）、`anp` 一族（`show` / `login` / `sign`）、`version`，
以及身份这块的换钥 / 换设备 / `update_document`。顺序见 TODO5 §6 的 Phase 3。
