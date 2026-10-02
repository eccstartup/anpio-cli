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
    src/identity/                # 身份库（store / did 文档 / host 注册）
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
命名。`cargo test` 全绿（69 个单测）。

- **`did create | show | register`** —— 身份存储 + DID 文档。
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
- **`group e2ee publish | get-key-package | create`** —— P6 `anp.group.e2ee.v2`。
  `src/mls.rs` 是设备半边（造 KeyPackage、跑 prepare/finalize/abort），`src/group_e2ee.rs`
  是线上半边（请求体的形状）。前两条是**服务作用域**的 KeyPackage 方法；
  `create` 是四条控制方法里的第一条，也是唯一让 `create`/`add`/`remove` 共用的三阶段
  （prepare → 发送 → finalize 或 abort，§13.6）露出来的地方：服务拒绝就 abort，
  传输失败则留给 crate 的 `reconcile_pending_v2`，因为那时"服务到底收没收"是不知道的。
  这三条正是这个客户端用 Rust 写的理由：`awiki` 托管的身份对 P6 回 `anp.not_supported`
  （它没有 P6），所以它们**只对本仓的 `packages/service` 有意义**。已端到端跑通
  （发布 → 取出 → 取空后回 `key_package_not_found`；`group create` 建群 → `e2ee create`
  → 服务落 owner leaf、本地 pending 转 `finalized`），做法见 [TODO5.md](../TODO5.md) §6
  Phase 3。
- **`examples/phase0_key_package.rs`** —— Phase 0 的 spike，仍可复跑（它是怎么验证 crate
  能驱动 P6 设备半边的记录，结论在 TODO5 §6）：

```bash
cargo run --manifest-path rust/Cargo.toml --example phase0_key_package -- /tmp/agentx-spike
```

## 还没有

身份这块的换钥 / 换设备 / `update_document`；`group e2ee` 剩下的三条群作用域方法
（`add` / `remove` / `send`）与收包路径（`process_welcome_v2` / `process_commit_v2`）。
顺序见 TODO5 §6 的 Phase 3。
