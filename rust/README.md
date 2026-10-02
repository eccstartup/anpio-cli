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
    src/message/                 # 信封装配 + 那一跳 HTTP
    examples/phase0_key_package.rs
```

`docs/design/cli.md` §1 的那条线在这个布局里是**物理的**：命令面只解析参数、调库、渲染；
凡是带持续状态的东西（身份库、MLS store、消息库）都在库里。

## 依赖

`anp = "1.0.5"`（crates.io，2026-09-24），**默认 features**（`jwt-pem` + `mls` + `network`）。
注意本地 `~/code/github/anp` 那份检出的 Rust 版本号与 crates.io 不同步——**以 Cargo.toml 里的
pin 为准**，源码阅读用 `git show origin/release/0929:rust/...`。

## 现在有什么

- **`src/message/`** —— Phase 0 查出 crate **不做**的那一段（它停在"签好名的请求对象"，
  见 TODO5 §6）：出站信封装配（`envelope.rs`，移植 `core/message/envelope.ts`）与那一跳 HTTP
  （`rpc.rs`，移植 `core/message/rpc.ts`）。13 个单测，`cargo test` 全绿。
  **已知缺口**：`rpc.rs` 还没移植 `resolveDid.ts` 的 SSRF 逐跳策略，函数注释里有标注。
- **`agentx-cli discover <endpoint>`** —— 唯一一条能跑的命令。`anp.get_capabilities` 是唯一
  不需要 auth 的方法（P1 §8.2），所以它**不需要身份**，也就成了最省的"这端点活着吗"检查。
  端点只给主机时自动补 `/anp-im/rpc`。

```bash
cargo run --manifest-path rust/Cargo.toml -- discover http://127.0.0.1:8787
```

- **`examples/phase0_key_package.rs`** —— Phase 0 的 spike，仍可复跑（它是怎么验证 crate
  能驱动 P6 设备半边的记录，结论在 TODO5 §6）：

```bash
cargo run --manifest-path rust/Cargo.toml --example phase0_key_package -- /tmp/agentx-spike
```

## 还没有

身份存储、`msg` 一族（含 `msg listen`）、`x_agentx` 扩展面、`group`（含 `group e2ee`）。
顺序见 TODO5 §6。
