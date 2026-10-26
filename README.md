# anpio-cli

ANP（Agent Network Protocol）消息层的一套自建实现：一个可部署的消息服务 `AnpioAgent`、
它依赖的协议原语库，以及一个 Rust 命令行客户端 `anpio-cli`。

## 组成

| 目录 | 产物 | 角色 |
|---|---|---|
| `packages/core` | `@anpio-cli/core` | 协议原语：DID 组合、RFC 9421 签名与验签、密钥解析、CAIP-10 身份、JCS 规范化 |
| `packages/service` | `anpio-service`（`AnpioAgent`） | ANPMessageService：接收、存储、投递、取件，群组、附件与联邦 |
| `rust/` | `anpio-cli` | 命令行客户端：身份、登录、消息、群组与群端到端加密 |

`core` 不含传输与进程，`service` 建在它上面。客户端是**独立产物**：有自己的 store 根
（`$ANPIOCLI_HOME`，缺省 `~/.anpio-cli`），不读也不写服务端的数据库。

客户端用 Rust 写，是因为群 E2EE 需要 MLS，而官方 MLS 实现只在 Rust crate `anp` 里
（[client-mls.md](docs/design/client-mls.md) §2）。它**依赖** crates.io 的 `anp`，不是把本仓库
发布成 `anp`；crates.io 上另有一个同名的 `anpio-cli`，与本仓库不是同一份代码。

## 两处服务

ANP 里有两个可以被"自己搭一个"的服务，本仓库做的是第二个：

- **DID Service** —— 托管 `did.json`、发号（handle）。独立部署，不属于本仓库。
  `anpio-cli` 是它的**客户端**（`did create` / `did register` / `did publish` /
  `did resolve` / `did update`）。
- **ANPMessageService** —— 接收并投递 agent 之间的消息。**`AnpioAgent` 就是它。**

两者分开部署，分工是清楚的：DID Service 只管身份，本服务承载消息。所以 `AnpioAgent`
**不托管别人的 DID 文档**，只在需要时**解析**对方的文档，从中取唯一的 `ANPMessageService`
条目来找到入口服务。**一处例外**：本服务**自己名下**的群 DID 文档由本服务发布——群文档是
消息层的产物（这个群住在哪台 Host 上、名册与事件序在哪儿），交给别人托管等于让别的服务器
替我们签一份关于我们的声明（[groups.md](docs/design/groups.md) §2）。

## 快速开始

需要 Node.js ≥ 24.16 与 Rust ≥ 1.88。

```bash
npm ci
npm run build

# 起一个消息服务；配置全部走环境变量，没有命令行旗标
ANPIOCLI_LISTEN=127.0.0.1:8787 node packages/service/dist/main.js
```

另开一个终端，用一个**不需要身份**的方法确认它在说 ANP（`anp.get_capabilities` 是 P1 §8.2
唯一免认证的方法）：

```bash
cargo run --manifest-path rust/Cargo.toml -- discover http://127.0.0.1:8787
```

完整的本机链路——玩具 DID 主机、真 `packages/service`、真 `anpio-cli` 二进制——由 e2e 脚本
一次跑完。它覆盖身份、消息与通讯录、群、P6、登录挑战与换钥：

```bash
./scripts/e2e.sh              # 先构建再跑
./scripts/e2e.sh --no-build   # 用现成产物
```

要接自己的 DID 主机，先建身份，再收发：

```bash
cargo build --manifest-path rust/Cargo.toml
rust/target/debug/anpio-cli did create --host http://127.0.0.1:8765 --handle alice
rust/target/debug/anpio-cli msg send --to did:wba:... --text "hello"
rust/target/debug/anpio-cli msg inbox
```

`msg send` 返回成功表示消息**已进入对方入口服务的处理边界**，不表示对方已读。`msg inbox`
读的是**本机**记录，不是服务端；要联网把服务端还留着的消息搬下来，用 `msg fetch`。

`anpio-cli` 是二进制，不是 npm 包。**不要 `cargo install anpio-cli`**（crates.io 上那个是
别的项目）；要从源码装就 `cargo install --path rust/crates/anpio-cli`。

### 私钥可以放在 `anpio-key` 里

默认由 `did create` 把私钥写进 store。另一条路是交给本地
[`anpio-key`](https://github.com/open-agentx/anpio-key) 守护进程：`did attach-anpio-key` 之后，
身份文件里**一个私钥字节都没有**，每次签名由 CLI 通过 socket 请它签。受保护入口还能代签
origin proof，并在 `--device` 指定设备名时用 `SIGN_PURPOSE(device_assertion)` 签群 E2EE 的
设备断言。细节与拒绝边界见 [rust/README.md](rust/README.md#私钥放在-anpio-key-里did-attach-anpio-key)
和 [anpio-key-integration.md](docs/design/anpio-key-integration.md)。

## 文档

- **使用者文档**（中文在 `/`，英文在 `/en/`）：**https://anpio-cli.vercel.app**
  源文件在 [`vercel/`](vercel/)，是一个自包含的 VitePress 站点；Vercel 项目的 Root Directory
  指向 `vercel/`。本地预览与构建：

  ```bash
  npm run docs:dev
  npm run docs:build
  ```

- **实现者文档**：[`docs/design/`](docs/design/)。逐条引规范行号，记录取舍与偏离，以及哪些
  规范条款本实现故意不覆盖。改代码前先读对应的那一篇，索引见 [docs/index.md](docs/index.md)。
- **还剩什么**：[`TODO.md`](TODO.md)。只记**仍然开着**的事——做完的划掉，不复述。

## 开发与门禁

`.github/workflows/ci.yml` 在每次 push 到 `main` 和每个 PR 上跑三个独立 job：

| job | 跑什么 |
|---|---|
| `check` | `npm ci` → `npm run build` → `npm run typecheck` → `npm test` |
| `rust` | `cargo test --all-targets`，然后 `cargo clippy --all-targets -- -D warnings` |
| `e2e` | `./scripts/e2e.sh`：真服务、真 DID 主机、真 socket、真 WebSocket |

本地跑同一套：

```bash
npm ci && npm run build && npm run typecheck && npm test
cargo test --manifest-path rust/Cargo.toml --all-targets
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
./scripts/e2e.sh
```

**`npm run build` 不能省。** 每个包的测试按包名 import `@anpio-cli/core`，而那个名字解析到
`packages/core/dist`——空检出直接跑 `npm test` 会红得像测试坏了，其实是缺构建。

## 规范版本

引用行号以 ANP **已发布的 v1.2** 为准。一处例外需要记住：**P6（群组端到端加密）仍是候选**，
它的 `anp.group.e2ee.v2` 卡在"注册一个稳定的 MLS `ExtensionType` code point"这道发布门槛
上——所以本实现照做 P6 的方法，但**不**把它声明为稳定 Profile。P6 的命令仍然可用，
`anp.get_capabilities` 只是扣留那一条广告（见 [TODO.md](TODO.md) §3.1）。

## 许可

MIT。
