# anpio-cli

ANP（Agent Network Protocol）消息层的实现：一个可自建的消息服务 `AnpioAgent`，以及它
依赖的协议原语库。

## 两块

| 包 | 产物 | 角色 |
|---|---|---|
| `packages/core` | `@anpio-cli/core` | 协议原语：DID 组合、RFC 9421 签名与验签、密钥解析、CAIP-10 身份、JCS 规范化 |
| `packages/service` | `anpio-service` | ANPMessageService：接收、存储、推送、取件，群组与附件 |

`core` 不含传输与进程，`service` 建在它上面。

**客户端不在这里。** 命令行客户端是 Rust 的 `anpio-cli`，住在 [`rust/`](rust/)，
以 [`anp`](https://crates.io/crates/anp) crate 发布。本仓库曾经有一个 TypeScript 的客户端
（`packages/cli`，二进制名 `connectx`），2026-10-03 用户裁定**退役**：读搬到本地、服务端那三条
读方法随之摘掉之后，它没有剩下的用处，而且两份客户端意味着签名、规范化、DID 解析各存在两遍。
它连同只为驱动它而存在的测试包 `packages/e2e` 一起删掉了。

## 两处服务

ANP 里有两个可以被"自己搭一个"的服务，本仓库做的是第二个：

- **DID Service** —— 托管 `did.json`、发号（handle）。独立部署，不属于本仓库。
  `anpio-cli` 是它的**客户端**（`did register` / `did resolve` / `did update`）。
- **ANPMessageService** —— 接收并投递 agent 之间的消息。**`AnpioAgent` 就是它。**

两者分开部署，**分工是清楚的：DID Service 只管身份，本服务承载社交应用**（2026-10-02 的
口径，[TODO4.md](TODO4.md) §C）。所以 `AnpioAgent` **不托管别人的 DID 文档**（服务自己的
身份文档由 DID Service 托管——那是身份层的产物），只在需要时**解析**对方的 DID 文档，从中取
唯一的 `ANPMessageService` 条目来找到入口服务。**一处例外**：本服务**自己名下**的群 DID 文档
由本服务发布——群文档是**消息层**的产物（这个群住在哪台 Host 上、名册与事件序在哪儿），群 DID
就住在它的命名空间里（`<serviceDid>:g:<id>`），交给别人托管等于让别的服务器替我们签一份关于
我们的声明（[groups.md](docs/design/groups.md) §2、[TODO3.md](TODO3.md) §0）。

## 快速开始

```bash
npm install
npm run build

# 起一个消息服务（全部配置走环境变量，没有命令行旗标）
ANPIOCLI_LISTEN=127.0.0.1:8787 node packages/service/dist/main.js

# 另开一个终端：备一个身份，发一条消息，再取回来（客户端在 rust/ 下）
cargo run -p anpio-cli -- did create
cargo run -p anpio-cli -- msg send --to did:wba:... --text "hello"
cargo run -p anpio-cli -- msg inbox
```

`msg send` 返回成功表示**已进入对方入口服务的处理边界**，不表示对方已读。

## 文档

面向使用者的技术文档（中文在 `/`，英文在 `/en/`）在
**https://agentx-docs.vercel.app**，源文件在 [`vercel/`](vercel/)：

```bash
npm run docs:dev      # 本地预览
npm run docs:build    # 构建静态站点
```

这个目录是一个自包含的 VitePress 站点，部署在 Vercel 上，项目的 Root Directory 指向
`vercel/`。`anpio-cli --help` 每条 `See:` 行指的就是这个站。

## 开发设计文档

[`docs/design/`](docs/design/) 是**实现者**看的文档：逐条引规范行号，记录取舍与偏离，
以及哪些规范条款本实现故意不覆盖。改代码前先读对应的那一篇。

## 门禁

`.github/workflows/ci.yml` 在每次 push 与 PR 上跑四步：`npm ci` → `npm run build` →
`npm run typecheck` → `npm test`。本地跑同一套：

```bash
npm run build && npm run typecheck && npm test
```

**`build` 不能省。** 每个包的测试按包名 import `@anpio-cli/core`，而那个名字解析到
`packages/core/dist`——空检出直接跑 `npm test` 会红得像测试坏了，其实是缺构建。

## 规范版本

引用行号以 ANP **已发布的 v1.2** 为准。一处例外需要记住：**P6（群组端到端加密）仍是
候选**，它的 `anp.group.e2ee.v2` 卡在"注册一个稳定的 MLS `ExtensionType` code point"
这道发布门槛上——所以本实现照做 P6 的方法，但**不**把它声明为稳定 Profile。
