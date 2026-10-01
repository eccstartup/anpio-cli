# ANPMessageService

面向 ANP（Agent Network Protocol）消息层的**客户端 + 服务端**实现仓库。

本仓库从 `anp-sdk`（旧仓库，包名 `@connectx-sdk/core`）中把 CLI 剥离出来，
只做与 ANP 协议相关的部分，并新增一个 ANP 消息服务实现。

**本仓库不依赖 `anp-sdk`**：所需协议原语以裁剪后的 `packages/core` 形式落在仓内。

## 三块

| 包 | 名字 | 角色 | 对应规范 |
|---|---|---|---|
| `packages/core` | `@agentx/core` | 协议原语：DID 组合、RFC 9421 签名与验签、密钥解析、CAIP-10 身份、JCS 规范化 | ANP-02 / ANP-03 / CAIP-10 提案 |
| `packages/cli` | `connectx` | 命令行客户端：身份 / 登录 / 收发消息 | 同上 + ANP-09 消息 Profile |
| `packages/service` | `AgentXAgent` | ANPMessageService：收、存、推、取 | ANP-09 P1–P9 |

设计与旧仓库的分工：

```
anp-sdk (旧)                       ANPMessageService (本仓库)
  src/core  ──── 裁剪 ────►          packages/core
  packages/cli ── 剥离 ───►          packages/cli      (去掉 project / zk)
                                     packages/service  (全新)
```

## 两处服务

ANP 里有两个可以被"自己搭一个"的服务，本仓库只做第二个：

- **DID Service** —— 托管 `did.json`、发号（handle）。由兄弟仓库 `awiki-open-server` 承担。
  `connectx` 只是它的**客户端**（`did register` / `did resolve` / `did update`）。
- **ANPMessageService** —— 接收并投递 agent 之间的消息。**本仓库的 `AgentXAgent` 就是它。**

两者是独立部署，`AgentXAgent` **不托管 DID 文档**，只在需要时**解析**对方的 DID 文档
来找入口服务。

## 阅读顺序

1. [docs/design/cli.md](docs/design/cli.md) —— `connectx` 命令面、CAIP-10 接入、与 SDK 的边界
2. [docs/design/message-service.md](docs/design/message-service.md) —— `AgentXAgent` 架构、方法面、存储、联邦
3. [docs/design/realtime.md](docs/design/realtime.md) —— 接收侧：订阅流、游标、无空洞无重复
4. [docs/design/vendored-core.md](docs/design/vendored-core.md) —— `packages/core` 保留/删除/新增清单，以及 CAIP-10 留的口子
5. [TODO1.md](TODO1.md) —— 活动台账（只记还剩什么）

## 规范出处

引用行号以本机 checkout 为准（已核对到 `v1.2` 标签）：

| 简称 | 路径 | 版本 |
|---|---|---|
| ANP-02 / ANP-03 / ANP-04 | `code/claude/AgentNetworkProtocol/chinese/` | **已发布 v1.2** |
| ANP-09 P1–P9 | `code/claude/AgentNetworkProtocol/chinese/message/` | **已发布 v1.2 目录**；P6 仍为候选 |
| CAIP-10 提案 | `code/claude/AgentNetworkProtocol/proposals/anp-caip10-identity-proposal.md` | Proposal（未发布） |

**ANP 1.2 已经发布**，所以这两条都读**正式路径**：ANP-02/03/04 在 `chinese/` 根下，
消息九篇在 `chinese/message/`。仓库里还留着 `chinese/vnext/`（以及
`chinese/message/vnext/`），那是**下一轮修订的起点**、1.2 发布前的草案快照，不是引用对象
——同一份 ANP-02 在 `vnext/` 里行号会整体差一行（文件头的状态块不同），照它引就会指出
错误的位置。`main` 与 `v1.2` 在 `chinese/message/` 上目前没有正文差异，所以行号两边通用。

一处**未发布**的东西要在阅读时记住：ANP-09 的 **P6（群组端到端加密）仍是候选**，
它的 `anp.group.e2ee.v2` 卡在"注册一个稳定的 MLS `ExtensionType` code point"这道发布
门槛上（规范仓库 README 的发布清单里该项未打勾）。C13 依赖 P6，因此 C13 落地前要再看
一眼这个门槛是否已经跨过。CAIP-10 提案同理——它是提案，不是已发布规范。
