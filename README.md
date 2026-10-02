# ANPMessageService

ANP（Agent Network Protocol）消息层的**客户端 + 服务端**实现：一个命令行客户端
`connectx`，一个可自建的消息服务 `AgentXAgent`。

## 三块 + 一个测试包

| 包 | 产物 | 角色 |
|---|---|---|
| `packages/core` | `@agentx/core` | 协议原语：DID 组合、RFC 9421 签名与验签、密钥解析、CAIP-10 身份、JCS 规范化 |
| `packages/cli` | `connectx` | 命令行客户端：身份、登录、收发消息 |
| `packages/service` | `agentx` | ANPMessageService：接收、存储、推送、取件，群组与附件 |

`core` 不含传输与进程，`cli` 与 `service` 都建在它上面。

`packages/e2e` 是第四个包，只装测试：它把 `connectx` 的命令函数对着一个真跑起来的
`AgentXAgent` 跑，中间是真 HTTP、真签名、真 WebSocket。它**不产出任何东西**，只
回答一个别处回答不了的问题——这两块拼起来还成立吗。`npm run test:e2e`。

## 两处服务

ANP 里有两个可以被"自己搭一个"的服务，本仓库做的是第二个：

- **DID Service** —— 托管 `did.json`、发号（handle）。独立部署，不属于本仓库。
  `connectx` 是它的**客户端**（`did register` / `did resolve` / `did update`）。
- **ANPMessageService** —— 接收并投递 agent 之间的消息。**`AgentXAgent` 就是它。**

两者分开部署：`AgentXAgent` **不托管 DID 文档**，只在需要时**解析**对方的 DID 文档，
从中取唯一的 `ANPMessageService` 条目来找到入口服务。

## 快速开始

```bash
npm install
npm run build

# 起一个消息服务（全部配置走环境变量，没有命令行旗标）
AGENTX_LISTEN=127.0.0.1:8787 node packages/service/dist/main.js

# 另开一个终端：备一个身份，发一条消息，再取回来
npx connectx did create
npx connectx msg send --to did:wba:... --text "hello"
npx connectx msg inbox
```

`msg send` 返回成功表示**已进入对方入口服务的处理边界**，不表示对方已读。

## 文档

面向使用者的技术文档（中文在 `/`，英文在 `/en/`）在 [`vercel/`](vercel/)：

```bash
npm run docs:dev      # 本地预览
npm run docs:build    # 构建静态站点
```

这个目录是一个自包含的 VitePress 站点，在 Vercel 上把项目 Root Directory 指向 `vercel/`
即可部署。

## 开发设计文档

[`docs/design/`](docs/design/) 是**实现者**看的文档：逐条引规范行号，记录取舍与偏离，
以及哪些规范条款本实现故意不覆盖。改代码前先读对应的那一篇。

## 门禁

`.github/workflows/ci.yml` 在每次 push 与 PR 上跑四步：`npm ci` → `npm run build` →
`npm run typecheck` → `npm test`。本地跑同一套：

```bash
npm run build && npm run typecheck && npm test
```

**`build` 不能省。** 每个包的测试按包名 import `@agentx/core`，而那个名字解析到
`packages/core/dist`——空检出直接跑 `npm test` 会红得像测试坏了，其实是缺构建。

## 规范版本

引用行号以 ANP **已发布的 v1.2** 为准。一处例外需要记住：**P6（群组端到端加密）仍是
候选**，它的 `anp.group.e2ee.v2` 卡在"注册一个稳定的 MLS `ExtensionType` code point"
这道发布门槛上——所以本实现照做 P6 的方法，但**不**把它声明为稳定 Profile。
