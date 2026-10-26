# 设计文档索引

这里是**实现者**看的文档：逐条引 ANP 规范行号，记录取舍与偏离，以及哪些规范条款本实现
故意不覆盖。引用行号以**已发布的 ANP v1.2** 为准；P6（群组 E2EE）仍是候选，见
[README 的规范版本](https://github.com/eccstartup/anpio-cli#规范版本)。

面向**使用者**的文档不在这里，在 **https://anpio-cli.vercel.app**（源文件在 [`vercel/`](../vercel/)）。

## 服务端

| 文档 | 内容 |
|---|---|
| [message-service.md](design/message-service.md) | `AnpioAgent`：方法面、存储、取件流、通讯录与群备注、联邦 |
| [realtime.md](design/realtime.md) | 实时接收：订阅流、游标、无空洞无重复 |
| [groups.md](design/groups.md) | P4 群组：Group Host 语义、名册、策略与消息受理顺序 |
| [attachments.md](design/attachments.md) | P7 附件与对象：消息面送清单、控制面签票据、数据面搬字节 |
| [e2ee-direct.md](design/e2ee-direct.md) | P5 私聊端到端加密：服务端只是钥匙柜与邮箱 |
| [e2ee-group.md](design/e2ee-group.md) | P6 群组端到端加密：Host 排序、业主算 |
| [federation.md](design/federation.md) | P8 联邦与跨域：两层身份、一个 anchor、两条路 |
| [vendored-core.md](design/vendored-core.md) | `packages/core`：保留 / 删除 / 新增清单，以及 CAIP-10 留的口子 |

## 客户端

| 文档 | 内容 |
|---|---|
| [cli.md](design/cli.md) | 命令面的设计：薄壳判据、与服务端的分工、退出码契约、私钥归属 |
| [client-messages.md](design/client-messages.md) | 客户端 `messages.db`：写入路径、游标，以及本地读与 `msg fetch` 的界 |
| [client-mls.md](design/client-mls.md) | 客户端群 MLS：设备侧的密码学，以及还没做的 owner 编排 |
| [anpio-key-integration.md](design/anpio-key-integration.md) | 把私钥与签名交给本地 `anpio-key` 守护进程的分期计划、证明点与拒绝边界 |

## 台账

[`TODO.md`](../TODO.md) 只记**仍然开着**的事，按"卡在谁那儿"分栏：本仓库自己能做的、
等人裁定的、等上游或前置条件的。做完的条目删掉，历史留在 git 里。
