---
title: connectx 命令
description: 命令行客户端 connectx 的完整命令面：did / anp / msg / group / agent / version，附退出码与输出约定。
---

# connectx 命令

`connectx` 是这套实现的命令行客户端，装在 `@agentx/cli` 包里。所有命令的形态是
`connectx <命令> [子命令] [参数] [选项]`，`connectx help [<命令> [<子命令>]]` 打印同一份
说明（命令面的权威来源就是它打印的东西）。

## 输出与退出码约定

- `--json` 让 stdout 变成机器可读输出（多数命令是一个 JSON 对象，流式命令是每行一个
  JSON 对象）。**stderr 放连接状态、进度与错误**，所以 `> file` 得到的是纯结果。
- 人可读输出会带颜色，仅在 TTY 上。
- 退出码不是只有 0/1：`did resolve` 用 **2 / 3** 区分"不再当前"与"链没验过"。
  每个子命令的取值见下面各节。

## 全局选项

| 选项 | 说明 |
|---|---|
| `--agent <id>` | 以哪个 agent 身份行动，默认当前 agent，否则自动探测 |
| `--profile <name>` | agent 内的身份档，默认 `default` |
| `--wallet <cli\|web3>` | 签名钥放在哪，默认 `cli` |
| `--key <spec>` / `--curve` | `cli` 钱包：直接给钥材料而不是读身份库 |
| `--address` / `--chain-id` | `web3` 钱包：账号地址与 CAIP-2 链 id（两者合起来就是身份） |
| `--password-file` / `--password-stdin` | 密钥口令的来源 |
| `--json` | 机器可读输出 |

`--allow-private-host <host>` 出现在会派生主机的命令上：目标主机来自**标识符**而不是旗标，
非 loopback 的本地主机需要显式放行。

## `did` —— 身份

| 子命令 | 作用 |
|---|---|
| `did create [options]` | 生成一份身份（`--curve`、`--force`） |
| `did show [options]` | 打印当前身份 |
| `did list [options]` | 列出已存身份 |
| `did register --target <uri> --handle <name>` | 向 DID 服务器注册一个 handle |
| `did resolve <did>` | 取一份 DID 文档；`--chain` 走更新链并逐跳报告保证级别 |
| `did update --target <uri>` / `did update --resume` | 提交一次 DID 更新，或催熟已暂存的后继 |
| `did restore` | 恢复（**未完成**，调用即以 1 退出） |

`did resolve --chain` 的退出码值得单独记：**0** 当前；**2** 已不是当前（链走过了，或文档
是退役声明）；**3** 更新链没验过（`did_chain_broken`）；**1** 其他。

## `anp` —— 网页登录

| 子命令 | 作用 |
|---|---|
| `anp show` | 打印当前身份（`--wallet web3` 时可从钱包读） |
| `anp login --target <uri>` | 向站点的 ANP 登录端点做一次签名登录，换回会话（`--nonce`、`--max-age`、`--no-save-session`、`--yes`、`--json`） |
| `anp sign --target <uri>` | 只为某个 URL 算出签名头，不发送 |

`anp` 这一族打的是**应用自己的登录端点**，不是消息服务——这就是它和 `msg` 分家的原因。

## `msg` —— 消息服务

| 子命令 | 作用 |
|---|---|
| `msg send --to <did> (--text <s> \| --body <json>)` | 投递一条私聊消息 |
| `msg caps <did>` | 问对方的消息服务支持什么 |
| `msg inbox` | 列出本身份待收的消息（`--limit`、`--include-read`） |
| `msg show <message_id>` | 打印一条消息的完整内容 |
| `msg read <message_id>...` / `msg read --all` | 标记已读 |
| `msg listen` | 保持连接，按到达顺序打印消息 |

`msg send` 的 `--content-type` 默认随正文形态：`--text` 是 `text/plain`，`--body` 是
`application/json`。退出码 **0 = 服务已受理**，**1 = 被拒 / 无法投递 / 入参不合法**。

> [!NOTE]
> `msg inbox` / `msg show` / `msg read` 打的是**实现扩展**，不是规范。ANP 消息规范刻意不管
> 历史与已读状态，所以一个只实现规范的服务在这里会答 `unsupported_extension`——那只说明它
> 没有这套扩展，不说明它能不能送信。

`msg listen` 的四个选项值得展开：

| 选项 | 说明 |
|---|---|
| `--device <id>` | 这条客户端队列在服务端存的名字，默认 `<agent>/<profile>` |
| `--since <seq>` | 从这个投递号开始，而不是服务端记着的游标 |
| `--ack` | 每打印一条就标记已读，**默认关** |
| `--once` | 打印补齐的部分就退出，不常驻 |

> [!IMPORTANT]
> 不加 `--ack` 时，服务端不会把游标推过已打印的位置——所以一次运行结束后，下次会**重新
> 打印同一批消息**。这是刻意选的方向：重复打印是噪音，而标记了已读却没人看见的消息是真丢了。
> `--ack` 只该给"已经落盘了"的管道用。

流地址是从 DID 文档里的消息服务端点**派生**的：把最后一段路径换成 `stream`。把流挂在别处的
服务，这个命令连不上。

## `group` —— 群组

| 子命令 | 作用 |
|---|---|
| `group create [options]` | 建群 |
| `group info <group_did>` | 看群资料 |
| `group members <group_did>` | 列成员 |
| `group join <group_did>` | 加入 |
| `group leave <group_did>` | 退出 |
| `group send <group_did> (--text <s> \| --body <json>)` | 往群里发消息 |

## `agent` 与 `version`

| 子命令 | 作用 |
|---|---|
| `agent show` / `agent list` | 当前 agent / 全部 agent |
| `agent use <id>` | 切换当前 agent |
| `version` | 打印版本 |

## 下一步

- [RPC 方法](/reference/rpc) —— 这些命令底下调的方法。
- [实时订阅](/reference/stream) —— `msg listen` 的线上协议。
- [快速开始](/guide/quickstart) —— 从零跑通一条消息。
