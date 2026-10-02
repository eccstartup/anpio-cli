---
title: agentx-cli 命令
description: 命令行客户端 agentx-cli 的完整命令面：discover / did / agent / msg / group / anp / contacts / me / version，附退出码与输出约定。
---

# agentx-cli 命令

`agentx-cli` 是本仓库的命令行客户端，Rust 写的，源码在 `rust/crates/agentx-cli/`。
所有命令的形态是 `agentx-cli <命令> [子命令] [参数] [选项]`，
`agentx-cli help [<命令> [<子命令>]]` 打印同一份说明（命令面的权威来源就是它打印的东西）。

> [!NOTE]
> **`connectx` 已冻结。** `packages/cli` 的那个 TypeScript 客户端（`@agentx/cli` 包）不再加功能，
> 也不再是文档入口——本页描述的是 `agentx-cli`。站上其余指南里的例子大多仍是 `connectx` 的写法，
> 正在迁移；两者的**协议语义相同**，命令名与旗标有出入，以本页与 `--help` 为准。

## 安装与 store

`agentx-cli` 是二进制，不是 npm 包。从源码构建：

```bash
cargo build --release --manifest-path rust/Cargo.toml
# 产物：rust/target/release/agentx-cli
```

它有自己的 store 根（`$AGENTXCLI_HOME`，缺省 `~/.agentx-cli`），
**不碰 `connectx` 的 `~/.connectx/`**：两条 CLI 并存时互不干扰。
一条身份由 `--agent` + `--profile` 命名，落在 `<store 根>/<agent>/<profile>/` 下
（`identity.json`、`session.json`）。

## 输出与退出码约定

- `--json` 让 stdout 变成机器可读输出（多数命令是一个 JSON 对象，`msg listen` 是每行一个
  JSON 对象）。**stderr 放连接状态、进度与错误**，所以 `> file` 得到的是纯结果。
- 退出码不是只有 0/1：`did resolve` 用 **2 / 3** 区分"已不是当前"与"更新链没验过"。
  其余命令要么 0 要么 1。用错命令面（例如少给一个必填的位置参数）是 clap 的用法错误，**退出 2**。
- 失败长这样：stderr 上一行 `Error: <稳定码>: <人话>`。稳定码与 TS 客户端的
  `ConnectxError.code` 是**同一套拼写**（`message_invalid` / `message_send_failed` /
  `unsupported_extension` / `did_resolve_blocked` …），脚本按它分支，不必解析人话。

## 全局选项

| 选项 | 说明 |
|---|---|
| `--agent <id>` | 以哪个 agent 身份行动；缺省依次看 `$AGENTXCLI_AGENT`、当前 agent（`agent use` 选的）、`default` |
| `--profile <name>` | agent 内的身份档；缺省看 `$AGENTXCLI_PROFILE`，再缺省 `default` |
| `--allow-private-host <host>` | 把一个**不以 loopback 拼法出现**的本地主机当成"本机"。放行之后同时允许私网地址与明文 `http` |
| `--json` | 机器可读输出 |

`--allow-private-host` 出现在会派生主机的命令上：目标主机来自**标识符**而不是旗标，
`localhost` / `127.0.0.1` / `::1` 已经算本机、不需要它，它管的是"是本机但没这么拼"（LAN 地址、
往里解析的名字）。

**`did create` 是唯一不走身份选择链的**：它造的是**新的**身份，"谁当前被选中"不该决定第二份
身份写在哪，所以缺省用 `--handle`。

## `did` 与 `agent` —— 身份

| 子命令 | 作用 |
|---|---|
| `did create --host <url> --handle <name>` | 生成一份身份，并把 DID 文档发布到 DID 主机（`--agent` 缺省=handle） |
| `did show` | 打印本机存着的这份身份 |
| `did list` | 这台机器持有的全部身份，以及各自绑到了什么 |
| `did register` | 把 DID 文档（重新）发布给它自己的主机，取回 bearer token |
| `did publish` | 文档改过之后重签并重新发布——走主机的 `update_document`，不是 ANP 签名路 |
| `did update --target <uri>` / `did update --resume` | 提交一次 DID 更新，或催熟已暂存的后继（ANP-03 §2.5.3） |
| `did resolve <did>` | 取一份 DID 文档；`--chain` 走更新链并逐跳报告保证级别 |
| `did restore` | 恢复（**anp 没有这条路**，调用即以 1 退出并说明什么都没读、什么都没恢复） |
| `agent show` / `agent use <id>` / `agent list` | 当前 agent / 切换 / 全部 agent |

`did resolve --chain` 的退出码值得单独记：**0** 当前；**2** 已不是当前（链走过了，或文档
是退役声明）；**3** 更新链没验过（`did_chain_broken`）；**1** 其他。

`did update` 会把后继钥在**任何字节出门之前**写进 `successor.json`：服务器接受之后、store 搬过去
之前，那个文件是 DID 已经搬过去的钥的**唯一**副本。所以投递结果不确定时它**留着**暂存钥并提示
`--resume`，而不是丢掉。

## `msg` —— 消息服务

| 子命令 | 作用 |
|---|---|
| `msg send --to <did\|name> (--text <s> \| --body <json>)` | 投递一条私聊消息 |
| `msg caps <did>` | 问对方的消息服务支持什么 |
| `msg inbox` | 列出本身份待收的消息（`--limit` 默认 20、`--include-read`） |
| `msg show <message_id>` | 打印一条消息的完整内容 |
| `msg read <message_id>...` / `msg read --all` | 标记已读 |
| `msg listen` | 保持连接，按到达顺序打印消息 |

`msg send --to` 收 **DID 或通讯录里的名字**；两个名字指向同一人时**退出 1 并逐个列出候选**，
不随便挑一个。`--text` 与 `--body` **二选一**，`--content-type` 默认随正文形态
（`--text` 是 `text/plain`，`--body` 是 `application/json`）。

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
> `--ack` 只该给"已经落盘了"的管道用。Ctrl-C 退出 **0**；掉线按 2s→30s 退避重连。

流地址是从 DID 文档里的消息服务端点**派生**的：把最后一段路径换成 `stream`。把流挂在别处的
服务，这个命令连不上。

> [!NOTE]
> `msg inbox` / `msg show` / `msg read` 打的是**实现扩展**（`x_agentx.inbox.v1`），不是规范。
> ANP 消息规范刻意不管历史与已读状态，所以一个只实现规范的服务在这里会答 `-32601`——
> 客户端把这句话**原样报成 `unsupported_extension` 并退出 1**，那**是正确答案**，不是缺陷：
> 它说明对端没有这套扩展，与"对端拒绝了"（`message_send_failed`）是两件事。
> `msg listen` 的握手同理。

## `contacts` —— 名字 ↔ DID

| 子命令 | 作用 |
|---|---|
| `contacts list` | 这份身份的全部联系人，按 subject 排序 |
| `contacts add <did>` | 把一个 DID 放进册子（`--remark <name>` 起名；缺席=保留原有备注，清空要 `--clear-remark`） |
| `contacts set-remark <name> <remark>` | 改名：同一行，新备注（`<name>` 收名字或 DID） |
| `contacts remove <name>` | 移出册子（名字或 DID） |
| `contacts resolve <name>` | 名字进、DID 出；`--json` 给整行（含 `subject`） |

册子不在本地文件里，在**消息服务的库**里（扩展 `x_agentx.contacts.v1`），按**请求的已验证
签名者**分行，所以一个身份的备注对另一个身份天然不可见。行按 **`subject`** 存、不按 `did`——
`did update` 会把 DID 挪走（它内嵌钥指纹），备注挂 `did` 上就会在换钥时静默消失。

`resolve` 是**给 agent 用的那条**：名字进、DID 出。DID 形状的参数**直接原样返回**
（不连网、不读 store）。`add` 收到非 DID 的输入会**在开身份之前**就拒——否则会落一行键是字面量、
永远发不出去也永远匹配不上任何 DID 的记录。

**收到一条私聊也会让发件人落一行**，但没有备注、且绝不碰已有的备注——一封来信对名字没有说
任何话。所以 `contacts list` 顺带就是"谁跟我说过话"。

## `group` —— 群组

| 子命令 | 作用 |
|---|---|
| `group create` | 建群（`--name`、`--policy <json>` 在 P4 §7.1 的推荐结构上浅合并） |
| `group info <group_did>` | 看群资料与策略 |
| `group members <group_did>` | 列成员（`--names` 额外去各自主机取对方给自己起的名字） |
| `group join` / `group leave <group_did>` | 加入 / 退出 |
| `group send <group_did> (--text <s> \| --body <json>)` | 往群里发消息 |
| `group update-profile <group_did> --name <name>` | 改**群自己的**名字（P4 §7.4） |
| `group set-remark <group_did> [<remark>]` | 起一个**只有我看得见**的群名，`--clear` 是取反 |

群的默认策略是 `open-join`；`--policy` 里的 `admission_mode` 只认 `admin-add` /
`open-join`，越界的值**在联网之前**就被拒。`group join` 一个非 `open-join` 的群，服务按 §8.3.2
回 `policyViolation`（3003）——"这个群不让自助加入"是群策略在说话。

**`update-profile --name` 与 `set-remark` 不是一件事**：前者写的是群**自己的**名字，存在群的
主机上、对所有人一样；后者起的是**只有我看得见**的那个，存在服务里另一张表（扩展
`x_agentx.group_remarks.v1`），`group info` 把它印在 `name:` 的下一行。`members` 里认得的成员
后面跟的是**你给他起的备注**（名字挂在 `subject` 上，对端换钥也不会丢）。

## `group e2ee` —— 群端到端加密

| 子命令 | 作用 |
|---|---|
| `group e2ee publish` | 发布本设备的 KeyPackage，让别人能把自己加进来 |
| `group e2ee get-key-package` | 取对端设备已发布的 KeyPackage（`--target-did`、`--target-device`） |
| `group e2ee create <group_did>` | 用本设备初始化群的 MLS 状态 |
| `group e2ee add` / `remove <group_did>` | 加 / 删一个设备的 leaf（`--member-did`、`--member-device`） |
| `group e2ee send <group_did> (--text \| --body)` | 加密一条消息并发给服务排序 |

这几条打的是 P6 `anp.group.e2ee.v2`。`create` / `add` / `remove` 共用那条三阶段
（prepare → 发送 → finalize 或 abort，§13.6）：服务拒绝就 abort，传输失败则留给 crate 的
`reconcile_pending_v2`——那时"服务到底收没收"是不知道的。`send` 是唯一**不是三阶段**的一条。
这四类控制方法都**不当作成功，除非**答复里有 `published: true` / `created: true` /
`accepted: true`。`group e2ee send --content-type` 是**加密内容**的类型，与 `msg send` 那个被
规范钉死的外层 `meta.content_type` 不是一回事。

## `anp` —— 应用层

| 子命令 | 作用 |
|---|---|
| `anp show` | 打印这份身份，`subject` 与当前 `did` 摊开成一对 |
| `anp sign --target <uri>` | 只为某个 URL 算出整条 ANP-02 请求（body + 签名头 + DID 文档），**一行都不发** |
| `anp login --target <uri>` | 签名、POST、拿回应用服务器发的凭据（`--nonce`、`--session-ttl`、`--no-save-session`、`--json`） |

`anp` 这一族打的是**应用自己的登录端点**，不是消息服务——这就是它和 `msg` 分家的原因。
`show` 与 `sign` 都**不连网**。

`anp login` 的 401 挑战只答一次，而且只在服务器点了**另一个** nonce 时才重签。**409
`did_superseded` 是一个结论**而不是一次被拒的证明：它不走"登录失败"那条路，客户端拿**自己的**
链说哪个 DID 才算数。token 从 `Authentication-Info` 或 body 里取，缓存进 `session.json`，
键是 **`host:port`**；写失败只警告不失败，因为 token 已经在手里了。

## `me` —— 主机给这份身份记的资料

| 子命令 | 作用 |
|---|---|
| `me show` | 主机为这份身份存的资料，外加它正在服务的那份文档 |
| `me set` | 改一个或多个字段：`--name` / `--bio` / `--avatar` / `--profile-url`（**至少给一个**） |

这一族**不是 ANP 协议**：协议里根本没有昵称这一类东西。资料落在**服务该 DID 的那台主机**上，
只有点过名的字段才发出去，所以改昵称不会顺手清掉头像。
它与 `did publish` 是缓存里那个 bearer token **仅有的**两个消费者。

## `discover` 与 `version`

| 子命令 | 作用 |
|---|---|
| `discover <endpoint>` | 问一个 ANP 消息服务它能做什么（`anp.get_capabilities`，P1 §8.2） |
| `version` | 打印版本（`--json` 给 `{"version": …}`），与 `--version` 是同一个事实 |

`anp.get_capabilities` 是唯一**不需要 auth** 的方法，所以 `discover` 不需要身份，也就成了最省的
"端点活着吗、说的是这个协议吗"检查。端点只给主机时自动补 `/anp-im/rpc`。

```bash
agentx-cli discover http://127.0.0.1:8787
```

## 下一步

- [RPC 方法](/reference/rpc) —— 这些命令底下调的方法。
- [实时订阅](/reference/stream) —— `msg listen` 的线上协议。
- [快速开始](/guide/quickstart) —— 从零跑通一条消息。
