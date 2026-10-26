# CLI 设计

> **本仓库的 CLI 是 `anpio-cli`** —— Rust 客户端，源码在 `rust/crates/anpio-cli/`（库
> `anpio_cli`、bin `anpio-cli`）。**命令面的权威是 `--help`**，现状与逐族的旗标在
> [`rust/README.md`](../../rust/README.md)。本文只写**为什么**：
> 那条薄壳判据、它与服务端的分工、以及退出码契约。

## 1. 已经不在这里的那个客户端

本仓库曾经有一个 TypeScript 客户端（`packages/cli`，二进制名 `connectx`，2026-10-02 起冻结）。
**2026-10-03 用户裁定退役，连同源码一起删掉了**，理由是两件具体的事：

1. **它没有剩下的用处了。** 它唯一还在调的服务端扩展面是 `inbox.get` / `inbox.mark_read` /
   `message.get_batch`，而读搬到本地之后（[client-messages.md](client-messages.md) §8）这三条
   在 Rust 侧已经没有调用者，服务端那三条 spec 也随之下线（[message-service.md](message-service.md) §9）。
   `sync.delta` 是 `x_anpiocli.inbox.v1` 里唯一还有客户端的成员，而它由 `msg fetch` 与
   `msg listen` 走。
2. **两份客户端意味着签名、规范化、DID 解析各存在两遍。** 服务端与协议库是 TypeScript、
   客户端是 Rust，这本身是有意的取舍；再叠一份同语言的客户端只是把同一份协议实现再写一遍，
   而两份之间没有一份能说"另一份错了"。

`packages/e2e`（一个只为把 `connectx` 的命令函数对着真服务跑而存在的测试包）随之删除——
它的客户端那一半就是被退役的那个客户端，而它唯一的独有覆盖（跨域中继的 `groupFederation`）
记在 [TODO7.md](../../TODO7.md) §5 里当待办，没有随代码一起消失。

**这份裁定覆盖了 TODO5 §0.1 第 4 条与 TODO6 §5 的"保留 / 继续维护"**，那是 2026-10-01/02 的
口径，前提是"TS 客户端与 Rust 客户端并存"；并存的前提没了，那两条就没有落点。

## 2. 定位

**薄壳。** CLI 只做三件事：解析参数、调用协议原语、按人 / 机器两种读者呈现结果。协议逻辑
一行都不在 CLI 里——`rust/README.md` 说这件事是**物理的**：带持续状态的东西（身份库、MLS
store、消息库）都在库里，命令面只是它们的调用者。

判据沿用旧仓库，本仓库对两个客户端都成立：

> 判据不是"这个能力有没有用"，而是"**有没有一条 CLI 路径会消费它**"。
> 实时 / 长连接 / 持续状态的能力留 SDK 或 agent 运行时，不进命令面。

由此推出的硬约束：

1. **命令面宁少勿多**：无头可脚本化 + 任务级 + 对 agent 有价值，三条全中才开一个命令；
   没有第二种形态的动作不单开子命令。
2. **推送只走 `msg listen` 一条路**。它是 CLI 里**唯一**的常驻进程，契约（输出 / 退出码 /
   信号 / `--once`）单独在 [realtime.md](realtime.md) 里定死。其余命令一律是"一次调用、
   一个结果"。
3. **签名是 ANP 方法唯一的证明方式；bearer token 只喂给主机自己的控制面**。
   `msg` / `group` / `contacts` 一族每次照样签 `origin_proof`；而 **DID host 自己的方法**
   （`update_document`、`get_me` / `update_me`）不收签名，只收 `register` / `login` / `create`
   发下来的 bearer token——所以那个缓存是**要读回的**，读它的正是 `did publish` 与 `me`。
   仍然没有 `logout`：一条命令要么当场用一个 token，要么重新签发一个，"清掉缓存"这个动作
   没有位置。

## 3. 两处服务，两个客户端身份

ANP 里有两个可以被"自己搭一个"的服务，`anpio-cli` 对两者都是客户端，但**分工是清楚的**：

- **DID Service** —— 托管 `did.json`、发号（handle）。`did create` / `did register` /
  `did resolve` / `did update` 打的是它。独立部署，不属于本仓库。
- **ANPMessageService** —— 承载 agent 之间的消息。`msg` / `group` / `contacts` 一族打的是它
  （发现流程：解析对方 DID 文档 → 取**唯一**那条 `ANPMessageService` 条目 → POST）。

**服务端不托管别人的 DID 文档**（服务自己的身份文档由 DID Service 托管——那是身份层的产物），
只在需要时**解析**对方的文档。一处例外：本服务**自己名下**的群 DID 文档由本服务发布
（`<serviceDid>:g:<id>`），因为群文档是**消息层**的产物，交给别人托管等于让别的服务器替我们
签一份关于我们的声明（[groups.md](groups.md) §2）。

## 4. 退出码与失败

**退出码。** 0 成功、1 失败，只有 `did resolve` 例外——它按**答案**而不是按成败给码：
**2** 这份文档已不是当前（链走过了，或是退役声明），**3** 更新链没验过，**0** 当前；
取不到文档是普通失败，给 1。

**失败长什么样。** stderr 上一行 `Error: <稳定码>: <人话>`，退出 1。稳定码（`message_invalid` /
`message_send_failed` / `unsupported_extension` / `did_resolve_blocked` /
`message_service_not_found` …）是给脚本分支用的，人话是给人看的——**两句话要能分开**，
脚本才分得出"该换个对端"和"这次没成"。逐族的失败话术在
[`rust/README.md`](../../rust/README.md)。

`--json` 只改 stdout：状态、进度与错误**始终**走 stderr，所以 `> file` 拿到的是纯结果。

## 5. 扩展面：规范没有定义的那一半

`msg fetch` / `msg listen` 走的是 `x_anpiocli.inbox.v1`，`contacts` 走
`x_anpiocli.contacts.v1`，群备注走 `x_anpiocli.group_remarks.v1`——**规范里都没有**。
`x_` 前缀是 P1 §12 给扩展留的命名空间，取值不是任何一个规范 Profile（那才是对客户端撒谎：
P1 §6.2.2 L277 说 `profile` 是"唯一解释"）。

**仅实现规范的对端回 `-32601` 是正确答案，不是缺陷。** 客户端把它报成
`unsupported_extension` 并退出 1，与"对端拒绝了"（`message_send_failed`）分开。
逐条的形状与理由在 [message-service.md](message-service.md) §9。

## 6. 与协议库的边界

**CLI 不得自己拼 JSON-RPC 信封，也不得自己做 JCS 规范化。** 这两件事一旦出现第二份，
`msg send` 与服务端的验签就会以最难查的方式不一致（[client-mls.md](client-mls.md) 记录过一次
同形的取舍）。

Rust 客户端这边，这条边界落成一个具体的机器：**它只调 `anp` crate 的公开面**。客户端做群
E2EE 需要 MLS，而官方的 MLS 实现只在 Rust crate 里——这正是客户端写成 Rust 的理由
（[client-mls.md](client-mls.md) §2）。协议与状态在库 `anpio_cli`，`main.rs` 只是命令面。

## 7. 私钥的两种归属

私钥要么由 `did create` 写进 store，要么由 [`anpio-key`](https://github.com/open-agentx/anpio-key)
守护进程持有（`did attach-anpio-key`）。第二种下，身份文件里没有私钥字节，签名通过 socket 委托。

**能委托的只有"签整条 HTTP 请求"这一件事。** `anpio-key` 的合同是"给我 method / URL / body，
我把 RFC 9421 头还给你"，私钥不出守护进程，默认构建里也没有签任意字节的命令。所以：

- **能跑**：`anp sign` / `anp login`（ANP-02 请求）、`did register` / `did publish`（用守护进程
  发布的文档走主机的控制面）、`did show` / `anp show`。
- **当场拒**：`msg` / `group`（origin proof 与 MLS 设备钥都是 CLI 自己拼的字节）、`did update`
  （退役文档要由 key-1 签，而后继钥还是 CLI mint 的）。拒绝发生在动手之前，并把这条身份能做
  什么写在错误里。

这不是待办清单上的一条：要么守护进程长出一条"签任意字节"的接口（那等于放弃它存在的理由），
要么这三处继续由本地钥完成。
