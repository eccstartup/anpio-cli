# TODO6 —— 文档、测试、通讯录

这份接 [`TODO5.md`](TODO5.md)（把 Rust 客户端从零写到六族 24 条 + `did publish` / `me`）。
范围由用户两次说过的话定：

> 我希望你把这个 phase 3 做完了之后，写一个 TODO6，把**文档的更新**，以及**软件的测试**也写进去。
> **至少我要能跑通吧。**（2026-10-02）

> 如果我想让 Agent 帮我给 Alice 发消息，他面对的都是 DID，也不知道哪个是 Alice，
> 所以他也不知道给谁发。这就是我为什么要添加个人用户的这个信息这些东西以及群聊的这些信息。
> **你把这些都要写到 todo 里。**（2026-10-02）

三块：**文档**（§2）、**测试**（§5）、以及**名字到 DID 的那一层**（§3、§4）——
第三块是这次新加进来的，它是"Agent 能不能替人发消息"的前置，不是可选装饰。

`~~划掉~~` / `- [x]` 表示做完或有结论。

---

## 1. 现状（2026-10-02 量出来的）

| 事实 | 量法 |
| --- | --- |
| Rust 单测 **132**，`cargo test` 全绿 | `cargo test --manifest-path rust/Cargo.toml` |
| **全是单测**：没有一个测试同时起动服务和客户端 | `rust/crates/agentx-cli/` 下没有 `tests/` |
| `cargo test` / `cargo clippy` **不在 CI 里** | `.github/workflows/ci.yml` 只有 `npm ci / build / typecheck / test` |
| `packages/e2e` 不覆盖新客户端 | `grep -rn "agentx-cli" packages/e2e/src` → 0 行 |
| 文档站不提 Rust 客户端 | `grep -n "Rust\|agentx-cli" vercel/reference/cli.md vercel/en/reference/cli.md` → 0 行 |
| `docs/design/cli.md` 描述的是 **TS 的 `connectx`** | 二进制名、`--curve`、`--wallet`、`~/.connectx/`——一条都不是 Rust 这边的 |
| `skill/connectx/SKILL.md` 同上 | 照 `connectx` 写 |
| `rust/README.md` 是唯一描述真客户的文档 | 但它是一份 README，不是参考页 |
| **没有通讯录**：任何"名字 → DID"的概念都不存在 | `grep -rni "contact\|remark\|nickname\|address_book" rust/crates/agentx-cli/src` → 只剩 `me` 那两处注释 |
| 群成员列表**没有名字字段** | `member_list` 每一项是 `{agent_did, role, status, joined_at}`（`docs/design/groups.md`） |
| 群自己的名字是 `group_profile.display_name`，而 CLI **没有写它的命令** | `GroupCommand` 只有 create / info / members / join / leave / send |

**两句话**：

1. 文档描述的是一个**冻结的**二进制，而在动的那个只有一份 README。
   "至少我要能跑通"今天卡住的地方不是跑不起来，是**没人能从文档里知道怎么跑**。
2. 定址单位是 DID，而人是按名字认人的。**这两者之间那一层，今天一个字节都没有**——
   所以 Agent 拿到"给 Alice 发消息"这句话时，没有任何东西告诉它 Alice 是哪个 DID。

---

## 2. 文档更新

### 2.1 先裁定一件事：谁是 CLI

两条路，必须先选，否则后面全是重复劳动。

| | 甲：`agentx-cli` 接棒 | 乙：两边都写 |
| --- | --- | --- |
| `docs/design/cli.md` | 改写成 `agentx-cli` 的设计（保留 §1 的判据与 §7 的退出码契约） | 拆两份 |
| `vercel/reference/cli.md`（中英） | 改写成 `agentx-cli` | 加一节"另一个 CLI" |
| `skill/connectx/SKILL.md` | 改名 + 重写 | 两份 skill |
| `packages/cli` | 明确标冻结，文档里不再作为入口 | 继续维护 |
| 代价 | 文档站上旧的 `connectx` 页面要么删要么标注 | 每改一次命令面要改两处，且**门禁只认一份** |

**建议甲。** 理由不是"Rust 更好"，是 TODO5 §0 已经这么定了（`packages/cli` 冻结），
而文档没跟上；两边都写会让"命令面只写一遍"那条机制（`cli.md` §3 的开头）
**当场作废**——那才是真的贵。

### 2.2 清单

- [x] **§2.1 的裁定落成一句话**，写在 `docs/design/cli.md` 开头：这个仓库的 CLI 是哪个二进制，
      另一个是什么状态。**先做这条**，它是其余各条的前置。
      —— 2026-10-02 定：`agentx-cli` 是 CLI，`connectx` 冻结；用户原话「ts的cli暂时不要动，
      也不加功能，主攻rust cli」。已写进 `docs/design/cli.md` 开头。
- [x] **`rust/README.md` 的**命令面一节**升级成参考页级别的逐条说明**
      （今天它是散文，缺"每个旗标的默认值"与"失败时说什么"）。
      —— 2026-10-02 完成，**加成式的**：原来自上而下的"为什么"散文一字不动，在它下面新增
      `### 约定（每条命令都适用）`（`--allow-private-host` / `--json` / 身份选择链 /
      退出码 / 失败形状）与六族逐条表（每族一张 `命令 | 位置参数 | 旗标（默认值）` 表 +
      一段"失败时说什么"，引的都是**真跑出来**的话）。分四笔落地：
      `b24f14d`（did / agent 与约定）、`88090a1`（msg）、`8198e23`（group 含 e2ee）、
      `2be3599`（contacts / me / anp / discover / version）。选加成而不是重写，是为了
      不把已有的"为什么"降级成一张表。
- [x] **`vercel/reference/cli.md` 与 `vercel/en/reference/cli.md`：按 2.1 的裁定改写**，
      并**同时改 `see` 指向的那批页面**（`cli.md` §3 记的门禁只管"链接还活着"，
      不管内容一致——所以这条是人手的活，别指望门禁替你发现）。
      —— 2026-10-02 完成（`aad660b`）：两页重写成 `agentx-cli`（怎么装、store 根、身份选择链、
      退出码与 `Error: <码>: <人话>`、逐族表 `did`/`agent`、`msg`、`contacts`、`group`（含
      `e2ee`）、`anp`、`me`、`discover`/`version`，以及调用方必须接住的那几条拒绝）。
      页面顶部有一句"`connectx` 已冻结、其余指南仍是 connectx 写法、正在迁移"——站点对自己的
      过渡状态说实话，而不是自相矛盾。导航标签、站点描述与**八处**入站链接文本一并改名；
      `npx vitepress build` 全页渲染、无死链。
- [ ] **文档站其余页面里的 `connectx` 例子还没换。** 参考页已指向 `agentx-cli`，但
      `quickstart.md`、`introduction.md`、`messages.md`、`realtime.md`、`groups.md`、`e2ee.md`、
      `deploy.md` 的**正文**仍在教 `npx connectx …`（各自 ×2 语言）。按 2.1 的裁定
      （`connectx`"不再是文档入口"）这些都该换，但那是一次跨十来页的正文改写，且 `quickstart`
      的安装那段要从 `npx` 改成"从源码 build"，**需要你点头再动**：甲=现在就整体换；
      乙=只在各页加一句"另有 `agentx-cli`，见参考页"，正文维持现状。
      —— **2026-10-02 核过一件事，它决定甲案怎么落笔**：`agentx-cli` 这个名字**在 crates.io 上
      已经是别人家的**（`https://crates.io/api/v1/crates/agentx-cli` → `github.com/open-agentx/agentx-cli`，
      一句"a lifecycle CLI for AI coding agents"，2026-05-10 发的 0.1.0，唯一一版）。本仓库
      `rust/Cargo.toml` 的 `version = "0.0.0"`、从没发过。所以第一，**不许写
      `cargo install agentx-cli`**——那会装到别人家去；第二，甲案里 quickstart 的安装段只能
      落成"从源码 build"（`git clone` + `cargo build --release -p agentx-cli`，二进制叫 `agentx`），
      除非先决定改名或先决定发布。这两件都是独立决定，不在本条里顺带做。
      —— **2026-10-03 裁定：甲**（用户："一三按建议"）。就是现在整体换。安装段照上一段
      落成"从源码 build"，**不写 `cargo install`**。下面在做。
- [x] **`skill/connectx/SKILL.md`：按 2.1 改名/重写，并**把 `help.test.ts` 的门禁跟着改**
      （它拿 skill 里逐字给出的调用去和命令面对账，命令面变了它就该红）。
      —— 2026-10-02 完成（`6063fd0`）：`skill/connectx/SKILL.md` → **`skill/agentx-cli/SKILL.md`**，
      按 Rust 客户端重写（装法、store 根、`did create` 一步注册、`contacts`、扩展面的
      `unsupported_extension` 负结果、`Error: <码>: <人话>`），判断那部分照旧。
      门禁**从 `packages/cli` 搬到 Rust**：它原本拿 skill 的调用对 TS 的 `commands.ts` 账，
      skill 改讲 `agentx-cli` 之后就对错了账本；现在在
      `rust/crates/agentx-cli/tests/cli_surface.rs` 里**跑真二进制**校验每条逐字调用与旗标。
      `help.test.ts` 只留三条门禁；`docs/design/cli.md` 记了这次搬运。
- [x] **`docs/design/cli.md` §8 的存储布局**：现在是 `~/.connectx/` + `key.json`（keystore V3），
      与 Rust 的 `~/.agentx-cli/<agent>/<profile>/{identity.json,session.json}` **不同**。
      要么写两段，要么写一段并把差异点名。
      —— 2026-10-02 完成（`d565369`）：**一段名字、差异点名**。冻结的 `connectx` 那棵树保留，
      旁边摆上 `agentx-cli` 的（`identity.json` / `session.json` / `successor.json` / `mls/` +
      `current-agent`），并点出两处**实质**差异：私钥在 `identity.json` 里（PEM、0600）而不是
      单独的加密 V3 keystore（口令那套旗标在 Rust 侧不存在）；暂存后继钥叫 `successor.json`。
      `mls/` 只有 Rust 侧有（P6）。
- [x] ~~**`did publish` 与 `me` 还没有任何用户文档。**~~ 它们不在 `cli.md` §3 的命令面里
      （那节列的是 `connectx`），也不在文档站上。文档要跟上。
      —— 2026-10-02 完成：`rust/README.md` 的 `did`/`me` 条（`b24f14d` 起）已逐条写清
      （`did publish` 的三步、CAS、重签、忽略 `proof` 的比对；`me` 的字段映射与"只发点过名的
      字段"），文档站的参考页（`aad660b`）也各有一节。
- [ ] **§3 与 §4 的每一条命令，落地时同时写文档。** 命令面和文档在同一次改动里，
      别攒着——TODO5 攒了一次，结果就是 `did publish` / `me` 至今无文档。
      —— 进度：**§3 的 `contacts` 一族已随 `cf4b7dd` 落地**，文档同批写完
      （`rust/README.md` 的 `contacts` 条 + `msg send --to` 那一条，
      `docs/design/message-service.md` §9.4 的接口定义、§9.1 与 §13 的 Profile 清单）。
      **§4 的"群里成员的名字"也已落地**（`rust/crates/agentx-cli/src/contacts.rs` 的
      `RosterNames` + `main.rs` 的 `group members --names`），文档同批在 `rust/README.md`
      的 `group` 条里。**§4 的"群的本地备注"也已落地**（service 侧 `cf4b7dd`… 之后的
      `5f979c0`，CLI 侧 `c2059f6`），文档同批：`docs/design/message-service.md` §9.1/§9.5/§13
      + `rust/README.md` 的 `group` 条。§4 只剩"我在群里的昵称"一条，已裁定**以后做**。
- [x] ~~`TODO5.md` §6 里那些"端到端跑过"的记录**是历史，不是说明**。~~ 参考页要能独立站住，
      不能要求读者先去读一份 TODO。
      —— 2026-10-02 完成：参考层（`rust/README.md` 的 `### 约定` 往下 + 文档站两页）**不引任何
      TODO**，逐条表与"失败时说什么"引的都是真跑出来的输出，能独立读；上面那层"为什么"散文仍
      指 TODO5 §6，那是**刻意的**——它讲的是来历与取舍，不是使用说明。顺带把开头那句
      `CONNECTX_HOME` 改成实际的环境变量名 `AGENTXCLI_HOME`。

---

## 3. 通讯录：名字 ↔ DID

### 3.1 为什么要有这一层

ANP 的定址单位是 **DID**，`msg send --to` 只吃 DID。
但人是按名字认人的，**Agent 也是**：它接到"给 Alice 发消息"这句话时，
手上只有一串 `did:wba:...`，没有任何东西说哪个是 Alice。今天这个客户端
**没有通讯录**（§1 最后几行量过），所以它答不了这个问题。

这就是用户说的"个人用户的这个信息这些东西"。

### 3.2 要分清三个名字，它们不是一个东西

| 名字 | 谁起的 | 存在哪 | 换钥会不会丢 |
| --- | --- | --- | --- |
| `remark` 备注 | **我**给他起的 | 本地，协议不支持也不该支持 | 挂错键就会丢 |
| `nickname` 昵称 + 头像 | **他自己**起的 | 服务该 DID 的**主机**上（`get_me`） | 不会，但他能随时改 |
| `subject` 稳定主体 | 协议给的 | 在 DID 文档里 | **不会**——它就是为了"换钥不换人"才存在 |

**推论（这条是整节的支点）：本地那行的主键必须是 `subject`，不是 `did`。**
换钥会把 `did` 挪走（`did update` 就是干这个的），备注挂 `did` 上就会在换钥时
静默消失——而这正是 `anp show` 非要摊开 subject / did 那一对的原因。
`did` 是**列**，不是键。

### 3.3 要做的事

- [x] ~~**定表**~~ —— **表的答案不是本地文件，是 service 的库**（用户裁定"我们 service 的库"）。
      落在 `packages/service` 的 `contacts` 表，列为 `(owner_did, subject, did, remark, created_at,
      updated_at)`，`SCHEMA_VERSION` 12。不在 `<store root>/` 下，所以没有 `0600` 那一条。
- [x] ~~**先裁定隔离粒度**~~ —— **随"存在 service 的库"一并定了，且不是原来那两个选项**。
      行按 `owner_did` 分——`owner_did` 是请求的**已验证签名者**（不是参数里写的名字），
      所以一个身份的备注对另一个身份天然不可见，粒度落在**身份**上而不是整机。
      这正是用户要的"别人是看不见的"，且不需要文件权限来保证。
- [x] ~~**命令面 `contacts` 一族**~~ —— `list` / `add <did> [--remark <s>]` /
      `set-remark <name> <s>` / `remove <name>` / `resolve <name>` 均已在 `agentx-cli` 落地
      （`rust/crates/agentx-cli/src/main.rs` 的 `ContactsCommand`）。
      `resolve` 名字进 DID 出、`--json` 给机读；`--own` 走本身份的库。
- [x] ~~**`msg send --to` 接受名字**~~ —— **形状定为：DID 形状的参数直接进发现，其余当名字查通讯录**。
      不另开 `--to-name`：`--to` 的取值本身就能分辨（`looks_like_a_did` 是语法测试，不是方法白名单）。
      非 JSON 输出会把 `named:` 一行打出来。
- [x] ~~**重名要能拒**~~ —— 大小写不敏感地收集**全部**匹配再计数，≥2 就退出 1 并逐个列出候选的 DID 与备注；
      不是"精确拼写赢"。`lookup` 的 `Ambiguous` 分支就是这个。
- [x] ~~**写入路径**~~ —— ① 显式 `contacts add` 与 ② 收到消息时落一行**都已落地**；
      ③ 不做（自动联网查 profile 会让"看看通讯录"突然打网络）。
      —— **2026-10-02 裁定：② 做**（用户选"做"）。语义钉死在代码里：**②绝不碰 `remark`**。
      `contacts.put` 的线上规则是"缺字段即清空"，而 ② 是系统自己走的路径，照搬那条
      就会把用户已经起好的名字清掉——"发错人"的另一种形态。所以存储层分成两条：
      `upsertContact`（整行以这次为准）与 `rememberContact`（只挪 `did` / `updated_at`），
      `direct.ts` 用的是后者。落点在受理的同一个事务里，且只在**本服务就是 ingress** 时
      执行（`relayed` 早返回之后）。三条服务侧用例：来信落一行（无备注）／来信**不动**
      已有的备注／同一个人第二封不新增行。
- [x] ~~**拉 nickname 要跨域**~~ —— **裁定：不做**（同 ③）。nickname 是对方自己的说法、存在对方的主机上，
      存到我们这儿就是一份没有失效机制的缓存。`contacts` 只答"这个 DID 对我来说是谁"。
      所以 `Contact` 里没有 nickname 字段，服务端返回里也没有。
- [x] ~~**换钥后要认得出是同一人**~~：**认人已经成立**——行按 `subject` 存，换钥不动 `subject`，
      所以备注不会丢（§3.3 第三条测试已覆盖）。**还缺的是 `did` 这一列的刷新**：
      对端换钥后，本地这行的 `did` 会旧到下次交互为止。谁触发？（`contacts refresh`？
      还是 `did resolve --chain` 成功后顺手？）——**这一条还悬着，要给答案。**
      —— 2026-10-02：写入路径 ② 落地后**这条窄了一半**。对端只要再写一封信，
      `meta.sender_did` 里的新 DID 就落回这一行的 `did` 列（`rememberContact` 只挪 `did`）。
      剩下的只是"换了钥、且从此不再来信"那一档，而它在**按 DID 发信会失败、按名字仍解析到
      旧 DID** 时才咬人。所以现在的形态是：不急着造 `contacts refresh`，
      但真遇到时它得是一条命令，而不是让用户手动 `remove` 再加回来。
      —— **2026-10-03 裁定：甲**（用户："二也甲"）。**不造 `contacts refresh`**。这条的
      射程收窄到"真咬到人时再加一条命令"——加命令是增量、不改任何现有语义，所以不必现在
      为一条今天走不到的路径提前造它。到此为止。
- [x] ~~**测试**~~ —— ① 换钥后备注还在：`packages/service/src/rpc/dispatch.test.ts`
      的 "subject survives a key change"；② 重名被拒且列出候选：`contacts.rs`
      `two_contacts_with_the_same_name_are_ambiguous_and_both_are_listed` 与
      `the_ambiguous_refusal_lists_every_candidate_with_its_did`；③ 可执行的错：
      `the_unknown_name_refusal_names_the_command_that_fixes_it`。共 11 个新单测 + 8 个服务侧用例。

---

## 4. 群聊资料

### 4.1 协议给的和不给的

- **群自己的名字**：`group_profile.display_name`，走 `group.update_profile`，
  要 `permissions.update_profile` 权限。（CLI 早已有这条命令，见 §4.2 第一条。）
- **群成员的显示名**：`member_list` 每一项只有 `{agent_did, role, status, joined_at}`——
  **没有名字字段**。要看名字，只能各自去主机取 profile（§3.2 那张表），或本地缓存。
- **"我在这个群里的昵称"**：协议里**不存在 per-membership 昵称**。
  这是真的缺一块，不是我们没找到。

这就是用户说的"群聊的这些信息"。

### 4.2 要做的事

- [x] **`group update-profile <group_did> --name <s>`**：改群自己的名字。
      先确认本仓 `packages/service` 支持这个方法、且权限判断对
      （不支持的端要回 `-32601`，那是**正确的负结果**，见 §5 最后一条）。
      —— 2026-10-02 核过：`packages/service/src/rpc/groups.ts` 有 `group.update_profile`，
      权限键 `update_profile` 在 `PERMISSION_KEYS` 里，正文收 `group_profile_patch`（RFC 7386）。
      命令已落地，走 `anp.group.base.v2`、target 是群、subject 是 `group_did`。
- [x] **`group info` 打出 `group_profile.display_name`**：先查今天打不打；
      不打就是一条现成的补丁。
      —— 今天**已经打**（`report_group_info` → `name:`），不是缺口。
- [x] ~~**群里成员的名字**~~：`group members` 今天只出 did / role / status / joined_at。
      加名字有两条路，要选：
      ① `--names` 显式开关，逐个去主机取 profile（群大了会很慢，但总是新的）；
      ② 只显示**通讯录里已经认得的**，认不得就只出 DID（快，但依赖 §3 的表）。
      **建议 ②为主、①做逃生舱**：默认不联网，要名字就明确要。
      —— **2026-10-02 裁定：按"②为主 + ①逃生舱"做**（用户选的就是这条）。
      默认那条只读 `contacts.list`，认不得就出 DID；`--names` 才逐个去各自主机 `get_me`。
      —— **2026-10-02 落地**。默认读一次 `contacts.list`，名字按 **`subject`** 查（§3.2：
      换钥后仍认得出人），认不得就只出 DID；`--names` 只对**通讯录不认得**的成员去各自
      **DID 主机**取名字，**备注优先**、已起过名的不再问。两条要说清的：
      (a) 取名字走的是主机上那条**免凭据的公开资料路由**
      `GET /user-service/v1/users/<did>/profile`（awiki 自己的兼容面，不是 ANP——
      `get_me` 要 bearer token，我们只有自己身份的，读不了对端的）；
      路径里的 DID 要**把 `%` 再转义一次**（`%3A` → `%253A`），否则服务端解一次码就得到
      `localhost:8765` 这个不存在的 DID——已用真主机对过：不转义回 404 `profile_not_found`。
      (b) 对端主机不是 awiki 时该成员退回只出 DID，末尾一行 `note: N member(s) …`。
      **不是失败**：可执行的那一半（DID）照样在。`--json` 始终是服务答复原文，名字属于
      给人看的那一层。真链路跑过：本仓 service 上建群 → awiki 身份 `group join` 进群 →
      默认只出 DID；`--names` 把 awiki 那边的 `Names Alice` 取回来，而 toy host 那个成员
      如实落进 note；给 awiki 那位起了备注后，`--names` 也只出备注（对方改成
      `AWIKI-NAME-WINS` 也没顶掉它）。4 个新单测（`contacts::tests` 的 `RosterNames`）。
- [x] **群的本地备注**：和人的 remark 同口径，落在本地表
      （`groups(group_did / subject, remark, ...)`）。我给群起的名字，协议里没有。
      —— 口径要跟 §3 对齐：人的备注落在 **service 的库**（`contacts` 表，`owner_did` 分行），
      所以群的备注也应落在同一处、同一分行方式，别一边在库里一边在文件里。
      —— **2026-10-02 裁定：新表 + 新扩展面**（用户选的，不是"复用 `contacts`"、
      也不是"只在 `group info` 里显示"）。落成 `group_remarks(owner_did, group_did, remark,
      created_at, updated_at)` + Profile `x_agentx.group_remarks.v1`
      （`list` / `put` / `remove` 三条，见 `docs/design/message-service.md` §9.5）。
      **为什么不并进 `contacts`**：那张表是"`msg send --to` 能到谁"，键的另一头是一个
      **agent**；并进去会让一个名字解析成群 DID，再让 `msg send --to <那个名字>` 把消息投进
      一个群读不了的邮箱。**表的键是 `group_did` 本身、不是 `subject`**——群 DID 是本服务
      命名空间里的 `did:web:…:g:<id>`，不含钥指纹也搬不动，`subject_of` 在它身上是恒等
      函数，这是它与 `contacts` 唯一的结构分歧。`remark` 这一列是 `NOT NULL`（同样与
      `contacts` 不同）：通讯录有"收信时顺带落一行"的写入路径会造出无名的行，这张表唯一
      的写者就是起名这个动作，一行没有名字就是 bug 而不是一种状态。服务**不检查**群是否
      托管在本机（和 `contacts.put` 不检查对端存在同一条道理）：名字是调用者的记忆，
      联邦那头的群恰恰是本地这本册子该管的事。
      CLI 落成 `group set-remark <group_did> <s>`（清空是 `--clear` 取反，不另开子命令），
      `group info` 在 `name:` 下一行印 `remark:`（只走非 `--json` 那一档）。真链路跑过：
      建群 → `info`（无此行）→ `set-remark` → `info`（`remark: Team`）→ 改名 → `--clear`
      → `info`（行没了）；再让第二个身份给同一个群起名，第一个身份的名字**不受影响**
      （两本册子、按 `owner_did` 分行）。服务侧 9 个 dispatch 测试 + Rust 侧 3 个单测。
- [ ] **"我在群里的昵称"要一个裁定**：本地表存，还是提一个 Profile 扩展？
      今天协议没有这一层，所以这是一次**设计选择**，不是实现细节。**别悬着**——
      悬着的结果就是每个客户端各存各的、互不可见。
      —— **2026-10-02 裁定：接下来以后做**（用户原话）。所以现在**不动**，
      保持"协议里没有"这个事实可见即可；真要动时再来选本地表还是扩展。

---

## 5. 测试

### 5.1 "跑通"分三档，别把它们混成一句

| 档 | 含义 | 今天 |
| --- | --- | --- |
| **一** | 单测全绿 | ✅ 154 个库侧 + 8 个命令面（`tests/cli_surface.rs`） |
| **二** | 一个人照文档能手工跑完一条链路 | ✅ `scripts/e2e.sh` 一条命令跑完（`4245d9e`），不再是只有散文的配方 |
| **三** | **一条命令**跑完全链路，并且 CI 每次 push 都跑 | ✅ `e2e` 这个 job（`e9d14dc`）：`./scripts/e2e.sh`，GitHub 上三个 job 全绿，`e2e` 从头到尾约 70 秒 |

用户那句"至少我要能跑通吧"要的是**二**，但只有做到**三**，二才不会随时间烂掉
（文档里的手工步骤是最先过时的那一类东西）。

### 5.2 卡在哪：本仓库没有 DID host

链路的前半截需要一个 **DID host**，而后半截需要本仓的 `packages/service`：

```
did create / did publish / me   ──►  DID host（本机 awiki-open-server，:8765）
msg * / group * / group e2ee *  ──►  packages/service（本仓，:8787 之类）
```

`did create` 的第一步是 `GET /.well-known/did.json` 读主机的 `serviceDid` 与消息端点
（`identity/host.rs::fetch_host_service`）。**本仓的 `packages/service` 没有这个路径**——
它只发 `/.well-known/anp-message-service.json`，以及每个群的 `GET /g/<id>/did.json`
（`http/server.ts:24,28`）。所以 `did create --host http://127.0.0.1:8787` 今天**必然失败**。

后果：第三档的 e2e 要么拖上 awiki，要么先补上这个路径。两条：

| | 甲：e2e 带上 awiki | 乙：让 `packages/service` 也当 DID host |
| --- | --- | --- |
| 做法 | CI 里 clone 并起动 `awiki-open-server` | 给 `packages/service` 加 `/.well-known/did.json`，返回它自己的 `serviceDid` |
| 好处 | 不碰服务端代码 | **一条命令、一个仓库**就能跑通，CI 里不需要第二个仓库 |
| 代价 | awiki 硬断言 `anp==1.0.3`（`AGENTS.md`），Rust 这边钉 `anp=1.0.5`——**两个 Python/Rust 版本线要一起维护**；CI 里还要 clone 一个外部仓 |
| 语义风险 | 无 | 服务端要声明一个它**并不真的持有**的 DID 身份文档（它的身份一直在 awiki 上）。这不是实现细节，是一次**设计裁定**：本仓的 service 能不能同时当自己的 DID host？ |

**建议乙，但先裁定语义。** 那个问题的答案是"能"还是有代价的——`did:wba` 的文档要和主机
的真实域名/端口对得上，`serviceDid` 又是配置里来的。如果没有干净的答案，
**退到甲，并且把"需要 awiki"写进 e2e 的前置条件里**，别假装它能自足。

> **2026-10-02 裁定：走甲**，用本机的
> `/Users/eccstartup/code/claude/awiki-open-server` 那份 checkout 当 DID host
> （用户原话「用这个跑」）。所以 e2e 的前置条件里**明写"需要 awiki"**，
> `scripts/e2e.sh` 要么检测它、要么给出起动命令（§6 第 1 步），不许假装本仓自足。
> 乙那条路（让 `packages/service` 也当 DID host）**没被否决，只是没选**——
> 它要的那次语义裁定（本仓 service 能不能声明一份自己并不持有的身份文档）还没做。

> **2026-10-02 补记（做 §5.3 的第一条时撞到的）。** 裁定之后发现两件事，都会影响乙的估价：
>
> 1. **乙不只是语义裁定，还得改客户端。** `identity/host.rs::fetch_host_service` 把主机文档的
>    `id` **同时**当作 `serviceDid` 与身份 DID 的 `authority`，而 `authority` 又要求
>    以 `did:wba:` 开头。给 `packages/service` 加一份 `id = did:web:127.0.0.1%3A8787` 的
>    `/.well-known/did.json`，这条客户端路径**第一步就会拒**（"the host's DID is not a
>    did:wba DID"）；就算把前缀放宽，`authority` 会变成 `127.0.0.1%3A8787`，而
>    `create_did_wba_document` 拒收 IP 当主机名。所以乙要连着改三处，不是加一条路由。
> 2. **"主机即消息服务"是这个客户端的结构假设，不只是 awiki 的配置。** 服务自己的
>    `did:web:` 与主机的 `did:wba:` 天生是两个方法，除非服务能被声明成别的权威——
>    而 `AGENTX_SERVICE_DID` 正是那个开关。§5.3 的玩具主机就是用它把两者接上的。

### 5.3 计划

- [x] **进 CI 的最小一步：`cargo test` + `cargo clippy`。** 与 5.2 无关，可以立刻做。
      今天 Rust 这边**完全不在门禁里**，改坏了没有任何东西会红。
      —— 2026-10-02 做了：`.github/workflows/ci.yml` 新增 `rust` job，跑
      `cargo test --all-targets` 与 `cargo clippy -- -D warnings`；顺手修掉唯一那条
      `needless_question_mark`（`message/client.rs`）。`cargo fmt --check` 未加（见原文）。
- [x] **一个可复跑的 e2e 配方**（先是一份 `scripts/e2e.sh`，不是测试框架）：
      起 host → 起 service → 走完整条链路 → 断言。今天这条链路是**手工走过一遍**的
      （见 §6），把它写成脚本的第一版就是把 5.1 第二档钉住。
      —— **2026-10-02 落地（`4245d9e`）**。`scripts/e2e.sh` 起一台 DID 主机 +
      本仓 `packages/service`，用**真二进制**走完 `did create|show|publish`、
      `me set|show`、`msg send`、`contacts add|resolve`、`group create|info|members|
      set-remark|join|leave|update-profile|send`、`group e2ee publish|create`，逐条断言，
      非 0 退出，失败时把两份日志的
      尾部一并打出来。两条**必须在联网前发生的拒绝**也在里面（`me set` 空参、
      删掉 `session.json` 后的 `did publish`）。
      **DID 主机那里有一处与 §5.2 的字面不同的做法，说清楚**：脚本自带一台玩具主机
      （`scripts/e2e/did_host.py`），所以整条链路**不需要 awiki**，一条命令、一个仓库就能跑。
      理由不是省事：`msg` / `group` / `group e2ee` 要打的是**本仓的服务**，而身份文档里的
      `serviceDid` 是**主机**在它的 `/.well-known/did.json` 里说了算的
      （`identity/host.rs::fetch_host_service` 读主机文档的 `id`），awiki 只肯发端点指向**它
      自己**的文档——拿它当主机，恰恰**测不到**"对端服务在别处"。`packages/e2e/src/harness.ts`
      起玩具主机的理由与此**逐字相同**（那里写的原话是"拿它当主机就测不到对端服务在别处"），
      所以这不是本脚发明的东西，是本仓既有的那个决定。玩具主机只做主机该做的那几件事，
      **没有一处签名逻辑**（文档全由客户端造再 `register`，主机只按 DID 存、按 DID 发），
      并把 `/g/<id>/did.json` 让给服务（`groups.md` §2.2：群文档归服务）。
      它对外宣告的身份就是服务的身份（`AGENTX_SERVICE_DID` 设成同一个值），于是
      awiki 那套"主机即消息服务"的关系照旧成立，只是消息服务换成了我们的。
      **awiki 的角色因此被收窄到它唯一能演的那半截**，并且是**开关打开才有**：
      `./scripts/e2e.sh --with-awiki` 对真主机 :8765 跑 `did create` / `did publish`
      （先 no-op，改一笔后真的走 awiki 的 CAS 推 `version: 1 -> 2`）/ `me set`。
      这一遍会在那台 awiki 上**留下一条身份**（`register` 没有删除、handle 唯一），
      所以 handle 带时间戳、默认不开——前置条件（含起动命令）写在脚本头部，不假装自足。
      **两半都实跑过**：玩具那半全绿；awiki 那半（本机 8765 在跑）全绿，版本 1→2 是真的。
- [x] ~~**把配方升成 `rust/crates/agentx-cli/tests/` 里的集成测试**~~，读 `AGENTXCLI_HOME`
      指向的临时目录，自己起服务、自己收尾。这一步之后第三档才成立。
      —— **2026-10-02：这条的理由已经兑现，但走的是另一条路，所以留着等裁定。** 它给的
      结果是"第三档才成立"，而第三档今天成立的方式是**脚本进 CI**（§5.1 已改）——
      `e2e` job 每次 push 都跑，GitHub 上前三个 job 全绿。写这条时假定的是"配方只能是人跑
      的脚本，所以得把它变成 `cargo test` 的一档"，CI 证明了这个假定不成立。
      还剩的价值只有一条：**不跑脚本、只跑 `cargo test` 的人**看不见这条链路。
      两条路：(甲) 就到这里，脚本+CI 就是第三档的载体（`cargo test` 仍只跑库侧）；
      (乙) 再加一层"把脚本当测试"的薄测试（`#[ignore]` 默认跳过，`cargo test -- --ignored`
      才跑），代价是同一套机制多一个入口、且 `cargo test` 会多一个需要 node 的档。
      **建议甲**，不为一个已经有的门禁再造一个影子。**这条要用户裁一下。**
      —— **2026-10-03 裁定：甲**（用户："一三按建议"）。脚本 + CI 就是第三档的载体，
      `cargo test` 仍只跑库侧；**不**再造一个 `#[ignore]` 的影子入口。这条到此为止。
- [ ] **覆盖要跟命令面走，不是跟"写过的测试"走。** 132 个单测长在库侧
      （身份存储、JCS 哈希、会话缓存、策略、信封），**命令面一层几乎没有测试**。
      `did publish` 的三个分支（未变 / 变了 / 没有 token）今天只在手工验证里出现过。
      §3、§4 落地后同样要补进这一层。
      —— 进度：**第一块已落**（`rust/crates/agentx-cli/tests/cli_surface.rs`，`d5bbd89`）。
      它跑**真二进制**（解析器推出来的清单与被测对象同源，什么都钉不住），覆盖九族的
      `--help`、`contacts resolve <did>` 的不读库短路、以及两条必须在联网前发生的拒绝。
      全是**不需要 DID host** 的那一半——`did publish` 三个分支仍要等 §5.2 的裁定。
      —— 进度二：**要 DID host 的那一半落进了 `scripts/e2e.sh`**（`4245d9e` 起，此后每块
      新命令面都跟着加）：`did create|show|publish`（含 no-op / 改一笔 / 无 token 三个分支）、
      `me set|show`（含空参拒绝）、`msg send`、`msg listen --once`（`80dff85`，
      投递与读取是两件事）、`msg send --to <名字>` 与其拒绝（同一次）、`contacts add|resolve`、
      `group create|info|members|set-remark`、**`group join|leave|update-profile|send`**
      （2026-10-02 补，此前这四条只有"写过"没有"跑过"）、`group e2ee publish|create|
      get-key-package|add|send|remove`（2026-10-02 补全，`f6e284c`）——P6 的四条控制方法
      此前只有手工跑过，现在脚本里也跑，其中"柜子是空的"那条是**以拒绝为预期**的负结果
      （5000 `key_package_not_found`）。脚本一并记下了 KeyPackage 的**一次性**语义：
      `get_key_package` 在挑的同时就占住它（§8.2.4 L767 的 MAY），所以"读一枚来断言"与
      "让 `add` 拿走一枚"是两次消耗。
      **还差**：`did update` 与它的 `--resume`、`anp login` 的 401 挑战那条路。这几条各自要
      一台愿意配合的主机或第二个设备，不是能顺手塞进去的。
      —— **2026-10-03 裁定：以后再说**（用户："五以后再说"）。所谓"加一台**会验签**的玩具主机"
      是**另一个决定**，不是这条待办的收尾：它的独立价值是能咬住"签名到底对不对"，
      但要新造一个组件。不现在做，也不把它记成"必须做"——真到想咬住签名链路时再单开一块。
- [x] ~~**负结果的测试值得单列。** 这个客户端的正确行为里有好几条"对端不支持时应该怎样"~~
      （`msg inbox` 一族对 awiki 回 `-32601` 是**正确**结果，`cli.md` §5）。
      这类断言最容易在重构里被悄悄改成"跳过"，要有测试咬住。
      —— **2026-10-02 落地**。写这条时撞到一个真的分歧：TS 那边有一枚自己的错误码
      `unsupported_extension`（`packages/core/src/errors.ts`），`cli.md` §5 与文档站
      （`vercel/reference/errors.md`）也这么写，**而 Rust 这边把它折进了 `message_invalid`**。
      折进去的代价正是这条待办要防的：一个脚本再也分不出"对端只实现规范"（该换个对端）
      与"这次没成"（该重试或查因），而"折"本身正是那种重构。所以先补上这枚码
      （`error.rs::UnsupportedExtension`，`code()` 给 `unsupported_extension`），
      `channel.rs::extension_rejection` 与 `listen.rs` 的未知方法那条都改回它。
      咬住它的是两处：**单测**（`channel.rs::tests` 四条——`-32601` 与 `1001
      anp.unsupported_profile` 报成 `unsupported_extension` 且带"实现扩展、规范未定义"那句话；
      `-32602` / `1014` 这类**真的拒绝**报成 `message_send_failed` 且不许出现
      "does not implement"——反方向也钉住，否则"把拒绝读成没有"同样是错的；
      拒绝那条把对端自己的 `anp_code` 带上行）；**真主机**（`scripts/e2e.sh --with-awiki`
      新增四条断言，awiki 对 `inbox.get` 回的就是 `-32601`）。实跑过：退出 1、首行是
      `unsupported_extension`、话里带 `does not implement inbox.get (JSON-RPC error -32601)`。
      这一条断言是目前唯一**以失败为预期**的那种，所以它单独占一段并写明了为什么。

---

## 6. 今天手工跑通的那条链路（写进脚本的原料）

> **2026-10-02 后记**：这一节现在是**历史**——它已经被 `scripts/e2e.sh` 收进去了
> （§5.3 第一条），脚本跑的就是这里的命令与断言。留着的理由有两条：README 与 §5 一直在
> 指它，以及它记的是**当初为什么这么走**（比如"手工在 `identity.json` 里加一条
> verificationMethod"这个动作，在脚本里是那几行 python）。要跑就请跑脚本，不要照这里抄。

2026-10-02 实跑过一遍，命令与观察到的输出如下。这是 5.3 第二档的直接原料。

```bash
# 1. DID host（外部仓库，一次）
cd ~/code/claude/awiki-open-server
PYTHONPATH=src AWIKI_DATA_DIR=/tmp/awiki-data \
  AWIKI_PUBLIC_BASE_URL=http://127.0.0.1:8765 AWIKI_DID_DOMAIN=localhost \
  uv run uvicorn 'awiki_open_server.app.main:create_app' \
  --factory --host 127.0.0.1 --port 8765
```

```bash
# 2. 客户端（本仓）
export AGENTXCLI_HOME=/tmp/agentx-e2e

cargo run --manifest-path rust/Cargo.toml -- \
  did create --host http://127.0.0.1:8765 --handle e2ealice --agent e2ealice
#   → did / device / stored / token: cached in …/session.json / registered with …
#     ^ 这个 token 就是 did publish 与 me 读的那个

cargo run --manifest-path rust/Cargo.toml -- did publish --agent e2ealice
#   → http://127.0.0.1:8765 already serves this document / version: 1
#     ^ 什么都没变时是 no-op，而不是把 version 顶上去

# 手工在 identity.json 里加一条 verificationMethod（模拟"本地文档改了一笔"）
cargo run --manifest-path rust/Cargo.toml -- did publish --agent e2ealice
#   → published … / version: 1 -> 2 / store: …/identity.json
#     ^ 重签 + 写回；不写回，store 里就留着一份 proof 盖不住自己的文档

cargo run --manifest-path rust/Cargo.toml -- me set --agent e2ealice --name "Alice 爱丽丝" --bio "…"
cargo run --manifest-path rust/Cargo.toml -- me show --agent e2ealice
#   → did / handle / name / bio / avatar / profile
```

失败路径（同样实跑过，脚本里要有）：

```bash
rm …/session.json
cargo run --manifest-path rust/Cargo.toml -- did publish --agent e2ealice
#   → Error: no usable access token for 127.0.0.1:8765 — run `agentx-cli did register …`
#     或 `agentx-cli anp login --target …`

cargo run --manifest-path rust/Cargo.toml -- me set --agent e2ealice
#   → Error: nothing to set — pass at least one of --name, --bio, --avatar, --profile-url
```

`msg` / `group e2ee` 那几族要打本仓的 `packages/service`，配方在 TODO5 §6 各条里，
**它们同样没有脚本**——这是 5.3 那份 `scripts/e2e.sh` 要一并收的。

---

## 7. 其余待办

不在这里展开，但它们是**待办**，不是"不做"。每条的详情在指到的那一节。

- [x] ~~**本地消息库 `messages.db`**：表结构、游标、与 `mls/` 的分工。~~（TODO5 §4、§6 Phase 2）
      —— **2026-10-02 完成（`a5727d4`）：形状定在
      [docs/design/client-messages.md](docs/design/client-messages.md)**。四张表
      （`conversations` / `messages` / `sync_state`，加 `PRAGMA user_version` 的版本与
      拒绝更新的口径），去重键 `(conversation_id, sender_did, message_id)` 是**协议身份**而不
      是本地到达，群消息多记 `epoch` 供两个资产对账。
      **四处不是顺手写的结论**：
      (1) **为什么是两个文件而不是一个 sqlite**——`mls/` 丢了解不开以后、不可重建、属密钥；
      `messages.db` 丢了只是历史没了、能重拉、属内容。三种重建性不同，所以必须能分别备份
      （"只导出一份聊天记录"是这个功能最日常的用途）。
      (2) **没有跨库事务，所以顺序是契约**：crate 落 `mls/` → 落行 → 同一事务最后推本地游标；
      崩溃在中间可恢复（游标没动、服务端会重放，`decrypt_received` 本就允许重复输入），
      反过来先推游标就**静默丢消息**。
      (3) **realtime.md §5.4 那句"本地不存游标"要改口**：它说的是交付游标（仍然只有服务端一份），
      本地记的是"哪些已经落进库"。两者本来就该不同，只有一条单向不变式：
      **没有落库的序号不许 ack**，于是本地那份永远是交付游标的下界。已在原位补说明。
      (4) **换钥之后是个洞**：`messages.db` 按本地槽位而不是 DID 组织，所以历史还在；
      但服务端 `deliveries.owner_did` 不会被挪到新 DID 名下，**这是服务端要补的一笔**——
      也正好解释了本地库的价值。
      **一行代码还没写**：§7 记了动手前三件事（`rusqlite 0.32.1` 已在树里、零构建成本；
      写入口挂在事件消费那一侧），§8 建议**先只写、不改读**——`msg inbox` 要不要变成本地优先
      是一次要用户裁定的动作（三种做法见那份文档 §8）。
      —— **2026-10-02 续（`a04cc5e`、`5c3d5d8`、`4a98d3b`、`9b0a2af`）：写入侧已落地**。
      `crate::messages` 是库（`MessageStore`：表、去重、单事务里"先落行后推游标"），
      `RecordingView` 是那个挂法——包在 `ListenView` 外面，`cmd_msg_listen` 里装配，于是
      **到消费侧才落库**，终端看到的一个字不变；写失败只在 stderr 说一句、不退出，
      因为那一行的游标没前进、下次重连服务端会重放。P6 的 §12 帧走设备队列、没有交付号，
      所以只落行不动游标。**读侧仍然一行没动**（`msg inbox` 还是只问服务端），§7 第 3 条待裁定。
      落地的过程改掉了这份文档两处，都是实现逼出来的：
      (a) **`epoch` 换成了 `group_state_version`**——P6 每条消息的版本是密文自己指名的
      `group_state_ref.group_state_version`（`anp` 1.0.5 的 `V2GroupStateRef`，十进制字符串），
      本地 epoch 是 crate 的状态、两个文件各滚各的；对账要问的正是"对面在哪一版上加的密"。
      两列在库里都是 INTEGER（服务端自己的就是整数列，它还得自增前一个），转不动就拒整行。
      (b) **补上 `messages.endpoint`**：换了服务之后同一个会话里躺着两套编号，
      没有这一列 `service_seq` 就是一串没有命名空间的数字。
      顺带修掉 realtime.md 里第三、第四份已经过期的"本地不存游标 / 尚未落地"。
- [x] ~~**命令面定稿**：六族 24 条 + `did publish` / `me` + §3、§4 新增的，一起冻结形状。~~
      —— **2026-10-02 完成（`053c73e`）：定稿落成一份 50 个页面的清单**（九族 + 各子命令，
      `group e2ee` 六条在内），在 `rust/crates/agentx-cli/tests/cli_surface.rs` 的
      `FROZEN_SURFACE` 里**逐字写着**，每条都要能在真二进制上答出 `--help`：
      改名或删命令会让你**故意**去改那份清单，而这是**唯一**会红的东西（解析器与 help
      渲染器同源，别处都发现不了）。**清单是手写的，不是从解析器推的**——推出来的与解析器
      构造上一致，什么都钉不住。
      **旗标刻意没钉**：它们随协议长，抄进测试会让每次加法都变成两处改动，换来的只有
      "某个旗标被改名"。所以"定稿"的范围就是**页面**：加命令是加法，改名与删命令是
      破坏性的。这条判据和"权威是 `--help`"一起写在 `rust/README.md` 参考层的开头。
- [x] ~~**TS CLI 冻结在某个版本**~~ —— **2026-10-02 结论：没有"某个版本"可钉，因为
      `@agentx/cli` 从没发布过**（`npm view @agentx/cli` → 404，仓库里没有 tag，
      `packages/cli/package.json` 停在 `0.0.0`）。所以冻结点就是**这次裁定这个提交**，
      而"哪个版本起不再加功能"这句话在这里是空的——不存在一个用户手里的旧版本需要被
      按版本说明。冻结的实际射程按用户 2026-10-02 的原话（「ts的cli暂时不要动，也不加功能」）
      是**暂时全停**：不加功能，也不为它改代码。写在 `docs/design/cli.md` 的抬头——
      它是冻结这件事本身的出处，不在 `package.json` 里造一个没有语义的字段。
- [x] ~~**`packages/e2e` 的既有覆盖**~~ —— **2026-10-02 结论：保持不动，但它现在该被
      当成"服务侧的跨域 e2e"，不是"客户端的 e2e"。** 量出来的事实：它 `import` 的是
      `packages/cli/src/commands/*` **源码**（不是 `@agentx/cli` 这个包、也不是二进制），
      所以它**只能**测 `connectx`——Rust 客户端一旦接棒，它作为客户端 e2e 就失效了。
      但 2 个文件 4 条用例里，只有 `directSend` 那两条是重复的（`scripts/e2e.sh` 现在用
      **真二进制**跑同一条路，更好）；另外两条独一份：
      `groupFederation` 是**两台真服务 + 真中继**跨域 `group.send`（本仓别处没有），
      `msg listen` 那两条是**真 WebSocket**——脚本现在只补上了**回填**那半
      （`msg listen --once`，`80dff85`），"连着的时候推过来"那半仍只有这里有。
      所以删掉它的代价不是"少两条旧用例"，是**跨域中继失去唯一的端到端覆盖**。
      迁移的判据留下：等中继那半有了别处的覆盖（或 Rust 侧也起两台服务）再谈搬，
      而 `directSend` 那两条**不要照搬**——同一条路脚本已经跑得更真。今天实跑：2 文件
      4 条全绿，6.4 秒。
- [x] ~~**换设备**~~ —— **结论：对端没有这条路**，不是缺口。
      本机 awiki host 对改设备清单回 `device_enrollment_or_removal_not_supported` /
      `device_key_or_root_change_not_supported`，`replace_did` 回 `not_supported`，
      客户端没有路可走（TODO5 §6）。记在这里是为了别有人把它当缺口重新发现一遍。

---

## 8. 这一轮做完的样子

- 一个没碰过仓库的人，从 `rust/README.md` 或文档站的 CLI 页出发，**不需要读 TODO** 就能：
  起 host、`did create`、`did publish`、`me set/show`、`msg send`、`msg listen`、
  `group create` —— 并且知道每一条失败时会看到什么。
- **Agent 能按名字找到人**：`contacts resolve Alice` 给出 DID 或明确拒绝（重名 / 没有），
  备注在对方换钥之后还在，群成员能显示成名字而不是一串 DID。
- `cargo test` 与 `cargo clippy` 在 CI 里；Rust 这边改坏会红。
- 一条命令跑完整链路，并且在 CI 里跑。
- 文档描述的是**在动的那个二进制**，冻结的那个标着冻结。
