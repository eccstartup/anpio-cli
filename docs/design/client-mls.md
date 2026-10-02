# 客户端侧群 MLS（B2）—— 设备侧的密码学，内嵌进 `connectx`

[e2ee-group.md](e2ee-group.md) 写的是**本服务**在 P6 里的位置：排序、一份公开投影、两台柜子，
一行 MLS 都没有。那份文档从头到尾站在**没有密码学的那一边**。

这份写另一边。做 MLS 的那一半在设备上，而它在本仓库里**一行都不存在**：
[TODO4.md](../../TODO4.md) §B2 记的就是它——"Rust crate → Node 的 napi 绑定"。

口径是**方案，不是落地记录**。下面的函数名、版本、形状都核过，但一行代码还没写；动手第一步
见 §8。

## 1. 为什么有这一块

服务端那一半**早就写完了**：`packages/service/src/rpc/groupE2ee.ts` 571 行受理逻辑，配
`groupE2ee.test.ts` 702 行——方法表、资格门禁、分发、存储都在那条路上跑。它做得也对：判的是
**包装对象的形状与绑定**，不碰 `mls_key_package_b64u` 里面（§4.1 第 1 条：那部分归接收方的
MLS runtime）。

但那套测试的 `mls_key_package_b64u` / `commit_b64u` 是**手搓的 b64u 串**。这不是偷懒，是这半边
**本来就无从**拿到真东西——服务端不做 MLS，测试也就造不出真的。于是现在这个局面：

> **P6 的服务端半边，从来没有被一个真客户端驱动过。**

做 MLS 的那一半在设备侧，而设备侧今天是这样：

- `packages/cli/src/commands/` 有 `group.ts`（P4）与 `msg.ts`（P3），**没有**任何 `group.e2ee.*`；
- `packages/core` 是协议原语的 TS 移植（[vendored-core.md](vendored-core.md)，来源
  `@connectx-sdk/core` 0.4.1），里面**没有** MLS；
- 官方 TS SDK 也没有 MLS（§2 最后一段）。

所以 B2 不是一个"顺手补上"的边角，它是 P6 唯一还空着的一半，而且**正好是最容易出错的那一半**：
Host 判不了的 `delta` 对不对、Commit 是不是正确，全部落在这里。

## 2. 能直接用的东西：官方 crate 已经把每一步写好了

官方 `anp` crate 的 `group_e2ee::operations::v2` 里，P6 要的每一步都有对应的函数，挂在默认开启的
`mls` feature 后面：

| 我们要的 | crate 里的函数 | 返回 |
|---|---|---|
| 发布 KeyPackage | `generate_key_package_v2` | `V2GroupKeyPackage` |
| 建群 | `create_group_prepare_v2` | `V2PreparedCreate{pending_commit_id, body}` |
| 加人 / 移人 | `add_member_prepare_v2` / `remove_member_prepare_v2` | `V2PreparedAdd` / `V2PreparedRemove` |
| 发 / 收消息 | `encrypt_v2` / `decrypt_v2` | `V2GroupCipherObject` / `V2DecryptOutput` |
| 处理通知 | `process_commit_v2` / `process_welcome_v2` / `process_notice_v2` | 各自的结果结构 |
| 收尾与自省 | `finalize_commit_v2` / `abort_commit_v2` / `reconcile_pending_v2` / `inspect_local_group_v2` | 各自的结果结构 |

**这不是"碰巧有这些函数"，是形状本来就是一回事。** crate 的
`prepare →（Host 受理）→ finalize / abort` 两段式，正是 [e2ee-group.md](e2ee-group.md) §4.2
给 Host 定的受理顺序：`remove_member_prepare` 落一个**耐久的 pending commit**、**本地 epoch
不动**，等 `group.e2ee.remove` 被 Host 接受再 `finalize`，被确定性拒绝就 `abort`。
`pending_commit_id` 就是那条关联句柄。**服务端早就是这个形状，客户端库天然接得上**——这是这份
方案里唯一一处不用设计的接缝。

状态那一侧同样对得上：`storage.rs` 的 `ImCoreSqliteGroupMlsStore` 就是**一个调用方指定的
sqlite 路径**加一把 fs2 文件锁（`StateLock`），单进程。正是 [e2ee-direct.md](e2ee-direct.md)
§9.1 定下的"一处落盘、客户端进程"。

**官方自己的位置**（`rust/README.md`）：MLS **是库调用，不是 `anp-mls` 子进程调用**；"MLS state
is kept behind `anp::group_e2ee::storage` store implementations **rather than a subprocess or
CLI JSON command surface**"。这也正是 [TODO1.md](../../TODO1.md) `D4` 裁定 (a) 的依据。

**反面教材也在同一份 README 附近**：官方 monorepo 里 MLS **只**存在于 Rust crate；Python / TS /
Dart / Java 四套 SDK 都没有，Go 只剩一个驱动已被移除的一次性二进制。所以**没有现成绑定可借**——
这也解释了为什么这一条必须自己写。

## 3. 边界：一个 napi crate + 一层薄包装

新增 workspace 包 `packages/mls`：

1. **一个 napi-rs crate**（`cdylib`），依赖 `anp`，**非默认 features**（见 §5 第 4 条）。
   官方那个 crate 自己是 `rlib`-only，所以**不用改它、也不用 fork**——我们的 crate 是那个
   `cdylib`。
2. **一层薄 TS 包装**：`openMlsStore({path, deviceKey})` 拿一个句柄，然后每个操作一个方法。
3. **CLI 的 `group e2ee` 子族**，形状照 `group.ts` 的既有风格（那一族的文件头解释了"一个群一个
   Group DID、五步发现"为什么让它自成一族）。
4. **owner 的编排**（§11.12）：观察 P4 状态变化 → 生成 MLS 结果 → 调 `group.e2ee.*`。
   [e2ee-group.md](e2ee-group.md) §2 说清了这是**客户端**的活——服务端既不替 owner 观察，也不
   替它触发。

**数据边界是一条**：**JSON 进、JSON 出**。crate 的 v2 模型本来就是 serde 结构
（`V2GroupCreateBody` / `V2GroupAddBody` / `V2GroupCipherObject` / …），TS 侧直接把它们塞进
`group.e2ee.*` 的 `body`，**不重新建模一遍**。这样这一层的厚度就是它可以有的最小厚度：TS 不理解
MLS，只搬运。

`packages/core` 保持纯 TS。native 模块不进它，更不进 `packages/service`——那两处今天都能在没有
任何原生依赖的前提下 `npm test`，这个性质要保住。

## 4. 第一阶段范围

目标：**一台设备能建群、加人、发、收、处理 welcome/commit，走真服务**。

1. `packages/mls`：napi crate + TS 包装 + 一句说明"为什么这块必须内嵌"的文件头。
2. pin 一个明确的 `anp` 版本，非默认 features，`mls` 必需（§8）。
3. store 落在 `CONNECTX_HOME/<agent>/<profile>/mls/`，与 keystore 同级——`identity/paths.ts`
   已经定义了"一个身份的状态放哪"，MLS 状态跟着它走，不另起一套。
4. CLI：`group e2ee` 子族，至少 key-package / create / add / remove / send 五条。
5. e2e：`packages/e2e` 里**两台真客户端 + 一台真服务**，跑通 create → add → send → 收。
   这一步同时是服务端 P6 的第一条真验收路径（§1）。

**不做**（与 [e2ee-group.md](e2ee-group.md) §12 那张表同源，那边是 Host 不做、这边是客户端
不做）：`External Commit`、`update` 作为协议级动作、同 DID 的 remove 分支、多控制者、任何 P6
历史拉取。

## 5. 四处坑，现在就得说

1. **构建成本。** `rusqlite` 是 `bundled`——每次构建编一份 SQLite 的 C 源。加上 Rust 工具链与
   `rust-toolchain.toml` 钉的版本，等于给一个**今天一个 Rust 文件都没有**的仓库引入第二套构建。
2. **发版面。** `connectx` 是 `bin` 包（`tsup`，ESM-only，`@agentx/core` 保持 external）。加了
   native 依赖之后，发布就从"一个包"变成"一个包 + 每平台预编译产物"——napi-rs 的标准做法是按
   平台走 `optionalDependencies`，那是一套新的 CI 矩阵。`tsup` 也要把 `.node` 标成 external。
3. **同步阻塞。** crate 的 `group_e2ee` 全是**同步**的 rusqlite + fs2。napi 侧必须包成
   `AsyncTask`（或 `spawn_blocking`），否则会卡住 CLI 的事件循环——`msg listen` 是长驻的，
   那正是它最不能卡的地方。
4. **依赖面比想象的大。** `anp` 的默认 features 含 `network`，会把 `tokio` + `reqwest` 一起拖
   进来（`group_e2ee` 自己一个都不用，是网络模块用的）。所以第一个动作就是**用
   `default-features = false, features = ["mls"]` 构建**，并且确认它编得过。另外
   `generate_key_package_v2` 要**单独**收一把 `&PrivateKeyMaterial`（其余操作不收私钥，钥存在
   sqlite 里）——所以包装层要能把这把钥交进去，而不是让 crate 自己去读文件。

## 6. 两个闸门，别混成一个

- **广告闸门**：P6 不得进 `anp.get_capabilities`，直到 MLS 的 `anp_did_wba_device_binding`
  `ExtensionType` 有稳定注册 code point。落在 `capabilities.ts` 的 `WITHHELD_PROFILES`，
  [TODO4.md](../../TODO4.md) `B1` 管着。
- **代码闸门**：上游把这件事做成了**运行时**开关。`0xF0A1` 那个常量是编译期的
  （`DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED_V2 = false`），但 v2 的**每个操作**都收一个
  `draft_extension_negotiated: bool`，传 true 就能跑。

**两个闸门互相独立**：库今天就能写、能跑、能测，只是不能对外声明。所以"什么时候开"**不是一个
全有全无的问题**——这正是 §7 那条建议成立的原因。

## 7. 建议：现在开，但只开到"能跑 e2e"为止

**建议现在就开第一阶段，把发版面留到广告闸门打开之后。** 三条理由：

1. **库在关键路径上，但不依赖那个 code point。** code point 决定的是"能不能对外声明"，不是
   "能不能本地跑"——上游自己就是这么切的（运行时 flag）。
2. **服务端 P6 需要它。** 571 行受理逻辑目前只有合成输入。真客户端一接上，等于补上唯一缺的那条
   验收路径。这与 [TODO4.md](../../TODO4.md) §A3 是同一手：**同族问题上，把 stub 换成真东西
   立刻暴露了一批只有真链路才看得见的问题**。
3. **发版面可以后置。** §5 第 2 条那套预编译矩阵只在 P6 真要发的时候才需要；在那之前，开发机 +
   CI 上编一份就够。

**等着开的代价也写清楚**：服务端 P6 继续只有合成输入，而 MLS 那半边——最容易出错的那一半——
到真开工时才开始积累。

## 8. 动手前必须先做的三件事

1. **fetch。** 本机 `/Users/eccstartup/code/github/anp` 停在 **0.9.0**、落后 origin/master
   **93 个提交**；而 crates.io 上 `anp` 已经是 **1.0.5**（2026-09-24）。本文 §2 的函数名是在那
   份 0.9.0 检出上核的。
2. **在 1.x 上重核签名。** docs.rs 确认 1.0.5 里 `group_e2ee` / `operations` / `storage` 都还在
   （`operations` 的描述是 "Real OpenMLS group E2EE operations"，仍挂在 `mls` feature 后），
   1.x 还多了 `v2_origin`、`sealed_handoff` 与 update/recover 那几个模型。**但 §2 那张表的函数
   签名必须在 pin 定的版本上逐个核一遍再动手。**
3. **定 pin。** 选一个明确版本写进 crate 的 `Cargo.toml` 与 README。注意这与 `awiki-open-server`
   钉 `anp==1.0.3`（Python）**没有关系**：两边不共享进程，也不共享 crate 版本——线上那条约定
   是 Profile，不是 SDK 版本。
