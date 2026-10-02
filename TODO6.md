# TODO6 —— 文档与测试

[`TODO5.md`](TODO5.md) 把 Rust 客户端从零写到六族 24 条 + `did publish` / `me`。
这份是它之后的一轮，范围由用户 2026-10-02 定：

> 我希望你把这个 phase 3 做完了之后，写一个 TODO6，把**文档的更新**，以及**软件的测试**也写进去。
> **至少我要能跑通吧。**

两个词就是全部范围：**文档**、**跑通**。所以这份**不列还剩哪些命令要写**——那是 TODO5 §6
Phase 2/4 的事，这里只做索引（§5）。它答两个问题：

1. 一个没碰过这个仓库的人，照着**哪一页**能把 `agentx-cli` 跑起来？
2. 怎么知道它**没有偷偷坏掉**？

`~~划掉~~` / `- [x]` 同样表示做完。

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

**一句话**：文档描述的是一个**冻结的**二进制，而在动的那个只有一份 README。
这就是"至少我要能跑通"今天卡住的地方——不是跑不起来，是**没人能从文档里知道怎么跑**。

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

- [ ] **§2.1 的裁定落成一句话**，写在 `docs/design/cli.md` 开头：这个仓库的 CLI 是哪个二进制，
      另一个是什么状态。**先做这条**，它是其余各条的前置。
- [ ] `rust/README.md` 的**命令面一节**升级成参考页级别的逐条说明
      （今天它是散文，缺"每个旗标的默认值"与"失败时说什么"）。
- [ ] `vercel/reference/cli.md` 与 `vercel/en/reference/cli.md`：按 2.1 的裁定改写，
      并**同时改 `see` 指向的那批页面**（`cli.md` §3 记的门禁只管"链接还活着"，
      不管内容一致——所以这条是人手的活，别指望门禁替你发现）。
- [ ] `skill/connectx/SKILL.md`：按 2.1 改名/重写，并**把 `help.test.ts` 的门禁跟着改**
      （它拿 skill 里逐字给出的调用去和命令面对账，命令面变了它就该红）。
- [ ] `docs/design/cli.md` §8 的存储布局：现在是 `~/.connectx/` + `key.json`（keystore V3），
      与 Rust 的 `~/.agentx-cli/<agent>/<profile>/{identity.json,session.json}` **不同**。
      要么写两段，要么写一段并把差异点名。
- [ ] **`did publish` 与 `me` 还没有任何用户文档。** 它们不在 `cli.md` §3 的命令面里
      （那节列的是 `connectx`），也不在文档站上。这是本次新增的两个命令，文档要跟上。
- [ ] `TODO5.md` §6 里那些"端到端跑过"的记录**是历史，不是说明**。参考页要能独立站住，
      不能要求读者先去读一份 TODO。

---

## 3. 测试

### 3.1 "跑通"分三档，别把它们混成一句

| 档 | 含义 | 今天 |
| --- | --- | --- |
| **一** | 单测全绿 | ✅ 132 个 |
| **二** | 一个人照文档能手工跑完一条链路 | ⚠️ 能跑，但配方只存在于本次对话和 TODO5 §6 的散文里 |
| **三** | **一条命令**跑完全链路，并且 CI 每次 push 都跑 | ❌ 没有 |

用户那句"至少我要能跑通吧"要的是**二**，但只有做到**三**，二才不会随时间烂掉
（文档里的手工步骤是最先过时的那一类东西）。

### 3.2 卡在哪：本仓库没有 DID host

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

### 3.3 计划

- [ ] **进 CI 的最小一步：`cargo test` + `cargo clippy`。** 与 3.2 无关，可以立刻做。
      今天 Rust 这边**完全不在门禁里**，改坏了没有任何东西会红。
      （`cargo fmt --check` **不要**加：这个仓库没有 `rustfmt.toml` 且是手写格式，
      `examples/phase0_key_package.rs` 今天就不过——加上去等于加一个假门禁。
      clippy 现有的 `needless_question_mark`（`message/client.rs:13`）要么修要么 allow，
      别让它变成"反正本来就有一个警告"。）
- [ ] **一个可复跑的 e2e 配方**（先是一份 `scripts/e2e.sh`，不是测试框架）：
      起 host → 起 service → 走完整条链路 → 断言。今天这条链路是**手工走过一遍**的
      （见 §4），把它写成脚本的第一版就是把 §3.1 第二档钉住。
- [ ] **把配方升成 `rust/crates/agentx-cli/tests/` 里的集成测试**，读 `AGENTXCLI_HOME`
      指向的临时目录，自己起服务、自己收尾。这一步之后第三档才成立。
- [ ] **覆盖要跟命令面走，不是跟"写过的测试"走。** 132 个单测长在库侧
      （身份存储、JCS 哈希、会话缓存、策略、信封），**命令面一层几乎没有测试**。
      `did publish` 的三个分支（未变 / 变了 / 没有 token）今天只在手工验证里出现过。
- [ ] **负结果的测试值得单列。** 这个客户端的正确行为里有好几条"对端不支持时应该怎样"
      （`msg inbox` 一族对 awiki 回 `-32601` 是**正确**结果，`cli.md` §5）。
      这类断言最容易在重构里被悄悄改成"跳过"，要有测试咬住。

---

## 4. 今天手工跑通的那条链路（写进脚本的原料）

2026-10-02 实跑过一遍，命令与观察到的输出如下。这是 §3.3 第二档的直接原料。

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
**它们同样没有脚本**——这是 §3.3 那份 `scripts/e2e.sh` 要一并收的。

---

## 5. 不在这一轮范围里的（TODO5 §6 的索引）

| 事项 | 在哪 |
| --- | --- |
| Phase 2：本地消息库 `messages.db` + 游标 + 与 `mls/` 的分工 | TODO5 §4、§6 Phase 2 |
| Phase 4：命令面定稿、TS CLI 冻结在某个版本 | TODO5 §6 Phase 4、§8-I |
| `packages/e2e` 对 TS 客户端的既有覆盖 | 不动；§3.2 只讨论新客户端的入口 |

**"换设备"不在这里，也不在任何一个人的待办里**：本机 awiki host 对改设备清单回
`device_enrollment_or_removal_not_supported` / `device_key_or_root_change_not_supported`，
`replace_did` 回 `not_supported`，客户端没有路可走（TODO5 §6）。记在这里是为了别有人
把它当缺口重新发现一遍。

---

## 6. 这一轮做完的样子

- 一个没碰过仓库的人，从 `rust/README.md` 或文档站的 CLI 页出发，**不需要读 TODO** 就能：
  起 host、`did create`、`did publish`、`me set/show`、`msg send`、`msg listen`、
  `group create` —— 并且知道每一条失败时会看到什么。
- `cargo test` 与 `cargo clippy` 在 CI 里；Rust 这边改坏会红。
- 一条命令跑完整链路，并且在 CI 里跑。
- 文档描述的是**在动的那个二进制**，冻结的那个标着冻结。
