# anpio-key 强对接计划

> 2026-10-26。本文是**计划**，不是现状：今天什么能用、什么被拒，以
> [cli.md §7](cli.md#7-私钥的两种归属) 和 `anpio-cli --help` 为准。
> 对端的冻结契约在 anpio-key 的
> [`docs/ADAPTER.md`](https://github.com/open-agentx/anpio-key/blob/main/docs/ADAPTER.md) §11；
> 本文只写**这个仓库**怎么接、按什么顺序接、每一步拿什么验收。

## 0. 一句话

同一份身份有两条私钥归属：

- **自托管**：`did create` 把私钥写进本机 store。今天全部命令可用，安全性较低。
- **anpio-key 托管**：`did attach-anpio-key` 只留下公开引用，签名委托给本地守护进程。
  store 里没有私钥字节，但能力要按守护进程的 P1–P5 分期补齐。

这份计划把第二条从「只能签整条 HTTP 请求」推到「身份 / 私聊 / 群聊 / 群 E2EE 全通」，
`did update` 放最后；第一条保持原样，并且**永远不作为降级路径**。

---

## 1. 两种归属，两份合同

### 1.1 自托管（今天的默认）

`identity.json` 内联 PEM：`key-1`（Ed25519）、`{device}-sign`（Ed25519）、
`{device}-agreement`（X25519），由 `write_private` 以 0600 写入
（[store.rs:420](../../rust/crates/anpio-cli/src/identity/store.rs#L420)）。

- 任何以该用户身份运行的进程都能读；没有策略、没有授权、没有审计；换机靠拷贝文件。
- 好处是零外部依赖，全部命令今天可用。
- 它并非「不安全所以不用」，而是**威胁模型不同**：本机与账号已被信任时够用；
  要防同机其他进程、防备份泄漏、防被委托的 agent 越权时，才需要第二条。

### 1.2 anpio-key 托管

store 里只有公开文档、keyid 与授权引用；签名经本地守护进程完成。

**「托管」本身不等于隔离。** anpio-key 有两条接入面：

| 接入面 | 形态 | 它实际给到的边界 |
| --- | --- | --- |
| 开发 socket | `--root` / `--socket`，今天的 `sign` / `document` | 私钥不出进程；**同 UID 的其他进程也能驱动签名**，没有策略/授权/审计 |
| 受保护 v2 | `data --config` + 独立 Agent UID + grant + 审计 | 策略、逐操作授权、次数/期限、审计、根钥只在管理面 |

本文的「强对接」只指第二条。在开发 socket 上把命令打通然后宣称受保护，是这一轮最容易犯的错。

### 1.3 三条硬规矩

1. **不降级。** 托管身份在 daemon 不可用、被锁定、grant 过期时失败，**绝不**回落到本地钥、
   开发 socket 或 raw 签名。错误要说清是哪一种。
2. **不搬钥。** CLI 不提供「托管身份转自托管」的命令；反向也不提供。迁入走 anpio-key 管理面
   （`import-mnemonic` / `import-archive`），CLI 只负责 `did attach-anpio-key`。
3. **模式可见。** `did show` / `did list --json` 必须打印归属与**协商到的操作集**，
   让「这条命令为什么会被拒」在动手前就能看见，而不是发到一半才失败。

---

## 2. 今天的边界（2026-10-26 量出来的）

`Custody::refuse` 只有三处调用，覆盖三族命令：

| 位置 | 拒的命令 |
| --- | --- |
| [message/channel.rs:248](../../rust/crates/anpio-cli/src/message/channel.rs#L248) | `msg send`，以及一切走 `Sender::from_identity` 的 `msg` / `contacts` / `group` 调用 |
| [mls.rs:100](../../rust/crates/anpio-cli/src/mls.rs#L100) | `group e2ee`（`device_signing_key` 拿不到设备钥） |
| [main.rs:2509](../../rust/crates/anpio-cli/src/main.rs#L2509) | `did update`（要铸后继钥，且退役文档由 key-1 签） |

能用的只有走 `Signer::AnpioKey` 的 ANP-02 路径：`anp sign` / `anp login` / `did register`，
以及不签名的 `did show` / `anp show` / `me`；`did publish` 直接用守护进程发布的
已签名文档（[main.rs:2165](../../rust/crates/anpio-cli/src/main.rs#L2165)）。

两件容易漏掉的事实：

- **今天走的是开发 socket，不是受保护 v2。** `custody.rs` 调 `anpio-key sign --did …`
  / `anpio-key document --did …`，不读 `service.json`，不带 grant、request_id，也不查审计。
  ADAPTER §3.1 的受保护入口是 `data --config`。强对接必须换入口，否则「托管」只兑现了
  「私钥不落盘」这一半。
- **身份记录里只有 `root` / `socket` / `kid`。** 没有 config、grant、设备绑定、操作集
  （[custody.rs:36](../../rust/crates/anpio-cli/src/custody.rs#L36)）。这些都得在阶段 0 补进
  `Custody::AnpioKey`，并保证老 `identity.json` 还能读（serde default）。

---

## 3. 每个证明点 → 守护进程操作

ANP 的每一种证明都要落到一个具体操作上；下表是这个仓库的全部签名点。

| 证明点 | 代码 | 签的字节 | 键 | 今天 | 目标操作 / 阶段 |
| --- | --- | --- | --- | --- | --- |
| ANP-02 登录、注册 | `anp/request.rs` `Signer::sign_headers` | 整条 HTTP 请求（RFC 9421） | `hot` | 可用（开发 socket） | `SIGN_HTTP`（v2 入口） |
| 每次 `msg` / `contacts` / `group` 调用 | [channel.rs:371](../../rust/crates/anpio-cli/src/message/channel.rs#L371) `sign_request` | ANP origin proof：`JCS({method, meta, body})` 的 digest，签名基覆盖 `@method` / `@target-uri` / `content-digest`，target 是 `anp:{agent\|group\|service}:{did}` | `key-1` → `hot` | 拒 | `SIGN_ORIGIN_PROOF`，**P1** |
| `msg listen` 握手 | `message/listen.rs`（复用 `sign_request`） | 同上 | `hot` | 拒 | 同上，**P1** |
| `group e2ee send` 的 origin proof | [main.rs:4901](../../rust/crates/anpio-cli/src/main.rs#L4901) `signing_as_device` | 同上 | `{device}-sign` → `device_signing` | 拒 | `SIGN_ORIGIN_PROOF`（需角色扩展）或 `SIGN_PURPOSE` 退路，**P2** |
| KeyPackage 的 `did_wba_binding` | `mls.rs` `generate_key_package`；anp crate 有 `prepare_key_package_v2` / `complete_key_package_v2` 接缝 | `prepared.signing_input()` | `{device}-sign` | 拒 | `SIGN_PURPOSE`（purpose 绑设备断言），**P2** |
| MLS commit / 消息加解密 | anp crate，MLS store 自持 | MLS 自己的签名与 ratchet 钥 | 本地 MLS store | 可用（但钥在本地） | **不经过 daemon**，见 §5.3 |
| DID 文档 proof | `identity/did.rs:352` `resign_document` | W3C Data Integrity over 文档 | `key-1` → `root` | `did publish` 用守护进程的已签文档；`did update` 拒 | `SIGN_DOCUMENT_PROOF`，**P5** |
| 后继钥铸造 | `cmd_did_update` | 无（生成新钥） | 新 `key-1` | 拒 | 管理面扩展，见 §4.4 |

注意 ANP origin proof 的签名基（`anp` crate `prepare_rfc9421_origin_proof`）是
**对 `{method, meta, body}` 的 JCS 规范化**，不是对传输层 HTTP 请求头。这决定了 §4.1
的接口缺口。

---

## 4. 对 anpio-key 的请求（P1 前必须定稿）

这五条不解决，本仓库无法在不削弱边界的前提下接上。前三条是**契约**，后两条是**接口面**。

### 4.1 `SIGN_ORIGIN_PROOF` 的输入形状

ADAPTER §11.3 冻结的 `origin` 是 `{method,url,headers,body,nonce}`（与 `http` 同形）。
ANP origin proof 真正要签的是：

```text
content-digest = sha-256(JCS({method, meta, body}))
base           = "@method" · "@target-uri" · "content-digest"
@target-uri    = anp:{agent|group|service}:{did}     // 由 meta.target 推导
```

`meta` 在这个形状里没有位置。两种收口方式：

- **推荐**：把 `origin` 改成 `{method, meta, body, nonce?}`，由 daemon 自己做 JCS 与
  `@target-uri` 推导。调用方只给事实，签名基仍由 daemon 拼，和 §11.3 的原则一致。
- 退路：保留 `{method,url,headers,body,nonce}`，规定 `url` 是 logical target、
  `body` 是**已规范化的 SRO 字节**。签名结果相同，但 JCS 由客户端做，边界弱一档；
  若走这条，要在 ADAPTER 里写死「body 必须是 JCS 输出，daemon 不重新规范化」。

### 4.2 `SIGN_ORIGIN_PROOF` 的角色

§11.5 的放行表只允许 `hot`。但 `group e2ee send` 的 origin proof 必须由
`device_signing` 键签（P6 §13.3 item 6，服务端拿它对照文档的 `signing_key_id`）。

建议把该行改成 `hot` + `device_signing`：grant 已经绑定具体 `key_id`，而
`SIGN_ORIGIN_PROOF` 不是任意字节 oracle（基由 daemon 拼），风险与 `hot` 同阶。
若不改，退路是 `SIGN_PURPOSE`（purpose=`mls-origin-proof`，payload 是
`prepare_rfc9421_origin_proof` 的输出），但那意味着设备钥对调用方选的字节签名，
只能在 P2 里作为降级方案记录。

### 4.3 受保护入口与固定参数

强对接要用 v2 `data --config`（或 §11.1 说的同名 v2 子命令），不能继续走开发 socket。
同时 §11.8 要求 `custody.rs` 的 config / socket / did / kid **由管理员固定、不接受调用方覆盖**，
因此：

- `Custody::AnpioKey` 在 attach 时记下 `config`，之后**没有**命令级旗标能改它；
- 受保护模式下不读 `$ANPIOCLI_ANPIO_KEY`（今天是二进制路径覆盖，等于一个绕过口）；
- 需要一个新的只读子命令让 CLI 拿到 `GET_CAPABILITIES` 的 `operations` / `purposes` /
  `grant_kinds`，以及 `GET_GRANT_STATUS` 的期限/余量。

### 4.4 `did update` 缺的不是签名，是「铸钥」

ANP-03 的一跳 = **铸一个后继 `key-1`** + **用旧 `key-1` 签退役文档**。在托管身份上：

- 后继钥若由 CLI 铸，私钥就回到了 store，托管当场破功；
- `SIGN_DOCUMENT_PROOF` 的 grant 只能由管理面签发（§11.7），数据面没有 root 授权；
- §11 没有任何「在 daemon 内铸后继钥」的操作。

所以在 §11 的现有形状下，`did update` 在托管身份上**应继续拒绝**。要打通，需要 anpio-key
管理面新增一个 ANP-03 successorship 操作（铸钥 + 签退役文档 + 返回公开后继），由人在管理面执行。
本文不假设它存在；P5 只到「记录这个缺口」。

### 4.5 设备身份的映射

CLI 的 `device_id` 是本地槽位（`agent/profile`），DID 文档里的设备清单是管理员登记的名字
（`{device}-sign` / `{device}-agreement`，见
[identity/did.rs:410](../../rust/crates/anpio-cli/src/identity/did.rs#L410)）。P2 之前必须定下：

- `did attach-anpio-key --device <id>`：显式给出文档里的设备名；
- 从 `GET_DOCUMENT` 的设备清单里取 `signing_key_id` / `e2ee_key_id`，映射到 daemon 的
  `device_signing` / `key_agreement` 键；
- 找不到就拒 `group e2ee`，不要猜一个 `{agent}/{profile}` 拼出来的名字。

---

## 5. 分期

阶段的编号跟着 anpio-key 的 P1–P5 走；每个阶段在本仓库都能独立验收。

### 阶段 0 —— 能力协商的骨架（不依赖守护进程新能力）

**做什么**

- `Custody::AnpioKey` 增加可选字段：`config`、`grant`、`device`、`operations`（缓存）。
  全部 serde default，老身份文件照读。
- `Custody::refuse` 改成 `Custody::supports(op)` + `Custody::denied(op)`：
  先看协商到的操作集，再说「daemon 没宣告这个操作」还是「宣告了但没有 grant / 被锁定」。
- `did show` / `did list --json` 打印 `custody` 与操作集；人读输出加一行
  `signs: http, origin-proof, purpose (device-sign)`。
- 查询能力只在缓存缺所需操作时发生，避免每条命令多一次子进程调用。

**验收**

- 老 `identity.json` 能读；现有 Rust 测试全过；
- 拒绝仍发生在**联网之前**，错误里点名缺的操作与对端的实际宣告；
- 自托管身份的行为逐字节不变。

> **状态（2026-10-26）：已落地。** 受保护入口 `invoke_protected` 已经能用，但还没有命令
> 走到它：`config` / `grant` / `device` 只作为身份文件里的字段存在，attach 的旗标留到 1.2。
> 在那之前，托管身份的能力集来自缓存或开发 socket 的基线（只宣告 `SIGN_HTTP`），
> 拒绝文案会如实说「本 build 还没把 X 交给 daemon」。

### 阶段 1 —— 通信全开（anpio-key P1）

**守护进程**：`SIGN_ORIGIN_PROOF`、`RENEW_GRANT`、`GET_CAPABILITIES` 的四个字段、
session grant、策略 `schema_version: 2`、每条新签名路的独立开关与审计。

**本仓库**

- `Sender` 从 `PrivateKeyMaterial` 扩成 `SenderKey::{Local, AnpioKey}`；
  `sign_request` 保持同步接口，daemon 调用仍是子进程。
- 请求日志：签名前把 `{request_id, method, operation_id}` 落到身份目录，
  重试复用同一个 `request_id`；拿到确定答复后删除。`REQUEST_ID_CONFLICT` 是停止信号，
  不换 ID 重签（ADAPTER §8）。
- grant 生命周期：长命令（`msg listen`）开始前查 `GET_GRANT_STATUS`；余量/期限不足时
  按 `RENEW_GRANT` 续，续不到就把「需要管理员做什么」写进错误。
- 解锁的命令：`msg send` / `inbox` / `read` / `show` / `fetch` / `listen`，
  `contacts` 全族，`group create` / `info` / `members` / `join` / `leave` / `send` /
  `update-profile` / `set-remark`。
- 本地读（`msg inbox` / `history` / `show` / `read`）继续不联网，不受 custody 影响。

**验收**

- 真服务上跑通「两台机、两个托管身份、私聊 + 群聊 + contacts」；
- 同一 SRO 在本地钥与 daemon 下产出**逐字节相同**的 origin proof（golden 对照）；
- daemon 停掉 / 锁定 / grant 耗尽：失败且不降级，错误可分流；
- store 里没有任何私钥字节（沿用 `no_key_material_on_disk` 的思路）。

### 阶段 2 —— 群端到端加密（anpio-key P2）

**守护进程**：`device_signing` 角色与专用键、`SIGN_PURPOSE`（每 purpose 一把键、一个开关）、
`purpose-signing` 策略，以及 §4.2 的角色决议。

**本仓库**

- `did attach-anpio-key --device <id>` + 文档设备清单映射（§4.5）。
- `group e2ee publish`：改用 `prepare_key_package_v2` + `SIGN_PURPOSE` +
  `complete_key_package_v2`；完成后校验返回的 `public_multibase` 等于文档里的设备签名键。
- `group e2ee send`：设备钥签 origin proof（若 §4.2 按建议放行），否则走
  `SIGN_PURPOSE` 退路；两条路都保留「签名者 keyid == 文档 `signing_key_id`」的检查。
- `create` / `add` / `remove` 在 P1 已可用（key-1 origin proof）；本阶段不动。
- **MLS ratchet 钥继续留在本地 store**。它是会话状态，不是身份钥；把它也搬进 daemon
  是另一个量级的工程，且当前 §11 没有任何 MLS 操作。这一点必须在文档里写明，
  不能让读者以为「托管身份 = 端到端加密钥也托管」。

**验收**

- publish → get-key-package → create → add → send 全链路；
- KeyPackage 的绑定签名由文档里的设备钥验证通过；
- store 中不存在 `{device}-sign` 的私钥字节。

### 阶段 3 —— ECDH / secure-direct（anpio-key P3）

**本仓库今天没有 secure-direct 客户端**（只有 `docs/design/e2ee-direct.md`）。
在客户端长出那条路之前，P3 不给这里解锁任何命令。本文把它列为**非目标**，
不为了「用上 ECDH」而先造一条客户端。

### 阶段 4 —— 助记词与四类密钥（anpio-key P4）

守护进程侧完成导入/派生；本仓库只做两件事：

- `did attach-anpio-key` 接受并映射四类键（`key-1` / `hot` / `{device}-sign` /
  `{device}-agreement`）；
- 文档写清：**托管身份的创建是管理员动作**（`keygen` / `publish` / `rotate-hot-key` /
  `import-mnemonic` 都要 TTY 或管理通道），CLI 不驱动管理面，也不读口令。
  流程是「管理员建好 → `did attach-anpio-key` 接管」。

**验收**：换一台机器，只用 24 词恢复 daemon，重新 attach，登录/发消息/建会话三条路都通。

### 阶段 5 —— DID 更新与根操作（anpio-key P5）

- `SIGN_DOCUMENT_PROOF` 可以让「签一份文档」落到 daemon，但 `did update` 还缺铸钥（§4.4）。
- 在管理面 successorship 出现之前，托管身份的 `did update` **保持拒绝**，错误里给出
  anpio-key 的管理面路径；`--resume` 同样拒绝（托管身份从不写 `successor.json`）。
- `did publish` 不受影响：它用守护进程发布的已签文档，本来就不在本地签。

**验收**：要么管理面操作落地并跑通一次真实 ANP-03 迁移，要么这条继续是明确的拒绝。

---

## 6. 验收矩阵

| 命令族 | 自托管 | 托管（今天） | 托管（目标） |
| --- | --- | --- | --- |
| `did show` / `anp show` / `me` | 可用 | 可用 | 可用 |
| `anp sign` / `anp login` / `did register` | 可用 | 可用（开发 socket） | 可用（v2 入口） |
| `did publish` | 可用 | 可用 | 可用 |
| `msg send` / `listen` / `fetch` | 可用 | 拒 | P1 |
| `msg inbox` / `history` / `show` / `read` | 可用 | 可用（纯本地） | 可用（纯本地） |
| `contacts` 全族 | 可用 | 拒 | P1 |
| `group create` / `join` / `leave` / `send` / `info` / `members` / 两个名字 | 可用 | 拒 | P1 |
| `group e2ee publish` / `send` | 可用 | 拒 | P2 |
| `group e2ee create` / `add` / `remove` | 可用 | 拒 | P1（origin proof 由 hot 签） |
| `did update` | 可用 | 拒 | P5 / 仍拒（见 §4.4） |

---

## 7. 安全取舍（写给人看的那张表）

| 威胁 | 自托管 | 托管·开发 socket | 托管·受保护 v2 |
| --- | --- | --- | --- |
| 同用户其他进程读私钥 | 能 | 不能 | 不能 |
| 同用户其他进程驱动签名 | 能 | 能（解锁期间） | 受 grant 限制 |
| 磁盘 / 备份泄漏 | 直接泄漏 PEM | 封装钥，视硬件绑定 | 同左 |
| 被委托的 agent 越权 | 无边界 | 无边界 | 只限 grant 里的键/操作/次数/期限 |
| 事后审计 | 无 | 开发日志，非受保护真源 | 受保护审计 + 独立采集 |
| 根钥使用 | 本进程 | 本进程（若持有） | 只在管理面，需在场 |
| 可用性 | 本机 | daemon 必须活着且解锁 | 同左，另需有效 grant |

两条容易误读的点，文档里要重复：

1. **托管 ≠ 一定更安全。** 开发 socket 只兑现「私钥不落盘」；同一 UID 的进程照样能驱动签名。
   只有受保护 v2 的 UID 分离 + grant + 审计才是完整的边界。
2. **托管 ≠ 连 MLS 状态一起托管。** 群 E2EE 的 ratchet 钥仍在本机 MLS store。

---

## 8. 不做的事

- 不加「签任意字节」的数据面操作（那等于放弃守护进程存在的理由）。
- 不导出种子 / 私钥；CLI 不读口令、不驱动管理面。
- 不做静默降级（本地钥、开发 socket、raw 都不作为 fallback）。
- 不为用上 P3 而新造 secure-direct 客户端。
- 不把 MLS store 迁进 daemon（除非另立一个计划）。
- 不在托管身份上实现 `did update`，直到 §4.4 的管理面缺口被补上。

---

## 9. 开放问题

1. §4.1 的 `SIGN_ORIGIN_PROOF` 形状选哪种？这决定 P1 能否在不弱化边界的前提下开始。
2. §4.2 的角色表是否放宽到 `device_signing`？不放宽就用 `SIGN_PURPOSE` 退路，
   并在审计里把这个差异标出来。
3. session grant 的默认寿命/次数由谁定：管理员预置的模板，还是 CLI 在 attach 时请求？
   本文倾向前者（策略里写死上限，CLI 只能续到上限）。
4. 请求日志放在身份目录还是单独文件？它含 operation_id 与 request_id，不含秘密，
   但必须与 grant 的生命周期一起清。
5. `did attach-anpio-key` 的开发/受保护两种入口，是互斥旗标还是两个子命令？
   本文倾向 `--config` 与 `--root/--socket` 互斥，避免一份身份同时指向两条面。

---

## 10. 在本仓库的落地顺序

按阶段拆成可单独提交的步子：

| 步 | 文件 | 内容 | 状态 |
| --- | --- | --- | --- |
| 0.1 | `custody.rs` | 扩 `AnpioKey` 字段；`capabilities()`；受保护入口 | 已落地 |
| 0.2 | `identity/store.rs` | `Custody::supports` / `denied`；`did show` / `list` 输出 | 已落地 |
| 1.1 | `message/channel.rs` | `SenderKey` 枚举；origin proof 走 daemon；请求日志 | 待守护进程 P1 |
| 1.2 | `main.rs` | attach 新旗标；grant 续期与错误分流；解锁命令清单 | 待 1.1 |
| 2.1 | `mls.rs` | KeyPackage prepare/complete；设备键映射 | 待 P2 |
| 2.2 | `main.rs` | `group e2ee send` 的设备钥路径 | 待 2.1 |
| 3.x | — | 非目标 | — |
| 4.1 | `main.rs` | attach 四类键的映射；文档流程 | 待 P4 |
| 5.1 | `main.rs` | `did update` 的拒绝文案指向管理面 | 待管理面操作 |
| 文档 | `docs/design/cli.md` §7、`rust/README.md`、`skill/`、文档站 | 行为落地后同批更新，不提前写 | 部分（§7 已链） |

每一步的测试都在该步落地：拒绝在联网前、老身份可读、命令行为与本地钥逐字节一致、
store 无私钥字节。
