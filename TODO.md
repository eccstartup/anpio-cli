# TODO

2026-10-26：`TODO1.md`–`TODO7.md` 七本流水台账合并成这一份。做完的条目随那七本一起删掉，
历史留在 git 里（`git log --all -- TODO1.md`）。这里只留**仍然开着**的事，按「卡在谁那儿」
分三栏——本仓库自己能做的、等人裁定的、等上游或前置条件的。

---

## 1. 本仓库自己能做

### 1.1 逐跳 SSRF 策略缺 DNS 那一半

`assert_allowed_host`（`rust/crates/anpio-cli/src/message/resolve.rs:281`）只拒**字面**私网
IP。主机名解析到私网地址照样过——LAN 名字、DNS rebinding 记录都在这一侧。TS 客户端当年靠
`node:dns` 补这半边，Rust 这边没带解析器就没有那道判断。而消息端点的主机名是**对端选的**，
比 DID 主机那一跳更需要它。允许列表仍然限住了「能去哪」，缺的是「这个名字指向哪」。

### 1.2 MLS owner 编排

Rust 客户端只有**设备半边**：MLS store、`create` / `add` / `remove` / `send`、以及收包解密。
缺的是观察 P4 状态变化（`group.state_changed`）再驱动 `group.e2ee.*` 的那一层。今天这一帧
在 `GroupReceiver::apply`（`rust/crates/anpio-cli/src/group_receive.rs:151`）里落到
`Ok(None)` 的兜底，等于丢掉。设计见 [client-mls.md](docs/design/client-mls.md)。

### 1.3 发布面

`anpio-cli` 是按平台发的原生二进制，但仓库里只有 CI（typecheck / test / e2e）：没有交叉编译
矩阵、没有产物签名、没有升级路径。

### 1.4 core 分裂的一致性

同一批协议原语在 TS `packages/core` 与 Rust 客户端各一份，都要跟 ANP 演进。今天靠「同一份
规范 + 两边各自的测试」对齐，没有把两份实现钉在一起的对照机制。

### 1.5 验签玩具 DID 主机

`scripts/e2e/did_host.py` **明写不验签**（文件头与 `handle_update` 的 docstring）：它只按 DID
存、按 DID 发，签名对不对交给读链的人。于是 e2e 咬不住「客户端签名错了」这一类缺陷。需要一台
**会验签**的玩具主机专门咬这一点——它独立成立，不与别的待办合并。

### 1.6 命令面覆盖率

单测仍长在库侧，命令面与拒绝分支的自动化覆盖偏薄。裁定不变：脚本 + CI 是第三档的载体，不造
`#[ignore]` 影子入口。用户 2026-10-03 说「以后再说」。

### 1.7 本机 `anp` 检出

开发机上的 `anp` 检出还停在 0.9.0 线，没 fetch 到最新、也没重核 1.0.5 的签名与函数面。
只影响开发环境，动 SDK 之前要先做。

---

## 2. 等人裁定

### 2.1 群里「我的昵称」

协议里没有 per-membership 昵称（`group_profile.display_name` 是**群**的名字，
`schema.ts:515`/`:532` 也写明没有 `nickname` 列）。要么存本地表，要么提一个 Profile 扩展。
用户 2026-10-02 裁定「以后做」——这条要留住：悬着的结果就是各客户端各存各的、互不可见。

### 2.2 附件命令面

要不要给 `anpio-cli` 加发附件的命令（发送 + 下载）。消息面 / 控制面 / 数据面在服务端与
core 里都有，`rust/crates/anpio-cli/src` 里没有这一族命令（见
[attachments.md](docs/design/attachments.md) §11）。

### 2.3 v2 请求的调用方身份

`publish_prekey_bundle` / `get_prekey_bundle` / `direct.send` 三处共用同一套身份判定，所以要
一次做完：要么引入**设备级会话**（连接上先证明设备私钥，后续请求据此认人），要么把「自报
身份」写进部署假设。在那之前，服务端对 P5 的受理只保证资格、不保证来源
（[e2ee-direct.md](docs/design/e2ee-direct.md) §9 第 3 条）。

### 2.4 `packages/service` 当自己的 DID host

「本仓库的服务能不能同时托管自己的 DID 文档（声明一份它并不持有的身份文档）」——乙案没被
否决，只是没选（2026-10-02 选了甲案：e2e 自带玩具主机）。语义裁定至今没做。

---

## 3. 等上游 / 前置条件

### 3.1 P6 广告闸门

`anp.get_capabilities` 继续扣留 `anp.group.e2ee.v2`（`packages/service/src/capabilities.ts:42`
的 `WITHHELD_PROFILES`），等上游公布稳定的 MLS `ExtensionType 0xF0A1` codepoint。公布之后删掉
那一项即可，方法表不用改；`capabilities.test.ts` 钉住的正是「这份清单被改动」这件事。

### 3.2 真实跨域部署前提

两件事缺一不可：`ANPIOCLI_PUBLIC_URL` 要是 https（`didToUrl` 对 `did:web` 恒给 https，本地
默认是 http），对端域要进 `ANPIOCLI_ALLOWED_DID_HOSTS`（默认空，
`packages/service/src/config.ts:257`）。缺任一件，跨域联邦在真实域名上跑不起来。

### 3.3 anpio-key 适配：端到端与 golden 对照

客户端侧阶段 1 已落地（`SenderKey::{Local, AnpioKey}`、grant 续期、受保护入口），但「两台机、
两个托管身份，私聊 + 群聊 + contacts」与「同一 SRO 在本地钥与 daemon 下产出逐字节相同的
origin proof」都没跑过——卡在 anpio-key 还没有发布版。见
[anpio-key-integration.md](docs/design/anpio-key-integration.md) §5 阶段 1、§10 的 1.3。

### 3.4 anpio-key 适配：阶段 2 / 4 / 5

- **阶段 2（P2）**：客户端侧已落地（2026-10-26）。`group e2ee` 的 KeyPackage 绑定与
  `send` 的设备 origin proof 都改为 `SIGN_PURPOSE(device_assertion)` 由 daemon 签，
  `--device` 映射文档里的设备名并核对 `public_multibase`；custody 的六条数据面操作都有
  适配层，拒绝按形态分类。**还差**：anpio-key 的 v2 面没有发布版，所以
  `publish → get-key-package → create → add → send` 全链路没有真守护进程跑过。
- **阶段 4（P4）**：attach 接受并映射四类键（`key-1` / `hot` / `{device}-sign` /
  `{device}-agreement`），等 daemon 的管理面导入。验收：换台机器只用 24 词助记词恢复，
  登录 / 发消息 / 建会话三条路都通。
- **阶段 5（P5）**：`did update` 在托管身份上的**拒绝已经落地**并点名管理面
  （`main.rs:2618` 起）；等 anpio-key 管理面出 successorship 之后再接真实迁移。
- **`SIGN_HTTP` 搬进受保护面**：受保护面只收 `https://` + DNS 主机名，本机的
  `http://localhost` 登录没有条件；有 https 的 DID 主机可验收时再搬（见设计文档 §4.3）。

守护进程侧仍然开着的账在 anpio-key 仓库的 `TODO.md` 里（P1/P2/P3 收尾、P4、P5、macOS SE 正式
分发、物理 TPM、无人值守恢复、challenge 格式），不在这里重复。
