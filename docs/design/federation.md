# 联邦与跨域（P8）—— 两层身份、一个 anchor、两条路

P8 不定义新方法（§3.1 L61–68：**SHOULD** 直接复用原业务方法，不新增 Relay 包装方法），
它规定的是**已有的那些方法在域与域之间怎么走**。本服务因此在同一个进程里坐着两个位置：
别人调我时的**接收侧**，和我替本地 agent 出站时的**发送侧**。

[message-service.md](message-service.md) §10 只有半页。这份写它背后的东西：
两层身份怎么分开、caller anchor 为什么只能有**一处**、以及一个在 C5b 就埋下、
直到读完 P8 才看得出来的结构性错误——**跨域私聊要转发的是原始 `direct.send`，不是
`direct.incoming`**。

## 1. 两层身份，一句都不许混

§3.6 L90–98 把跨域请求拆成两层，且说它们 **MUST NOT** 混淆：

| 层 | 谁 | 回答什么 | 载体 |
|---|---|---|---|
| 外层 HTTP | 发送方域的 `serviceDid` | **哪个域服务正在调用我** | `Signature-Input` / `keyid`（§6.2 L319） |
| 业务层 | `meta.sender_did` + `auth.origin_proof` | **哪个业务主体发起了该动作** | P1 附录 A |

两条推论，两条都是 MUST：

- 外层**不能**替代业务证明（§6.4 L435）：目标域服务 **MUST** 按业务 Profile 的要求
  独立验证 `origin_proof`。我们对 `direct.send` / `group.*` 照常走 C3，一条不省。
- 外层**不能**被改写成业务身份（§6.4 L437）：发送方域服务也 **MUST NOT** 把
  `auth.origin_proof` 重签成自己的 `serviceDid`。C5b 转发 proof 时逐字节不动，方向是对的。

对 `attachment.*` 是例外，但那条例外是 P7 给的、不是 P8 给的：§6.4 L439 明说它通常
没有终端业务证明，外层 hop 认证 **MUST NOT** 被误认成它。见 [attachments.md](attachments.md) §6。

## 2. 接收侧：caller anchor 只有一个函数

§6.2.2 L344 要求接收方**先按方法类型确定**「用于推导 caller `serviceDid` 的业务锚点」，
再走八步。锚点规则（L348–372）：

- 普通请求（`direct.send`、`group.*`、`direct.e2ee.*`、`group.e2ee.*`、`attachment.*`）
  → **`meta.sender_did`**（L368）
- `group.incoming` / `group.state_changed` / `group.e2ee.notice`
  → **`body.group_did`**（L370–372）

L387 那句「**MUST NOT** 一律从 `meta.sender_did` 推导」说的就是这件事：群通知的
「原始业务发送者」与「当前跨域调用者」是两个人，用前者去校验后者，攻击者在自己域里
建个 DID 就能冒充群。

**这个函数已经存在，就是 C3 的 `callerAnchor()`**（`rpc/auth.ts`）。C11 不许再写第二
处判断——同一个函数服务两次比较，比较对象不同：

| 用处 | 拿 anchor 去比什么 |
|---|---|
| 业务层（C3，已做） | `auth.origin_proof` 里 `keyid` 所属 DID **属于** anchor DID（P3 §11 的 2005/2006） |
| 外层（C11） | 外层 `keyid` 所属 DID **等于** anchor DID 公开服务条目的 `serviceDid` |

两处各写一遍判断，就回到了 §6.2.2 想防的那个洞。

### 2.1 八步落到本服务

| # | §6.2.2 L374–383 | 本服务 |
|---|---|---|
| 1 | 定 caller anchor | `callerAnchor()`，一处 |
| 2 | 按 P2 解析并验证 anchor 的当前文档 | `DidServiceLocator` / `DidKeyResolver`（A6） |
| 3 | 按 P2 选该 DID 对应的公开 `ANPMessageService` | 同上；解析不出服务条目 → 失败 |
| 4 | 读该服务条目的 `serviceDid` | 读；条目没有 `serviceDid` → 失败（L385） |
| 5 | 从外层 `Signature-Input` 取 `keyid` 的 DID | `parseSignatureInput`（core） |
| 6 | 比 `keyid` 的 DID 与步骤 4 的 `serviceDid` 完全一致 | 字符串全等，不一致即失败（L385） |
| 7 | 按 ANP-02 解析并验证 `serviceDid` 的文档 | `DidKeyResolver`；`authentication` 关系 |
| 8 | 用其公钥验外层签名 | `verifyHttpMessageSignature`（core），组件集与 ANP-02 一致 |

第 8 步的签名覆盖集合不用另定：core 的 `ANP_COMPONENTS` 就是
`("@method" "@target-uri" "@authority" "content-digest")`，与 ANP-02 §3.1.2 L112
（「至少覆盖 `@method` 与 `@target-uri`；有消息体时还必须覆盖 `content-digest`」）
以及 L98 的示例逐项对上。`keyid` **MUST** 是完整 DID URL（L82）——所以
[message-service.md](message-service.md) §13 里说的「`serviceDid` 不带 fragment」
是**它自己**不带，不是 `keyid` 不带。

### 2.2 重放防护要一张表

ANP-02 L437 要求服务端**必须**实现重放防护，直连 profile 按 `(keyid, nonce)` 建短期
replay cache；L143 是验证流程里的第 8 步。core 的 `verifyHttpMessageSignature` 已经
留了 `nonceStore` 接缝，C11 只需给它一个存储实现——**这是本设计唯一的新表**（§6）。

### 2.3 什么算跨域：只看有没有外层身份

**选择**：外层认证按「请求有没有带 `Signature-Input`」触发。带了就八步必过，任一步
失败即 401；没带就当作本地调用，只认 `origin_proof`。**这是本服务的选择**——
§6.2 的要求落在「服务到服务调用」上，而本地 `connectx` 客户端不是服务（P8 §9.2 L588
的"Agent 直达模式"也明说客户端自己做外层认证**不属于 v1 MTI**，所以 CLI 不该有它）。

**代价要说清楚**：一个跨域调用方可以不带外层身份，我们无法把它与本地客户端分辨开。
它换不到任何额外权限——业务动作仍由 `origin_proof` 授权，而那需要 `sender_did` 的私钥；
它失去的是**域级归属**，于是 §6.5 L443–454 那套按来源域做的路由与审计无从谈起。
§6.2 L319 那条 MUST 落在调用方头上，这一侧无法替它履行。

**也考虑过一个"更严"的判法**：解析 caller anchor 的文档，看它的 `ANPMessageService`
条目指向谁——不是本服务就要求外层身份（C3 验 `origin_proof` 时本来就拿到了那份文档，
所以这不多花一次解析）。**它并不更强**：调用方拥有自己的 DID 文档，一个想绕过这一层的
服务只要把服务条目写成指向我们，或者干脆不写条目，就会落回"本地调用"那一档。
既然挡不住有意为之的调用方，就不值得为它多一条会改变受理结果的规则。

在这之上，**带了外层身份但业务层缺 `origin_proof`** 仍按各 Profile 规则拒绝——两层
各判各的，不互相顶替（§6.4 L435）。

### 2.4 跨域身份认证失败回 401，不进 JSON-RPC

§2.1 的「一律 200」在**这一层**也不成立，理由与数据面那条同构：外层认证跑在 JSON-RPC
之前，那时还没有 `id` 可答，而 ANP-02 已经把这件事表示完了——
L236 的 `401`、L243 的 `WWW-Authenticate: DIDWba realm=…, error="invalid_signature"`、
L252–260 那组 `error` 取值（`invalid_signature` / `invalid_verification_method` /
`invalid_did` / `invalid_nonce` / `invalid_timestamp` / `invalid_content_digest`）。
自己另造一个 `anp_code` 只会多一套没有出处的名字。

于是发送侧读对端答复时也必须读**原始 HTTP 状态**，不能走 core 的 `postMessage`
（它对非 2xx 直接抛）。C11 为此加一条出站路，形状与数据面那条相同：**非 2xx 不是异常，
是答复**。

### 2.5 出站解析是跨域接收的前提

第 2 步要解析 caller anchor 的文档，第 7 步要解析 `serviceDid` 的文档，两者都住在**对方**
域里。§6.2.3 L328–329 推荐 `did:web` / `did:wba` 用**裸域名 DID** 做域级联邦身份，
而 core 的签名器只在**非** `did:web:` 时内联文档——所以 `did:web` 的跨域接收
**必然**要出站解析，而 `AGENTX_ALLOWED_DID_HOSTS` 的默认值是空（只认内联文档）。

**这不是代码问题，是部署问题**：跨域接收要求把对端域加进白名单，或者用
`AGENTX_DID_DEV_HOSTS` 联调。默认空是**对的**默认——一个消息服务不该因为跑起来
就去任意解析陌生域名。C11 不放松它，只在文档里写清楚。

## 3. 发送侧：一条同步路，一条异步路

C5b 只有一条路：受理 → 落库 → outbox → 后台推。读完 P8 之后这条要分成两条，
因为**有一件事 C5b 做错了**，而且它错得不是细节。

### 3.1 `direct.incoming` **不是**跨域消息

C5b 的 `delivery/worker.ts` 解析收件人的 `ANPMessageService`，然后 POST
**`direct.incoming`**。P8 把这条腿换了：

- §5.1 L206–210：`meta.target.kind = "agent"` 时，发送方域服务 **MUST** 解析目标
  `agent_did` → 选出目标 `ANPMessageService` → **直接把原始 `direct.send` 发送到该服务**。
  授权清单里没有 `direct.incoming`。§6.2.2 L348–368 那张跨域方法表里也没有它。
- P3 §7.2.1 L397 把 `direct.incoming` 定义成「由某 ANP Endpoint 向目标 Agent 推送一条
  **已被目标 ingress 接受**的直接消息」。跨域那一跳发生时，目标 ingress 还没接受——
  语义上它**不可能是**那条消息。

所以 `direct.incoming` 是**域内的最后一跳**（ingress → agent），不是域间的传输。本服务
作为 ingress 替本地 agent 收件时它仍然用得上（P3 §7.2.2 L403 要求能发、能收或能处理），
但它**不承担跨域搬运**。

### 3.2 请求要同步，因为答复必须回到原始调用方

§8.1 L511 说跨域 `direct.send`「当**最终目标域服务接受该消息后**，发送方域服务
**MAY** 向本地调用方返回成功」。那个 MAY 看起来把选择权给了我们，但 §6.7 L464 把它拿
走了一半：

> 联邦服务 **MUST** 原样保留最终服务返回的 DID 迁移错误……**原始调用方**负责验证迁移、
> 重建所有受影响的请求字段和认证上下文、**重新签名**并重试。

重签名要私钥，而私钥在 agent 手里，不在域名服务手里（§7.2 L492 同义）。所以
`anp.did_superseded` 必须**走回**原始调用方。C5b 的异步 outbox 在受理那一刻就已经
答复过调用方了，之后没有通道可回——那条路在跨域请求上**没法**满足 §6.7，而 §6.7 是
MTI 第 14 项（§10 L661）。

**选择**：

- **请求**（有人在等答复的）：`direct.send`、`group.*`、`attachment.*` 出站到非本服务时，
  在**请求路径里**转发，把对端的结果（含错误、含 `group_event_seq` / `group_receipt`）
  翻回给调用方。转发**不进事务**——C5b 那条"事务里不得有网络往返"的理由在这里
  一样成立，所以顺序是：**事务外转发 → 对端接受 → 事务内受理落库 → 答复**。
  对端拒绝时**不落库**，调用方用同一个 `operation_id` 重试即可干净地再来一次。
- **通知**（没人在等的）：`group.incoming` / `group.state_changed` / `group.e2ee.notice`
  由 Group Host 分发（§5.4 L273），继续走 outbox + 退避。这条路 C5b 已经建好，
  只是住户换了。

**三族都已接**（`direct.send` 在 C11、`attachment.*` 在 B1a、`group.*` 在 B1b-A4）。群族是
三族里最后接上的，因为它比前两族多一个前置条件：

- `group.*` 里那十一条的判断要先解析 `group_did` 的文档才做得了——而那份文档在 B1b 之前
  **还没有人发布**。B1b 把"谁来发布群 DID 文档"这件事裁定成**本服务自己**（TODO3 §0），
  A1–A3 铸出群钥、造出文档、把文档挂上 `GET …/g/<id>/did.json`，这一族才接得上。
- 接上之后还有一处前两族没有的判据：住在**自己命名空间**里的群（`serviceDid:g:<id>`）直接
  落在本地（`relayFor` 里的 `isOwnGroupDid`）。放它出站的那趟解析要么被
  `AGENTX_ALLOWED_DID_HOSTS` 拒（清单写的是对端域，不写自己），要么要求本服务的
  `publicUrl` 是 https——于是一个**本服务亲手建的群**会在自己的 `group.send` 上报 1012。
  这不是优化：一个本地就知道答案的调用不该取决于出站解析成不成功。见 §3.3。
- 跨域那一档还多一处与前两族不同的接线：群一转发，本地处理器就**整段跳过**
  （`dispatch.ts` 的群分支与附件分支同形）。群不住在本服务上，名册、事件序、回执与那把
  群钥都在它的 Host 那里，本地再跑一遍只会去查一个不存在的群。

（`attachment.*` 早先记在这里，理由是"锚点是原始附件消息的发送者 DID，不是
`meta.target.did`"。那条理由是错的，见 §5.2：那两句约束的是调用方怎么发现服务，不是域
服务怎么路由，而两条都落在 `meta.target.did` 上。接法就是把它加进 `RELAYED_METHODS`。）

判断只有一个入口（`dispatch.ts` 的 `relayFor`）：**哪些方法会出站**是它头上那张
`RELAYED_METHODS`，**该不该出站**是它本体那几行。

**转发之前先查一次幂等记录。**已经记过账的操作不再出站：那份记录里的结果就是对端的答复，
重试要的是它。少了这一查，每次重试都会再打扰对端一遍——对端恰好不可达时，那句
`anp.temporarily_unavailable` 会让调用方以为这颗消息没被受理，事实上它早就被受理过了。
§9.1 L630 说的"重试得到同一结果"包括不重做网络那一跳。

**并发**（C11 标题里那三个字）：转发在请求路径里、事务外，所以 N 个并发的跨域请求各自
出一趟车，谁都不挡谁；outbox 那边保持一轮串行（一次 tick 把对端限流撞满没有好处）。

**代价**：对端不可用时，本地调用方拿到的是失败——我们不再"先收下、再慢慢送"。
这是 §8.1 更强的那一半，不是退步；而重试是安全的，因为业务幂等键不变（§7.1 L478）。

### 3.3 怎么判断"该不该出站"：只看目标服务是不是自己

不需要判断两个 DID 是不是"同一个域"——那是个我们无从权威得知的属性。规则只有一条：

> 解析出 `meta.target.did` 公开的 `ANPMessageService`；**是本服务就在本地办完，不是本
> 服务就按 §5 转发原始方法。**

三族的目标写法不同、规则却同一条：私聊的 `target.kind = "agent"`，`target.did` 是收件
agent；附件的 `target.kind = "service"`，`target.did` 是那个对象服务的 `serviceDid`；
群的 `target.kind = "group"`，`target.did` 是 `group_did`——**只有一个例外**，
`group.create` / `group.e2ee.create` 的 `target.kind = "service"`、`target.did` 是一个
`serviceDid`（§8.1.2 L624–625）：建群之前还没有群可指，那两条是"请一个服务建群"。

`isOurOwnIngress(config, endpoint)` 就是这个判断，C11 把它从 `delivery/worker.ts` 提到了
`http/server.ts`——那里才是定义 `RPC_PATH`、也就是"我们的入口长什么样"的地方。出站转发与
后台推送现在读的是同一个函数：**"自己是谁"只有一个定义**，两处各写一遍就是将来只改了一边
的入口。同域不产生任何 HTTP，这是 C5b 就定下的取舍，仍然成立。

**两族在这条规则之前还有一次本地比较**（`relayFor` 里）。它们省的不是一次解析，是一次
**依赖**：`isOurOwnIngress` 要求先把目标文档解析出来，而我们自己的文档不在本服务手里
（§4 第 2 点）——靠它来判"是自己"会让一次同域调用在文档不可达时无端失败。

- 附件族比的是 `target.did` 与 `config.serviceDid`（目标写着我们自己的 `serviceDid`，
  答案本来就在本地）。
- 群族比的是 `isOwnGroupDid(config.serviceDid, target.did)`：住在自己命名空间里的群。
  与上一档不同的是，这里的理由**不是**"我们自己的文档解析不出来"——群文档正是本服务发布
  的（[groups.md](groups.md) §2.2）——而是那趟解析**过不了白名单**（见 §3.2）。

### 3.4 outbox 换了住户

`outbox.payloadJson` 装的是序列化好的通知。C11 之后它**只装通知**，而且只剩群那条路在写
它（`groups.ts` 的 `deliver()`）；`direct.send` 一个字节都不再往里排——域内的收件人由投递
行加订阅推送服务，跨域的走 §3.2 的同步转发。

C5b 那行 `direct.incoming` 入队本来就是白跑的一趟：后台 worker 再发一次 HTTP，而它遇到
自家入口时是直接丢掉的（§3.1 的结论）。C11 只是把它落实。

这**不改表结构**（`recipient_did` 的"重试要重新解析"语义一字不变），改的是谁往里写、
写什么。

## 4. 我们自己的 `serviceDid` 与签名钥

发送侧要签外层请求，就得回答三件事：

1. **`serviceDid` 是什么。** C8 已经从 well-known 与 `anp.get_capabilities` 里给了
   （`config.serviceDid`，默认由 `publicUrl` 推 `did:web`）。§6.2.1 L327 要求参与跨域的
   服务条目 **MUST** 声明它——这一条已经满足。
2. **keyid 指哪把钥。** 它 **MUST** 是完整 DID URL，指向 `serviceDid` 文档里被
   `authentication` 授权的验证方法（§6.2.1 L330）。我们的 DID 文档**不由本服务托管**
   （[message-service.md](message-service.md) §13 / [cli.md](cli.md) §3.4）——**这是分层，
   不是缺口**（2026-10-02 的裁定：DID server 只管身份，本服务承载社交应用；身份文档是 DID
   server 的产物，本服务发布的是群文档那一类消息层产物）。所以 keyid 的 fragment 由**发布
   方**决定，本服务只能配成一致。落地就是 `AGENTX_KEY_ID`：完整 DID URL，且必须挂在
   `serviceDid` 下——配置层会拒掉别的，因为不一致时我们签出去的每一份请求都会被对端按第 6
   步拒成 `forbidden_did`，而那个错误看起来像对端的问题。
3. **私钥从哪来。** `AGENTX_KEY_FILE`（`config.ts` L206）早就解析了却没人用。
   C11 就是它的第一个消费者：读一把 Ed25519 私钥（hex 或 PEM，与 `connectx --key` 认的
   同两种），按 ANP-02 §3.1.2 造 `Signature-Input` + `Signature` + `Content-Digest`。
   core 现有的签名器**不能**直接用——它是 ANP-02 的 DID 服务登录流程，不是通用外层的
   （见 `crypto/signer.ts`）。

## 5. 群与附件的跨域落点

### 5.1 `group_did` 要先能解析

§5.2 L215–221：`meta.target.kind = "group"` 时 **MUST** 解析 `group_did`，据其文档
确定 Group Host 的 `ANPMessageService`，再发给它；**MUST NOT** 绕过 Host 自定
`group_event_seq`（§3.3 L74–76）。而 §10 L648 的 MTI 第 1 项就是「对 `agent_did` 和
`group_did` 进行服务发现」。

[groups.md](groups.md) §2 选的形状 `group_did = serviceDid + ":g:" + <id>` 天然是
可解析的（`did:web:host:g:XXXX` → `https://host/g/XXXX/did.json`）。这条形状决定了**发布
义务跟着群走**：文档要住在那个 URL 上，就只能由 `group_did` 里的那个域发布——也就是
**本服务自己**（TODO3 §0 的裁定）。B1b 之前记在这里的"缺口"因此收了：本服务现在发布
**自己名下**的群文档（A1 铸钥、A2 造文档、A3 挂路由）。**剩下的那一半与 message-service.md
§13 仍是同一条接缝**：本服务**自己**的 `serviceDid` 文档仍由 DID 文档托管方
（`awiki-open-server`）发布，见 §4 第 2 点。

**代码侧只做两件**：把 `group_did` 交给 `ServiceLocator`，以及解析不出来时**明确失败**
（不要退化到"按域名猜 Host"——§7.5 L495 禁止的正是这个猜法，§5.2 也没给它留路）。本服务
名下的群在这一层之前就短路掉了（§3.3 的 `isOwnGroupDid`），所以这里问的都是**别人的**群。

### 5.2 附件：锚点是"调用方怎么找到服务"，不是"域服务怎么路由"

§9.2 L570：v1 标准互通路径是**域服务代理模式**——本地服务依据**原始附件消息发送者
DID** 去解析其公开 `ANPMessageService`，把 `attachment.get_download_ticket` 发过去
（L582）。模式 B（agent 直达）明确不属于 v1 MTI（L588）。

**这句话约束的是调用方，不是这一层。** P8 §5.3 写得很清楚：那句"先从原始附件消息发送者
的 DID 解析公开服务"是**caller** 的发现义务；等请求送到本服务手里，
`meta.target.did` 已经写着它解析出来的那个 `serviceDid`（§10.1 L798 要求四条附件方法
的 `target.did` 必须等于目标服务的 `serviceDid`）。所以发送侧的路由规则与私聊、群**完全
相同**——解析 `meta.target.did` 公开的 `ANPMessageService`，是本服务就本地办完，不是就
把原始方法转过去（§3.3）。早先那版把这条写成"附件的锚点是原始发送者 DID，不是
`meta.target.did`"，把调用方的发现义务与域服务的路由混成了一件事，是错的。

由此 §3.2 那张"还没接"的清单如今**是空的**：`attachment.*` 在 B1a 划掉，`group.*` 在
B1b-A4 划掉。三族共用的就是 §3.3 那一条规则。

**调用方那一侧另有两句约束，与本层无关但别丢**：§9.1 L565 与 §5.3 L249 都点着说，群场景
里用的是**原始群消息的发送者 DID**，**不是** `group_did`；而且 **MUST NOT** 只凭
`object_uri` 的域名猜控制面服务。C10 的 [attachments.md](attachments.md) §6 第 2 条已经
按这个写，这里只是把它接到 P8 上。

数据面**不跨域**：§3.4 L78–84 明令对象字节 **MUST NOT** 走跨域服务调用链路，下载是
独立 HTTPS（§9.3 L628）。C10 的数据面本来就是独立路由，这条自动成立。

## 6. 存储增量

只有一张表。C10 落地后当前是 v5，所以 C11 这张表会是 v6；两张表互不依赖，顺序无所谓。

```sql
-- ANP-02 L437 要求的重放缓存。键取 (keyid, nonce)，过期即无意义
CREATE TABLE http_nonces (
  keyid TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL,
  PRIMARY KEY (keyid, nonce)
);
```

不存外层调用方的 `serviceDid`：§9.9 L768–774 的 Grant 映射要的是 P2 的连续性来源，而
Grant 的键已经是 `(message_id, attachment_id, object_uri)`，多存一列只是多一处会过期的
副本。需要审计时它在日志里。

## 7. v1（C11）不做

- **改写到对方的 DID 迁移错误**：§6.7 L464 明令**原样保留**，且 **MUST NOT** 把
  `currentDid` 当可信重定向。
- **替换、删除或合成设备 selector**：§3.7 L100–104。P3/P4/P7 的 Base 操作
  **MUST NOT** 被合成 selector——C11 一行 selector 代码都不写，因为没有 P5/P6 可保留的。
- **触碰 E2EE 载荷**：§3.5 L86–88，服务对它是中间方，**MUST NOT** 修改。
- **任何形式的静默降级**：§6.6 L456–458。
- **`anp.federation.relay.v1` 之外的联邦 Profile**：§4.1 L139–145 保留这个标识。

## 8. 缺口（不是本仓库能补的）

1. **群 DID 文档的发布面窄了**（§5.1）。B1b 之前是"还没有人发布"；B1b 之后本服务发布
   **自己名下**的群文档，跨域 `group.*` 与 MTI 第 1/4/5 项（§10 L648、L651、L652）只在这个
   范围内通了。剩下两处不是本服务的事：别人名下的群要靠**它自己**的 Host 发布（§5.1 的
   `ServiceLocator` 本来就不假设是谁发的），以及本服务自己的 `serviceDid` 文档仍由
   `awiki-open-server` 托管（下面第 2 条）。**部署侧另有一条硬前提**：`did:web` 一律要求
   https，所以 `AGENTX_PUBLIC_URL` 是 http 的部署（含本仓库的默认值）其群文档解析不出来，
   `AGENTX_ALLOWED_DID_HOSTS` 也得写进对端域（TODO3 §B）。
2. **`serviceDid` 文档由 DID Service 发布——这是分层，不是缺口**（§4 第 2 点）。
   2026-10-02 的裁定把两个服务切开：**DID server 只管身份，本服务承载社交应用**。身份文档
   因此**有意**留在 `awiki-open-server` 那一侧，本服务不发布它；外层 `keyid` 的 fragment 由
   发布方决定，本服务用 `AGENTX_KEY_ID` 配成一致。同一裁定也把 TODO2 A7 那条收了口：一份
   身份文档里 `ANPMessageService` 条目指向谁，是**身份所有者**的声明，不是 DID server 的
   裁决——awiki 原先那两条"必须等于服务器自己"的相等检查正是把两层焊在了一起，fork 的
   `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE` 把它拆开（[TODO4.md](../../TODO4.md) §C）。
3. **被取代 DID 的拒绝需要 P2 连续性来源**：§6.7 / §7.2 L492 要求重建签名重试，而
   "哪个 DID 取代了哪个"的权威答案在 P2。[groups.md](groups.md) §12 记的是同一条。
4. **上面这些验到了什么程度。** B1b 落地时，跨域转发只有方法级测试，对端是一个回答
   "文档指向哪"的 stub。TODO4 §A3 把 stub 换成了第二台真的 `AgentXAgent`：同一台机器、
   两个端口、`AGENTX_DID_DEV_HOSTS` 那条联调口，A 域的 agent 对 B 域命名空间里的群发
   `group.send`（请求交给 A，`meta.target.did` 是 B 的群 DID），验三件事——转发真的发生
   （B 有群、有名册、有那条消息行，A 一条群行都没有）、B 签的回执在 A 域用**从网络上取回来
   的** B 域群文档过一次 `verifyObjectProofDetailed`、A 的本地库一个群行都没落。落点是
   `packages/e2e/src/groupFederation.test.ts`。
   **没验到的**：真 https 与真域名（上面第 1 条，e2e 走的是 dev-host 那条口）、跨机器、以及
   **外层签名那一半**——`egress` 的 `keyid` 必须指着本服务自己的 DID 文档，而那份文档不在
   本服务手里（第 2 条），所以 e2e 里没有一处能解析出它，签了也验不过。P8 §2.3 对不带外层
   身份的调用方的处置本来就是"按本地调用处理"，业务层的 `origin_proof`（由调用方真签）照旧
   是唯一的授权依据，所以外层那半段仍由它自己的方法级测试覆盖。
