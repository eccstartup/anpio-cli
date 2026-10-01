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

**并发**（C11 标题里那三个字）：转发在请求路径里、事务外，所以 N 个并发的跨域请求各自
出一趟车，谁都不挡谁；outbox 那边保持一轮串行（一次 tick 把对端限流撞满没有好处）。

**代价**：对端不可用时，本地调用方拿到的是失败——我们不再"先收下、再慢慢送"。
这是 §8.1 更强的那一半，不是退步；而重试是安全的，因为业务幂等键不变（§7.1 L478）。

### 3.3 怎么判断"该不该出站"：只看目标服务是不是自己

不需要判断两个 DID 是不是"同一个域"——那是个我们无从权威得知的属性。规则只有一条：

> 解析出目标（私聊是 `agent_did`，群是 `group_did`，附件是原始附件消息发送者 DID）公开
> 的 `ANPMessageService`；**是本服务就在本地办完，不是本服务就按 §5 转发原始方法。**

`delivery/worker.ts` 里的 `isOurOwnIngress()` 已经是这个判断，C11 复用它。
同域不产生任何 HTTP，这是 C5b 就定下的取舍，仍然成立。

### 3.4 outbox 换了住户

`outbox.payloadJson` 现在是序列化好的 `direct.incoming` 通知。C11 之后它只装**通知**，
请求不再经过 outbox。这**不改表结构**（`recipient_did` 的"重试要重新解析"语义一字不变），
改的是谁往里写、写什么。

## 4. 我们自己的 `serviceDid` 与签名钥

发送侧要签外层请求，就得回答三件事：

1. **`serviceDid` 是什么。** C8 已经从 well-known 与 `anp.get_capabilities` 里给了
   （`config.serviceDid`，默认由 `publicUrl` 推 `did:web`）。§6.2.1 L327 要求参与跨域的
   服务条目 **MUST** 声明它——这一条已经满足。
2. **keyid 指哪把钥。** 它 **MUST** 是完整 DID URL，指向 `serviceDid` 文档里被
   `authentication` 授权的验证方法（§6.2.1 L330）。我们的 DID 文档**不由本服务托管**
   （[message-service.md](message-service.md) §13 / [cli.md](cli.md) §3.4，发布方是
   `awiki-open-server`），所以 keyid 的 fragment 必须与**发布方写进去的那一条**对上。
   **这是一处部署耦合，C11 只把它写进配置与文档，不去猜。** 落地就是 `AGENTX_KEY_ID`：
   完整 DID URL，且必须挂在 `serviceDid` 下——配置层会拒掉别的，因为不一致时我们签出去的
   每一份请求都会被对端按第 6 步拒成 `forbidden_did`，而那个错误看起来像对端的问题。
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
可解析的（`did:web:host:g:XXXX` → `https://host/g/XXXX/did.json`），**缺口只在文档没有
人发布**——那条缺口与 message-service.md §13 的服务条目是**同一条接缝**，都在
DID 文档托管方（`awiki-open-server`）那边，不在本仓库。

**所以 v1 的跨域群操作，取决于那份文档发不发。** 本服务的代码侧只做两件：把
`group_did` 交给 `ServiceLocator`，以及解析不出来时**明确失败**（不要退化到"按域名猜
Host"——§7.5 L495 禁止的正是这个猜法，§5.2 也没给它留路）。

### 5.2 附件：模式 A 是唯一路径

§9.2 L570：v1 标准互通路径是**域服务代理模式**——本地服务依据**原始附件消息发送者
DID** 去解析其公开 `ANPMessageService`，把 `attachment.get_download_ticket` 发过去
（L582）。模式 B（agent 直达）明确不属于 v1 MTI（L588）。

坑在锚点：§9.1 L565 与 §5.3 L249 都点着说，群场景里用的是**原始群消息的发送者 DID**，
**不是** `group_did`；而且 **MUST NOT** 只凭 `object_uri` 的域名猜控制面服务。C10 的
[attachments.md](attachments.md) §6 第 2 条已经按这个写，这里只是把它接到 P8 上。

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

1. **群 DID 文档未发布**（§5.1）。挡住跨域 `group.*` 与 MTI 第 1/4/5 项
   （§10 L648、L651、L652）。
2. **`serviceDid` 文档未由本服务托管**（§4 第 2 点）。外层 `keyid` 的 fragment 由发布方
   决定，本服务只能配成一致。
3. **被取代 DID 的拒绝需要 P2 连续性来源**：§6.7 / §7.2 L492 要求重建签名重试，而
   "哪个 DID 取代了哪个"的权威答案在 P2。[groups.md](groups.md) §12 记的是同一条。
