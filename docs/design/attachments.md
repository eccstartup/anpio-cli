# 附件与对象传输（P7）—— 三平面、授权链与数据面

P7 把附件拆成**三个平面**：消息面送清单、控制面申请与签票据、数据面搬字节，
三者 **MUST NOT** 混淆（§3.1 L68–80）。本服务同时站在**控制面**与**数据面**上，
消息面不是新东西——清单是 `direct.send` / `group.send` 的正文。

[message-service.md](message-service.md) §12 只有一张六行的流程图。这份写它背后的东西：
授权链在哪一刻长出来、票据为什么不签名、对象字节放哪、以及数据面为什么**不**跟着
§2.1 的"一律 200"。

## 1. 本服务就是那个 Object Service

P8 §9.1 L558–563 说得很清楚：协议级的终结点**必须**是原始附件消息发送者 DID 所公开的
`ANPMessageService`；内部再路由到独立的 Object Service 属于实现细节。§9.7 L722–726 又
补了一句：若部署方拆了内部组件，**MUST** 保证对外那个公开入口拿得到签发所需的
Access Grant。

**v1 不拆。** 控制面四个方法进的是同一张方法表、同一个 `Storage`、同一个进程。拆开就得
为"Grant 怎么同步"发明一套内部协议，而规范明说 v1 **不单独标准化**它（§9.7 L724）。

这意味着 `object_uri` 的域名**就是本服务的域名**，而不是某个对象仓库的域名——§7.5 L495
要求调用方 **MUST NOT** 只凭 `object_uri` 的域名猜控制面服务，在"不拆"的前提下这条
自动成立。

**"本服务就是那个 Object Service"说的是本服务作为目标时的那一档。**目标写在别处时
（`meta.target.did` 是另一个服务的 `serviceDid`），本服务只是把原始方法转过去——见 §6.1。

## 2. 控制面四条方法的形状

四条都是 **service-scoped**（§10.1 L797–799）：`meta.target.kind` **MUST** 为 `service`，
`meta.target.did` **MUST** 等于目标公开服务的 `serviceDid`。Profile 固定
`anp.attachment.v1`，`security_profile` 固定 `transport-protected`（§10.1 L783–784）。

| 方法 | 正文要点 | 成功响应要点 |
|---|---|---|
| `attachment.create_slot` | `attachment_id` + `intended_message_security_profile` + `object_encryption_mode`（§10.2.2 L840–845） | `slot_id` / `upload_uri` / `object_uri` / `commit_token` / `expires_at`（§10.2.3 L881–889） |
| `attachment.commit_object` | `attachment_id` + `slot_id` + `commit_token` + `size` + `digest` + `object_encryption_mode`（§10.3.2 L909–916） | `committed` / `object_uri` / `committed_at`（§10.3.3 L933–938） |
| `attachment.abort_object` | `attachment_id` + `slot_id`（§10.4.2 L957–960） | `aborted` / `aborted_at`（§10.4.3 L964–968） |
| `attachment.get_download_ticket` | `attachment_id` + `object_uri` + `requester_did` + `message_security_profile` + `message_id`，再按上下文补 `message_target_did` 或 `group_did`（§10.5.2 L987–998） | `download_ticket_b64u` / `expires_at` / `ticket_binding`（§10.5.3 L1016–1033） |

一处硬约束：`intended_message_security_profile = "transport-protected"` 时，
`object_encryption_mode` **MUST** 为 `none`（§10.2.2 L875）。这条正是 §3.4 L140 那句
"明文承载下对象也必须明文"在控制面的落点。

**幂等**：`target_scope` 取 `attachment_id`。规范没为这四条定义键（§7.1 L474–480 只说
"复用原业务方法的幂等语义"，而它们是控制面方法，没有业务方法可复用），**这是本实现的
读法**。同 `attachment_id` 的不同操作靠 `operation_id` 区分——重试带同一个
`operation_id`，新请求带新的。

**`meta.content_type` 不是 JSON-RPC 的 `application/json` 吗？** 不是。控制面请求仍是
JSON-RPC（§14.1 的示例就是一个完整信封），`content_type` 是**业务载荷字段**，与 HTTP
的 `Content-Type` 无关。

## 3. 数据面：两条新路由

§2.1 那张路由表里已经写了 `PUT <upload_uri>`，但缺少下载那一半——`attachment_slots`
的草稿建表语句里也只有 `object_uri` 没有取它的路由。两条都补上：

| 请求 | 鉴权 | 应答 |
|---|---|---|
| `PUT /anp-im/upload/{token}` | URL 里那个不可猜的 token | `200`（空体） |
| `GET /anp-im/objects/{object_id}` | `Authorization: Bearer {download_ticket}`（§9.5 L703–706） | `200` + 对象字节 |

**第二段的段名不是摘要，是 `object_id`。** §14.2 的示例里 `upload_uri` 落在
`/upload/slot-70001`、`object_uri` 落在 `/objects/obj-abc`——两者是同一层的一对随机 id，
**不是** `sha-256:<...>` 那种自证式路径。规范也没给别的选择：`create_slot` 的响应里就有
`object_uri`（§10.2.3 L881–889），而那时字节还没上传，摘要根本不存在。于是 `object_uri`
是**不透明定位符**：`objectUriFor()` 是铸它与取它这**同一份定义**，下载路由把 URL 的最后
一段拿回来与行里的 `object_uri` 比。**字节仍按摘要寻址**（§4），只是那件事不进 URL。

上传不需要 `origin_proof`，也不能要：`upload_uri` 是给普通 HTTP 客户端用的，
`upload_headers`（§10.2.3 L892）指的是 HTTP 头，不是 JSON-RPC 的 `auth`。它的凭据就是
那条**只在 `create_slot` 响应里出现过一次**的 URL。

**HTTP 层要加一条字节路。** `http/server.ts` 的 `send()` 现在只写字符串，`RpcResponse.body`
也是 `string`。数据面要原样吐字节、要带 `content-length` 边收边写，所以照
`handleStream` / `wellKnown` 的接缝模式加两个可选 handler：没接上就回 `501`
——"这个面还没做"和"这个面做错了"必须分得开。

### 3.1 数据面**不**跟着 §2.1 的"一律 200"

§2.1 那条一律 200 的理由是：客户端按 `error.data.anp_code` 分支，而 `core` 的
`postMessage` 对非 2xx 直接抛错，把 4xx 用起来就等于把 `anp_code` 丢掉。**那条理由在
数据面上不成立**：这里没有 JSON-RPC 信封，没有 `id` 可答，客户端是普通的 HTTP 客户端
（curl、浏览器、`fetch` 下载），它们读的就是状态码。

所以数据面用**真的 HTTP 状态码**，同时把 `anp_code` 放进 JSON 体里，两种客户端都能用：

| 情形 | 状态 | `anp_code` |
|---|---|---|
| 没有 `Authorization` | `401` | — |
| 票据非法 / 已被作废 | `401` | `anp.attachment.download_ticket_invalid`（6007） |
| 票据过期 | `410` | `anp.attachment.ticket_expired`（6009） |
| 票据没绑到这个对象 | `403` | `anp.attachment.ticket_binding_mismatch`（6008） |
| 那个对象还没提交（或不在库里） | `404` | `anp.attachment.object_unavailable`（6012） |
| PUT 的槽不存在 / 已废弃 | `404` | `anp.attachment.slot_not_found`（6000） |
| PUT 的槽已过期 | `410` | `anp.attachment.slot_expired`（6001） |
| PUT 超限 | `413` | `anp.attachment.object_too_large`（6003） |

**6007 只从两条路开口，而 §12 L1095 的措辞比这宽。** 规范把 6007 的含义写成"缺失、
非法、**验签失败**、无法解析，或已被作废"——见 §7，v1 的票据是不透明令牌，没有签名
可验，所以"验签失败"这一项在本服务里没有对应场景。真正会用上它的是另外两项：
`download_tickets` 里查不到这张票（缺失），以及 `one_time` 的票已被兑换（已作废，
`consumed_at` 非空）。§12 里**始终发不出**的是另外两个码——6004
`unsupported_mime_type`（v1 不做类型白名单）与 6011 `decrypt_failed`（v1 只承载
`none`）。这与 P4 的 3002 是同一种情况：留着一个发不出的码，比造一个场景去用上它诚实。

### 3.2 回给浏览器的 `Content-Type` 不用清单里的 `mime_type`

`attachment_manifest.mime_type` 是**对端**给的（§7.3 L455），而对象字节也是对端给的。
按它原样回 `Content-Type` 就等于让对端在我们这个域名下挑渲染上下文——一个
`text/html` 的对象就是同源下的一个页面。所以数据面一律回：

- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment`
- `X-Content-Type-Options: nosniff`

`mime_type` 仍然照 §7.3 L455 存（§13 L1123 把它列进最小互通），但它只在**清单**里表示
"这是什么文件"，不决定我们**怎么送**它。规范没说数据面该回什么头，这是本服务的选择。

## 4. 对象字节放哪

**文件系统，按摘要寻址**，目录由 `AGENTX_OBJECT_DIR` 给（不给就用数据库文件旁边那个
目录）。路径就是 `sha-256` 的无填充 base64url：`<dir>/objects/<digest>`。

三条理由：

- **去重是免费的。** 同一份字节上传两次落在同一个路径上。§3.8 L180 那条"一个附件对象
  只上传一次"说的是多设备不要各造一份，把它推到存储层就是这个形状。
- **不用 sqlite BLOB。** 库是**顺序与幂等的台账**，WAL 每次检查点都要搬动脏页；几 MiB
  的对象体混在里面，等于让每条消息的提交都背着一份附件。
- **文件自己的名字就是它的完整性主张。** §7.4 L472 要求 `digest` 是上传字节的 SHA-256，
  于是"路径 = 摘要"这件事本身就是校验，不需要另写一套。

上传的落盘顺序：`PUT` 边收边算摘要、写进 `<dir>/tmp/<slot_id>`；`commit_object` 校验
`size` 与摘要（§10.3.2 L925 要求 `digest.alg` 为 `sha-256`）之后，才把它搬进
`objects/<digest>` 并落一行 `attachment_objects`。**没提交的对象不可被引用**
（§10.1 L826 那句"拿到 `object_uri` 不等于对象可用"），所以 `object_uri` 从 `create_slot`
就发出去，但它指向的东西到 `commit` 才存在——`object_uri` 是 locator，不是"东西已经在
那了"的断言（§7.5 L489）。

**大小上限**：`AGENTX_MAX_OBJECT_BYTES`（默认 64 MiB），超了回 6003。约束在**收流的
过程中**，不是收完之后——先缓冲再判断，等于把上限变成了内存用量。它和 `AGENTX_MAX_BODY`
是两个数：控制面信封是几 KB 量级，对象是几 MiB 量级，用一个数就必然有一个是错的。

**`object_uri` 里的 https 与回环例外**：§7.5 L488 要求 `object_uri` **MUST** 是 `https://`。
本服务默认的监听是回环、`publicUrl` 也是 `http`（[message-service.md](message-service.md) §14），
于是本地跑出来的 `object_uri` 会违这一条 **MUST**。**选择**：仅在 host 是回环时允许
`http`，其余一律要求 `https`——与 §14 里 `did:web` 的推导同一套判断。

## 5. 授权链：Grant 在哪一刻长出来（本节是 C10 的重点）

§9.2 L652 那句话否掉了一个很自然的误解：

> `attachment.create_slot` 与 `attachment.commit_object` **只**负责创建对象，
> **不授予任何接收方下载权限**。

**权限出现在承载清单的那条消息被接受之后**（§9.2 L656）：`direct.send` 由**发送方服务**
接受后建 Grant，`group.send` 由 **Group Host** 接受后建 Grant，`group.e2ee.send` 同理。
每条附件一条 Grant，绑定 `message_id` / `attachment_id` / `object_uri` /
`message_security_profile`，外加私聊的 `message_target_did` 或群聊的 `group_did`
（§9.2 L658–664）。

对本服务的落地：

- 受理 `direct.send` 时，若 `meta.content_type = application/anp-attachment-manifest+json`，
  就在**同一个事务**里为 `body.payload.attachments[]` 每条写一行 Grant——和消息行、
  投递行、幂等行同一个 `acceptOperation()`。放事务外面就会出现"消息收下了、附件还不能
  下载"的中间态，而那个中间态是客户端无法判断的（它只知道消息成功了）。
- 受理 `group.send` 时同理，那条路径归 C9 的 fan-out 事务。**这是 C9 与 C10 的接口线**：
  群消息的 Grant 由 Group Host 建，而 Group Host 就是本服务。
- Grant 的键取 §7.2 L434 要求的**三元组** `(message_id, attachment_id, object_uri)`，
  不是 `attachment_id` 单列——`attachment_id` 只在单条 Attachment Message 内唯一，
  跨消息复用是合法的（§7.2 L432–433）。
- `attachment_id` 两次 `create_slot` 会得到两个槽，这是对的：键是
  `(attachment_id, slot_id)`。

**这条链只在能读到清单时成立。** 清单若按 §6.3 / §6.4 走在内层
（`application/anp-direct-cipher+json` / `application/anp-group-cipher+json` 里，
`application_content_type` 才是清单类型），本服务**看不见它**——§3.5 L147 还把
`object_key_b64u` 也锁在内层。规范那里说的"发送方侧系统"于是只能包含客户端，而 P7
**没有**给客户端定义一条"把 Grant 交给服务"的方法（§3.6 L153–164 明确删掉了内联下载
票据这类分叉）。

**这是真缺口，不是本服务偷懒**：v1 支持 `transport-protected` 承载下的附件授权链；
E2EE 承载下的清单归 C12 / C13，到那时要解决的就是"客户端怎么把 Grant 的上下文交给
服务"。现在不假装支持。

`intended_target`（§10.2.2 L864–877）是**hint**，§9.3 L675 明说它 **MUST NOT** 单独构成
授权。v1 连存都不存：它唯一可能的用途是提前做大小/类型判定，而我们的大小判定只认
`expected_size`。

## 6. `attachment.get_download_ticket` 的七条校验

§9.6 L710–718 给了七条，逐条落到本服务：

| # | 规范要求 | 本服务 |
|---|---|---|
| 1 | `meta.target.kind = "service"` | 方法表（`targetMode: 'service-scoped'`） |
| 2 | `meta.target.did` = 由原始消息发送者 DID 解析出的 `serviceDid` | 方法表只判 `kind`（`targetBindingHolds`），所以 `did` 这一项由 handler 自己比对（`attachments.ts` L172），不符 → 1014 |
| 3 | `requester_did = meta.sender_did` | 正文校验（§10.5.2 L1008），不符回 1003 |
| 4 | `(message_id, attachment_id, object_uri)` 的 Grant 存在 | 查表，无 → 6005 |
| 5 | `message_security_profile` 与 Grant 一致 | 不一致 → 6006 |
| 6 | 私聊：`message_target_did` 存在且符合策略 | → 6006 |
| 7 | 群聊：`group_did` 存在且 `requester_did` 当前仍符合群访问策略 | 查 C9 的 `group_members`，不符 → 6006 |

第 7 条是**票时刻的实时判定**，不是消息时刻的快照：已移出群的成员**拿不到新票**
（§9.8 L734 的 SHOULD），但它此前拿到过的字节与密钥不追回（§9.8 L730–735）。这两句要
一起读，只做前一半会变成"我们追回了"，只做后一半会变成"谁都能接着下"。

**这四个方法不验 `origin_proof`。** §10.1 L800 明说 v1 **不要求**在 Object 控制服务端
再验一次终端业务证明，跨域那一跳由 P8 的 `serviceDid + HTTP Message Signatures` 保证
（§10.1 L799）。这是本服务里**唯一**一组 `requiresOriginProof` 返回 `false` 的非匿名
方法——其余方法都把锚点当认证前提。

**同域怎么办**：同域没有那一跳，只剩 `meta.sender_did` 这个自报字段。所以本服务的选择
是——**同域请求仍然要求 `origin_proof`**，跨域调用只要外层服务身份过了就放行。理由：
§10.1 L800 那句话约束的是"跨域链路里终端证明不作为必要条件"，不是"服务必须不设防"，
而 §6.4 L439 也专门提醒"外层 serviceDid 认证 **MUST NOT** 被当成业务原发者证明"——
我们不是在把两者混为一谈，是在同域这一侧**至少要求其中一层**。本地客户端本来就带
proof（[message-service.md](message-service.md) §5.1）。

### 6.1 跨域出站：这一族现在会转发（2026-10-02）

四条的 `meta.target.did` 是**目标对象服务的 `serviceDid`**（§10.1 L798），所以"该不该
出站"和私聊是同一个问题、同一条规则：解析 `meta.target.did` 公开的
`ANPMessageService`，是本服务就本地办完，不是就把**原始方法**转过去
（P8 §5.3、[federation.md](federation.md) §3.3）。接法就是把这四条加进 `dispatch.ts`
的 `RELAYED_METHODS`。

**转发时本地一个字节都不落。** 槽位、对象字节、票据都在对端——在本地落一行只会造出一颗
谁也 download 不到的对象。幂等台账仍然记（`acceptOperation` 写的），所以重试拿回的是
对端那一份答复，与 §9.1 L630 一致。这与 `direct.send` 略有不同：那边转发之后还要落一条
**消息行**（它是"这次受理"的台账，附件控制面本来就不产生本地消息）。所以 `dispatch.ts` 里
附件那一支在进 handler 之前就早退，而不是让四个 handler 各自接一个 `relayed` 参数。

还没接的是 **`get_download_ticket` 的两段式**：§5.3 L249 要求调用方先从**原始附件消息
发送者的 DID** 解析出公开服务，再跨域调用。那是**调用方**的发现义务，不是本层路由
（[federation.md](federation.md) §5.2）——请求送到这里时 `meta.target.did` 已经写着它
解析出来的 `serviceDid`。所以这一段不是"还没做"，是本层**不该**做。

## 7. 票据是一张不透明令牌，不签名

§9.4 L681–689 要求票据绑 `attachment_id` / `object_uri` / `requester_did` /
`message_id` / `message_security_profile` + 上下文 + `expires_at`，
**MUST NOT** 含任何设备 selector（L691）。

**选择**：`download_ticket_b64u` 是 32 字节随机数的无填充 base64url，服务端存**它的
SHA-256**（不存原值——它是一张 bearer 凭据，台账里不该有明文），校验时按摘要查行。

为什么不是自包含的签名令牌：

- §9.5 L697 允许一次性票据，§9.8 L734 要用**当前**群状态决定发不发新票——两者都需要
  服务端状态。签名令牌能省掉的那一次查表，在这里省不掉。
- §9.6 第 4 条无论如何都要查 Grant。查完 Grant 再查票据行，与只查票据行，
  差别是一次主键命中。
- 验签要一把钥，而 v1 的服务端**还没有**自己的签名钥（[message-service.md](message-service.md)
  §14 的 `AGENTX_KEY_FILE` 是给跨域外层身份准备的，见 C11）。为票据先引一套钥管理，
  是把 C11 的活提前到 C10，且提前得没有收益。

有效期默认 **5 分钟**（§9.5 L696 的 SHOULD NOT 上限），`one_time`（§10.5.2 L1002）为真
时下载一次即置 `consumed_at`。

## 8. 存储增量（v5）

```sql
-- 上传槽，§10.1 L808–824 那张状态机
CREATE TABLE attachment_slots (
  attachment_id TEXT NOT NULL, slot_id TEXT NOT NULL, owner_did TEXT NOT NULL,
  upload_token TEXT NOT NULL DEFAULT '', commit_token TEXT NOT NULL,
  object_encryption_mode TEXT NOT NULL, message_security_profile TEXT NOT NULL,
  state TEXT NOT NULL,                 -- pending | uploaded | committed | aborted
  expires_at TEXT NOT NULL, object_uri TEXT, size INTEGER, digest TEXT, committed_at TEXT,
  PRIMARY KEY (attachment_id, slot_id)
);
-- 下载路由按 object_uri 反查槽位；也是唯一性约束——两个槽共用一个 object_uri
-- 意味着一个对象有两个签发者。NULL 在 SQLite 的唯一索引里互不相等，旧行不撞。
CREATE UNIQUE INDEX attachment_slots_object_uri ON attachment_slots (object_uri);
-- 这条得是**部分索引**：迁移给旧行填的 upload_token 是空串，把空串也纳进唯一性，
-- 文件里只要有第二行旧数据整个建表就失败；空串的语义本来就是"这行没有令牌"。
CREATE UNIQUE INDEX attachment_slots_upload_token
  ON attachment_slots (upload_token) WHERE upload_token <> '';

-- 已提交的对象。路径由摘要推出，所以这张表是"这些字节存在"的索引，不是字节的容器
CREATE TABLE attachment_objects (
  digest TEXT PRIMARY KEY, size INTEGER NOT NULL, committed_at TEXT NOT NULL
);

-- 下载授权：§9.2 L656 说它在**承载消息被接受之后**才出现
-- 键取 §7.2 L434 要的三元组，不是 attachment_id 单列
CREATE TABLE attachment_grants (
  message_id TEXT NOT NULL, attachment_id TEXT NOT NULL, object_uri TEXT NOT NULL,
  message_security_profile TEXT NOT NULL,
  message_target_did TEXT, group_did TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (message_id, attachment_id, object_uri)
);

-- 下载票据：存摘要不存原值，理由见本文 §7
CREATE TABLE download_tickets (
  token_hash TEXT PRIMARY KEY,
  attachment_id TEXT NOT NULL, object_uri TEXT NOT NULL, requester_did TEXT NOT NULL,
  message_id TEXT NOT NULL, message_security_profile TEXT NOT NULL,
  message_target_did TEXT, group_did TEXT,
  one_time INTEGER NOT NULL DEFAULT 0,
  issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT
);
```

`attachment_slots` 是 message-service.md §7 那份草稿的同一张表，v5 给它补上
`upload_token`——数据面唯一的凭据（§3）。v4→v5 因此只有**一列**要 `ADD COLUMN`，
同一个事务里先按 `ADD COLUMN ... DEFAULT ''` 补列、再走那张 `IF NOT EXISTS` 建表。
那三张新表**不进迁移步骤**：`CREATE TABLE IF NOT EXISTS` 对新旧文件都是对的，写一遍
等于把同一件事说两遍。但版本号仍然要走，否则 v4 写的文件读进来会被当成 v5。

**过期不改行、不后台扫。** 槽与票据的过期都在**用的时候**判（`expires_at < now`），
不写 `state = 'expired'`、不起定时任务：判定所需的全部信息已经在行里，扫一遍只会把
"过期"从一个事实变成两个可能不一致的表示。

**没有 GC。** §9.8 L730–735 明说 v1 **不保证**追溯性撤权，对象与 Grant 因此永不删除。
真需要清理时那是运维策略，不是协议行为——不要把它做成一个方法。

## 9. 承载：清单怎么进消息面，以及一处必须先修的解读

§6.1 L349–350 与 §6.2 L360–361 都要求：`meta.content_type` **MUST** 为
`application/anp-attachment-manifest+json`，`body.payload` **MUST** 为 Attachment Message。
§6.1 L352 / §6.2 L364 再要求这种情况下每条 `encryption_info.mode` 为 `none`。

**这里有一个当前实现会挡住 P7 的地方**，C10 动手前必须先改：

`packages/service/src/rpc/direct.ts` 的 `CONTENT_TYPE_OF`（L18–21）把负载字段与内容类型
做成了**等号**：`payload` ↔ `application/json`，判定在 L65。而 P3 §6.2.5 L268 的原文是

> 要求：当 `content_type = "application/json"` 时 **MUST**［用 `payload`］

这是**单向**的：它规定了"什么时候必须用 `payload`"，没有规定"`payload` 只能配这个类型"。
读成等号之后，一条完全合规的 P7 清单消息会被 1003 拒掉；而且
`ACCEPTED_CONTENT_TYPES`（L34）是由这张表推出来的，于是 `supported_content_types`
里也不会出现 P7 §13 L1121 点名要求的那一类。

改法：`payload` 的规则改成"`content_type` 是 JSON 媒体类型"（`application/json` 或
`*+json`），`text/plain` ↔ `text` 保持精确；`ACCEPTED_CONTENT_TYPES` 显式收进清单类型。
C9 写 `group.send` 的正文校验时要照同一份规则，别把等号再抄一遍。

## 10. v1（C10）不做

- **追溯性撤权**：§9.8 L730–735。
- **内部 Grant 同步协议**：§9.7 L724。
- **缩略图与分块**：§7.7 L508–514——需要缩略图就把它当普通附件发，需要分块就在 HTTP
  上传实现内部做。规范不为它们定义字段。
- **§3.6 L153–164 删掉的那一串**：`service-managed`、`wrapped_object_key_b64u`、
  `key_wrap_alg`、内联下载票据、自定义票据传输头、永久公开直链、镜像 URI、
  专门的分块/缩略图结构、经业务方法中继对象字节。
- **对象级加密的任何服务端参与**：`object-e2ee` 的对象在本服务眼里就是字节
  （§8.3 L581 说上传的就是密文 `C`）。解密是客户端的义务（§8.5 L602–622），
  所以 **6011 `decrypt_failed` 在本服务里没有产生路径**。
- **6004 `unsupported_mime_type` 同样没有产生路径**：v1 不设 MIME 白名单，
  而回给浏览器的类型固定是 `application/octet-stream`（本文 §3.2），
  与清单里的 `mime_type` 无关。
- **DID 迁移后的历史 Grant 继承**：§9.9 L768–774 允许在 P2 迁移验证通过、业务策略接受
  之后把旧 DID 的 Grant 映射到后继 DID，但这需要 P2 的连续性来源——与
  [groups.md](groups.md) §12 记的是同一条缺口，都在 C11。

## 11. 与 CLI 的接口

[cli.md](cli.md) 里**没有**附件命令面，这是有意的：C10 先做服务端的两条线与授权链，
客户端怎么发附件是另一件事（要么 `msg send --attach`，要么只在库里）。两个问题留给
用户：

- 要不要给 `connectx` 加发附件的命令（`msg send --attach` 一类的形状）；
- 收附件那一侧要不要一个下载命令（拿清单 → 要票 → GET → 校验摘要，四步全在客户端）。

两件都是**产品取舍**，不是规范能定的：MTI 要求的是服务端支持这四个方法
（§13 L1117–1129），没有一条要求客户端有对应的命令。
