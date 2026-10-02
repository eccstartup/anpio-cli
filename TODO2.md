# TODO2 —— 第二轮台账

接 [TODO1.md](TODO1.md)。TODO1 是"把 P1–P6 做出来"，到 `3e3747b` 为止 C1–C13 全部落地。
本文件记两件事：**C13 端到端实测暴露的、需要你裁定的问题**，以及 **TODO1 里还没划掉的部分**。
设计文档仍在 `docs/design/`。

---

## 0. C13 端到端实测（结论留档）

（口径：**ANP 1.2 已发布**，不再是 vNext。本文件原先写的"vNext 文档"即 1.2 文档，已改过来；
规范里的 profile 名仍是 `.v2` 那一套，两者说的是同一版。）

**方法**：拿 `awiki-open-server`（用户改过的版本，`http://127.0.0.1:8765`）当 DID 服务器，
真注册一份 1.2 单设备文档（root + 设备签名钥 + 设备 E2EE 钥），再让**本服务的解析器**发真
HTTP 取回它、验 e1 文档证明、按 `allowInsecureTransport` 那条联调口放行，最后用**真签的**
`origin_proof` 打真方法。脚手架脚本跑完已删（它靠改模块常量取巧，不该当测试留在仓库）。

**两跑对比**：

| 方法 | 现状（不改任何东西） | 隔离（仅替掉下面 (a)(b) 两件事） |
| --- | --- | --- |
| `group.create`（P4） | 3008 the origin proof did not verify | **200 OK**，拿到 `group_did` |
| `publish_key_package`（§8） | 1017 …#dev-1 does not declare `anp.group.base.v2` | **200 OK** |
| `group.e2ee.create`（§9） | （没走到） | **200 OK** |

**结论**：除了 (a)(b)，P6 的受理链路上**再没有别的东西挡着**。顺带证到一件有价值的事——
KeyPackage 的 `did_wba_binding` Object Proof 由设备自签，验证侧从**服务器发回来的那份文档**
里取公钥，验过了；说明 `bindingProblem` 与"从 DID 文档取钥"这条路对真实服务器输出是通的。

---

## A. 需要裁定的（按要紧程度排）

- ~~**A1 core 的指纹绑定管得太宽 —— 最要紧，P6 在真实 DID 网里跑不起来的直接原因。**
  `packages/core/src/crypto/resolveDid.ts:1100` 在解析**任何** keyid 时都
  调 `assertFingerprintBinding`（定义在 `packages/core/src/crypto/resolveDid.ts:1236`），
  要求解析出的那把钥的指纹等于 DID 路径段里的 `e1_`。可 1.2 单设备文档里，`e1_` 承诺的是
  **root** 钥，设备签名钥是另一把。于是 `${did}#dev-signing` 一律解析失败：
  `binds fingerprint "e1_…" but the resolved key's fingerprint is "e1_…"`。
  而 P6 §6.4 要求 origin proof 由设备的 `signing_key_id` 签——**今天本服务无法验证一台合规
  设备的 P6 调用**。这是一条审计驱动的安全控制（ANP-2026-09-11-01），动它就是动安全边界。
  选项：(i) 放宽成"只对文档自身证明用的那把钥绑指纹，其余 keyid 只要求被关系授权"；
  (ii) 保持现状，在文档里记成已知限制。**建议 (i)**，但需要你拍板。~~
  （2026-10-02 按 (i) 落地，`7028711`：只有"active e1_ 文档、证明策略为 required、且 keyid
  点名的不是那把证明钥"这一档才免掉整体绑定。免掉的底气是文档自身的证明——`assertDocumentProof`
  已经要求并以指纹绑定的那把钥验过它，其后取到的方法属于一份**已被认证的文档**，
  `assertAuthenticationAuthorized` 照旧把它限在 `authentication`。其余各档——`k1_` 或认不出
  的 profile、过渡态的 deactivated 文档、不带 fragment（按位选方法而非按名）的 keyid、
  以及证明钥自己——一律保持严格整体绑定。）

- ~~**A2 设备 profile 集合两边对不上。**
  `packages/service/src/rpc/groupE2ee.ts:144` 的 `GROUP_E2EE_DEVICE` 要
  `[core.binding.v1, identity.discovery.v1, group.base.v2, group.e2ee.v2]`——与规范 §4.2
  （spec 第 10 行、256–258 行）**逐字一致**。但 SDK 的 Manifest builder 只肯发布"全 v1 基础
  \+ `group.base.v1`"或"全 v2 基础 + `group.base.v2`"（四个 v2 基础 profile 是只读草案，
  服务器拒绝发布）。实测两个方向都试过：交 v1 组 → 服务器收、我方拒（缺 `anp.group.base.v2`）；
  交全 v2 组 → 服务器收、我方拒（缺两个 v1）。**服务器今天发不出任何一份能过我方资格门的
  文档。** 选项：(i) 我方迁就 SDK 改成 `group.base.v1`（与规范字面不符）；(ii) 推 SDK 侧让
  v2 基础 profile 可发布。**建议 (ii)**——(i) 是让实现去迁就一个上游的临时限制。~~
  （2026-10-02 按 (ii) 结案：**上游已经自己做了这件事，我方一行都不用改。** SDK 1.0.x 线里
  `_P6_CURRENT_DEPENDENCIES` 正好就是上面那四个 id，`anp.group.base.v2` 也从
  `_LEGACY_DRAFT_FOUNDATION_PROFILES` 里移出去了。同一份文档、同一个 profile 数组，
  **anp 1.0.3 拒**（`P6 device profile dependencies are incomplete`——1.0.3 的 `_P6_DEPENDENCIES`
  仍要 `group.base.v1`，且把 `group.base.v2` 当只读草案），**anp 1.0.5 收**；实测过这一对。
  `origin/master`（1.0.4rc1）与已发布的 1.0.5 都带着这个修法。故 `GROUP_E2EE_DEVICE` 保持
  规范口径不变——它本来就对，要动的是上游版本。**残留（不是本条的事了）**：这只证明"SDK 发得
  出来"，不等于"眼前这台服务器发得出来"。`awiki-open-server` 在 `anp_adapter.py` 里硬断言必须
  恰好 anp 1.0.3（加载别的版本直接 `RuntimeError`），它那段 profile 改写补偿正是为 1.0.3 写的、
  今天仍不可少（删掉即 2 例失败）；它何时挪到发得出这份清单的版本，与 A7 是同一件事，归服务器
  侧定。）

- **A3 对端身份状态的同步（换设备、换 DID、DID 服务器已更新而我们没同步）。**
  用户 2026-10-02 裁定：**换 DID 与绑定新设备都必须支持**——新绑的设备能收群消息，被取代的
  旧 DID 不能再收；并点名要想清楚"DID Server 更新了但 ANPMessageService 没同步"这一档。
  另裁定：同步走**定时刷新**，但要低负载。
  分三段，A3a 已落地：

  - ~~**A3a 一份共享的 DID 文档缓存 + 可配 TTL。**~~
    （2026-10-02 落地，`8d3bdef`：受理、投递、出站共用 `config.didResolution.documentStore`，
    `AGENTX_DID_CACHE_TTL_MS` 默认 5 分钟。不配它，一次投递会把同一份文档抓两遍——`discovery.ts`
    找入口与 `devices.ts` 读清单各调一次 `resolveDidDocument`。它同时就是"对端身份变化的发现
    时延上界"：ANP 不为文档变化提供推送（P2 §5.5 规则 8），窗口封不到零，只能封成一个部署
    能声明的数。缓存不放松判定——core 不写、也不读出 `deactivated` / 带 `successorDid` 的文档。）
  - ~~**A3b 投递前复核设备资格。**~~
    （2026-10-02 落地，`8d7bc95`：`deliverable()` 拆成 `projected()`，投影只判第一层；
    第二层按对方的**当前文档**判"这台设备还在不在主人的清单里"，只在第一层判成 active leaf +
    active 成员时才付，且与"找入口"共用同一份解析结果（A3a 的缓存），所以仍是一次网络往返。
    判定（文档取回来了、里面没有这台设备）→ 丢弃整条队列；解析失败 → 走既有失败路径退避重试，
    一次网络抖动不该丢掉一整条队列。**残留边界**已记进 [e2ee-group.md](docs/design/e2ee-group.md)
    §6.2：撤销与 `remove` 之间正好入队、又还没轮到的信封，会在 `remove` 把 leaf 转成 `terminal`
    后落进"按序投完"的例外。收窄它要在 `remove` 的受理路径上也读一次文档。）
  - ~~**A3c 换 DID。**~~
    （2026-10-02 落地。原本一条都没有：`member_did` 在 `group_members` / `group_leaves` 的**主键**
    里，成员的 DID 改不了（只能删一行加一行）；P4 §8.12 的 `member-did-updated` 本服务的 P4（C9）
    没有接受，`group_did_updates` 因此没有写入者。验证侧 core 早就写好
    （`packages/core/src/did/chain.ts` 走完转移链并给出四档保证），服务端补上的是调用它、按保证
    档位决定接受，再按 P6 §10.5 编排（暂停 → 逐设备 add 新 DID → 逐设备 remove 旧 DID → 恢复）。
    分四段，四条都已落地：）

    - ~~**A3c-1 请求触发。**~~
      （2026-10-02 落地：`rpc/memberDidUpdate.ts` 走 §8.12 受理前的第 1–3 条（从记录里当前
      存着的旧 DID 出发、用 core 的 `resolveDidChain` 走完整转移链、只收 `verified` /
      `recovery_verified`——用户 2026-10-02 裁定按**甲**，`provider_asserted` 一律拒），通过后
      由 `groups.ts` 的 `applyMemberDidUpdate` 在一个事务里改名册（只改 `member_did`，`role` /
      `status` / `joined_at` / `added_by` 靠"改一行"而非"删加"原样保留）、推两个计数器、排一条
      `member-did-updated`（正文带 `previous_subject_did` / `subject_did`，§7.10.2 L590）。
      触发面是 §8.12 L946 逐字那五个：四个无条件，`group.get_info` 只在**私有群**触发。
      比较并交换做在 `renameGroupMember` 的 `UPDATE ... WHERE member_did = <旧>` 上，返回 false
      即"另一条触发路已经做过了"；操作标识是 `group_did + 旧 + 新` 的确定性摘要。
      **`group_leaves` 一行都不动**（2026-10-02 更正：早先那版让 leaf 跟着搬，是错的——见 A3c-3
      与 `applyMemberDidUpdate` 的注释）。**§8.12 本身只覆盖了"新 DID 来办事"这一路**，
      另外两条触发路见下面两段。）
    - ~~**A3c-2 投递触发。**~~ 往旧 DID 投递时发现合规后继 → 先改完名册，再往**当前** DID 生成新的
      `group.incoming`。
      （2026-10-02 落地，`9beb201`：挂在设备队列**投递尝试前的资格复核**里（`delivery/deviceQueue.ts`
      的 `deliver()`，在 `checkDevice` 之前），那是唯一说得通的位置——§8.12 第 1 条要求起点恰好是
      一条 current DID 就是这个旧 DID 的 active 记录，而只有走到资格复核才知道收件人还是 active
      成员；那次链解析又与紧接着的设备复核共用同一份文档缓存（A3a），所以热路径上没有多出来的
      往返。采纳走的是**同一个** `applyMemberDidUpdate`，于是投递触发的改名一样会开 §10.5 的编排
      行、一样会暂停群；采纳之后这条路就停手，已入队的信封留在队里**不重排**（它等的不是时间、
      是一次控制动作，重排会把"等"记成"失败"），之后走 §12.3 的例外按序投完。档位低于策略、或
      后继已经是另一个 active 成员 → 拒绝，与请求触发同口径。**已知覆盖缺口**：一份被取代的 DID
      文档若仍留着 `deviceManifest`，`checkDevice` 会放行、信封会照旧投给旧地址——规范把投递触发
      写成 MAY，这条缺口由 A3c-4 兜住。测试见 `delivery/deviceQueue.test.ts` 的 "adopting a member
      DID change on the delivery path (§8.12)"（5 例）。）
    - **A3c-3 P6 §10.5 编排（Host 一侧已落地）。** ~~给 `group_did_updates` 一个写入者。~~
      （2026-10-02 落地：`applyMemberDidUpdate` 在"这次更新还留着旧 DID 的 leaf 要退役"时开一行
      `group_did_updates`，`expected` = 那批旧 leaf、进度 `add-pending`；`groupControl.ts` 的
      `paused()` 用**投影**（有一条 active leaf 的 DID 已不是 active 成员——§8.12 不动 leaf 正是
      为了让它自动成立，重启后照样判得出来）与**编排行剩余工作**两个证人取或，于是改名一落定群
      就停收新的 `group.e2ee.send`。串行化：这次更新的 `group.e2ee.add` 只能加新 DID 的设备、
      `group.e2ee.remove` 只能退役旧 DID 的 leaf，其余一律 5004（与暂停同码——对调用方是同一件
      事）。**业主义务 Host 判不了**：§10.5 要"全部 Add 成功之后才有第一个 Remove"，而 Host
      数不出 owner 选了几台新设备，所以第一次被接受的 Remove 就是"Add 阶段结束"的可观测信号，
      那行随之翻成 `remove-pending`；最后一次 Remove 清掉该行、旧 leaf 转 `terminal`，投影与编排行
      同时解除暂停。）

      校验与端到端测试在 `rpc/groupControl.test.ts` 的 "orchestrating the MLS side of a DID
      change (§10.5)"：开行/暂停、无关 Add 被拒、无关 Remove 被拒、匹配 Remove 收尾并恢复发送。
      三条触发路至此齐了——请求触发（A3c-1）、投递触发（A3c-2）、定时刷新（A3c-4）——都收敛到
      这一个改名，所以任一触发路发现的换 DID 都得到同一套编排与暂停。
    - ~~**A3c-4 定时刷新。**~~ 用户裁定的低负载周期扫描，兜住"对端 DID 服务器已更新、而我们还没被
      任何请求或投递碰到"这一档。
      （2026-10-02 落地，`6b56868`：`refresh/memberDidRefresh.ts` 只是钟，判定在
      `rpc/memberDidUpdate.ts` 的 `refreshMemberDids`，与投递触发共用 `adoptSuccessorOfRosterDid`
      ——§8.12 受理前那五条因此只有一份实现。**低负载由取行方式保证，不由承诺保证**：一轮只取
      `batch` 行、且最久没看过的最先（`groupMembersDueForDidCheck` 的排序），于是每轮开销是个常数
      （托管多少群、群多大都一样），而所有人仍按同一周期轮转，把 N 个成员轮一遍要 `ceil(N/batch)`
      轮。游标是 `group_members.last_did_checked_at`（schema v10，`addColumnIfMissing`）：它记的是
      "看过"不是"没问题"，解析失败也盖章，否则一个暂时不可达的对端会永远卡在队头，把所有人挡住。
      `staleAfterMs` 取 `intervalMs`，所以那个间隔是每个成员的**最短**复查周期。两个数是部署档位：
      `AGENTX_DID_REFRESH_INTERVAL_MS`（缺省 6h）与 `AGENTX_DID_REFRESH_BATCH`（缺省 20）——一个
      1000 成员的部署按缺省约 12 天轮一遍，每轮仍是 20 次解析。启动时**不**立刻扫一轮：刚起来的
      进程正忙着开端口装订阅，几十次解析压在那个时刻没有好处。它单开一个 worker 是因为节奏与设备
      队列差四个数量级。测试：`refresh/memberDidRefresh.test.ts` 8 例（采纳并开编排行、无 leaf 的
      安静成员也能改、看过就出批、按最久未看轮转、低档位拒绝仍盖章、解析失败仍盖章、后继已是
      active 成员则不并、非 active 不入批）+ `storage/sqlite.test.ts` 的游标三条与 v9→v10 迁移
      一条。**这一层只负责"看一眼"**：退役旧 leaf 仍要 owner 按 §10.5 编排。）

- ~~**A4 同 DID 的 Remove 分支 v1 不做，回 5003。**
  理由写在 `packages/service/src/rpc/groupControl.ts:52`：该分支的前置是
  "目标设备已撤销/已失去资格"这个**否定**结论，而本服务是**肯定**门禁；且它还要 Host 验"发送
  设备有当前设备管理授权"，P2 清单里没有这个概念可读（只有 `signingAuthorizedBy` /
  `e2eeAuthorizedBy` 两个关系）。这是**收窄不是放行**（该拒的仍拒），但那条合法路径暂时不可用。
  选项：接受 v1 缺失，或补一个"否定门禁"的表达。~~
  （2026-10-02 裁定按**甲**：接受 v1 缺失。复核时找到一句把它从"缺口"变成"规范要求"的话——
  §13.4 L148 逐字："设备管理授权是受信任的**部署侧**授权事实，不是新的 P6 请求字段。Group Host
  若无法权威验证，**MUST** 拒绝该例外，且 **MUST NOT** 信任调用方自报或展示缓存。"我们手里没有
  那份部署侧事实，所以拒绝正是规范点名要的行为，现状即合规、没有合规压力。将来要开这条路，先
  得定出那份授权事实的来源（谁写、存哪、怎么签发与轮换）——规范明说它不是协议字段；在信任模型
  定下来之前不开，定错等于给同 DID 下的设备开了互相移除的权限。已落进
  [e2ee-group.md](docs/design/e2ee-group.md) §4.2 第 3 条、§12 与 `groupControl.ts` 的注释。）

- ~~**A5 两个有界保留闸门是 worker 选项，不是 Config 设置。**
  `maxAttempts` 默认 8（`packages/service/src/delivery/deviceQueue.ts:49`）、
  `maxQueueAgeMs` 默认 24h（`packages/service/src/delivery/deviceQueue.ts:55`），
  今天要调只能改代码。选项：提升到 `Config` 做成部署档位。**建议提**（运维会想调）。~~
  （2026-10-02 落地，`ec4e273`：`AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS`（缺省 8）与
  `AGENTX_DEVICE_QUEUE_MAX_AGE_MS`（缺省 24h），解析口径与其他数值设置一致——空值当未设、
  非正整数在启动时拒绝而不是悄悄钳住。worker 选项保留作覆盖，测试仍可钉住某一条上限。）

- ~~**A6 §12.6 第 3 项"投递前复核"的判据。**
  规范这句没给判据，现取"每次尝试前重跑资格检查，仅点名的那两个例外放行"（在
  `deviceQueue.ts`）。这是我定的读法，可复核。~~
  （2026-10-02 复核过，**读法与实现一致，不改**。§12.6 第 3 项（L1506）逐字只说了"入队前与
  每次投递尝试前复核当前资格、不再是当前合格 leaf 就停投"，判据确实留白；例外它也点明只有两个。
  代码里这两个例外各有一个明确的落点：`final-notice` 在 `projected()` 开头直接放行（§12.3 的
  最终通知），`leaf.state === 'terminal'` 也放行（就是"下文允许的、已为该 leaf 入队的信封"——
  leaf 转入 terminal 之后只有 `emitRemoveEnvelopes` 会碰它，而那一位只写最终通知，所以队里剩下
  的应用信封必然是 Remove 之前入队的）。其余各档都比规范更严而不是更松：成员已不是 `active`
  的中间态是 `hold`（§10.4/§10.5 的 epoch 不许承载应用消息），两层都过不去才 `drop`。另有一处
  规范没写、我方自定的区分：**取回了文档、里面没有这台设备**是判定（丢整条队列），**文档解析
  失败**只是这次失败（记一次尝试、退避重试），避免一次网络抖动丢掉整条队列。）

- **A7 服务器侧的部署结论（不是我们的 bug，但挡住真实部署）。**
  `awiki-open-server` 只肯发布 `ANPMessageService` 端点指向**它自己**的签名文档，否则
  `signed_did_document_service_endpoint_mismatch` / `..._service_did_mismatch`。所以一份指向
  我们服务的、带 P6 能力的文档，今天**没法在那个服务器上发布**。要真实部署落地，这条得服务器侧
  放开——需要你去跟那边定。
  （2026-10-02 把要谈的东西定到行：判定在
  `awiki-open-server/src/awiki_open_server/user_compat/core.py:336-345`，收的是**签名**文档里
  那**唯一一条** `ANPMessageService` 服务项，两条硬相等——`serviceEndpoint` 必须等于
  `settings.anp_service_endpoint`、`serviceDid` 必须等于 `settings.service_did`。而这两项就是
  服务器自己（`app/settings.py:28,81`）。**没签名的那条路更彻底**：`core.py:347` 起直接把
  对端声明的服务项**替换成**服务器自己的模板，所以"不带证明"也绕不过去。今天唯一相关的开关是
  `AWIKI_ALLOW_UNSIGNED_PEER_DEV`（`app/settings.py:33`），它只放宽"要不要证明"，不放宽"端点
  归谁"。另有两点顺带记下：服务器自己广告的 profile 集
  （`protocol/registry.py:10` 的 `STANDARD_PROFILES`）里有 `anp.group.base.v1` 和
  `anp.group.base.v2`，**没有 `anp.group.e2ee.v2`**——即它今天不对外声明 P6 能力；以及它的 SDK
  锁在 anp 1.0.3（见 A2 残留）。要谈的就是一句：**让服务器接受一份由对端签名、端点指向别处
  的 `ANPMessageService` 文档**，放开后面这些都会跟着动。）
  （2026-10-02 第二段：**这条不用去跟上游谈了**——用户已经 fork 了 `awiki-open-server`，明确说
  "可以按照 fork 出来的代码继续修复和更新，不一定等上游去调整"。所以放开这件事改成我们自己
  在 fork 里做。落法是 `adc796c`（`main`，**未推**）：新增开关
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE`（默认 `False`，`app/settings.py:34`），打开后
  `user_compat/core.py` 的 `_ensure_anp_message_service` 改走 `_check_peer_declared_message_service`
  ——只检查**形状**（`serviceDid` 是 `did:` 开头、`serviceEndpoint` 是带 host 的 http/https URL），
  不再要求等于服务器自己。刻意**不**要求 https：传输策略归解析方，不归发布方，发布侧硬要求
  https 只会把内网/自签部署挡在门外。默认关掉是刻意的——这是把"端点归谁"的裁决权从服务器
  让给签名方，属于放开而不是修 bug，不该在没打招呼的情况下对所有部署生效。
  **部署还差一步（运维侧，不是代码）：在需要接受对端端点的那台服务器上设
  `AWIKI_ALLOW_PEER_DECLARED_MESSAGE_SERVICE=1`。** 测试两条，都验过会红：一条走通
  "对端声明的 `did:wba:awiki.info` / `https://awiki.info/anp-im/rpc` 原样保留并发布"，
  一条把 `serviceDid: "agentx.example"`、`serviceEndpoint` 为 `""` / `"not-a-url"` / `"https://"`
  逐个打回。按用户口径这条路是"独立出来"，后续 fork 与上游分叉是预期内的，不是要回收的债。）

**A1 与 A2 是前置**：这两个不定，P6 在真实 DID 网里跑不起来，其余几条都只是能力边界。
（2026-10-02：**两条都清了**——A1 按 (i) 落地（`7028711`），A2 结在上游 1.0.x，我方不改代码。
所以"P6 在我方这一侧跑不起来"这个前置已经不存在；接着挡路的是服务器侧的口径——A7 的端点绑定，
以及 awiki 锁在 anp 1.0.3，两者都不在本仓库里。）

---

## B. 承接 TODO1 未划掉的

- **B1（= TODO1 C11 尾）** `group.*` / `attachment.*` 两族的**跨域出站**判断——今天落本地、
  响亮失败。两族的锚点各异（P8 §3.2），接口留在 `dispatch.ts` 的 `relayFor`。
  另有 C11 记的"挡住 v1 的"两条：群 DID 文档没人发布（§5.2 L220 要求解析 `group_did` 才能
  找到 Host）；`serviceDid` 文档由 `awiki-open-server` 托管，外层 `keyid` 的 fragment 必须与它
  写进去的一致（与 A7 同源）。
- ~~**B2（= TODO1 E4，端到端）** `connectx msg send` → `AgentXAgent` → `connectx msg listen` 收到。
  今天 P4/P5/P6 都是**方法级**测过、**没串起来端到端跑过**。A1/A2 定了之后，这条应该顺带把
  P6 也串进去。~~
  （2026-10-02：补了第四个 workspace `packages/e2e`，3 条用例串起 发送/收取/补历史/实时推送 四段。
  服务侧用真 `loadConfig` + `createDispatch` + `createServer` + `createStreamSession`，与 `main.ts`
  同一批模块同一批参数；客户端侧跑 `runMsg` / `runListen` 本体，真随机钥、真签名、真 WebSocket。
  唯一替身是"谁托管 DID 文档"——一台按 `didToUrl` 推出来的路径发 `application/did+json` 的玩具主机；
  真拿 `awiki-open-server` 当主机就测不到"对端服务在别处"（同 A7）。两个坑各留了一句注释：
  端口必须先占（`config.publicUrl` / `serviceDid` / `stream.hello` 要三处一致），`--once` 在补完
  历史后就结束、测实时推送得注 `ListenView` + `AbortSignal`。跑法 `npm run test:e2e`。）
- ~~**B3（= TODO1 A7 尾）** `packages/service` 里不得直连 `resolveDidDocument`——消息定址一律走
  `ServiceLocator` / `KeyResolver`。core 里那 5 处与 CLI 那 2 处是 ANP-02/03/04 自己的解析，
  **留着**，只有 service 这一侧要收敛（E3 的评审清单钉这条）。~~
  （2026-10-02 核过：`packages/service/src` 里 `resolveDidDocument` / `resolveDidChain` **零处**，
  全部经 `ServiceLocator` / `KeyResolver` / `DeviceResolver`。这条是早期收敛留下的结论，今天
  不需要改动。）
- ~~**B4（= TODO1 E2 缺口）** `help.test.ts` 的第三条门禁读 `skill/connectx/SKILL.md`，而那份
  skill 没搬过来，已随删除记录。要搬 skill 就把它一起恢复。~~
  （2026-10-02 用户裁定**要**，已落地。但**是重写不是搬运**：旧仓库 `anp-sdk` 那份 289 行照着
  **旧 CLI** 写——装的是 `@connectx-sdk/cli`、讲的是 `anp login/sign`、装法写全局安装，本仓库的
  消息层（`msg` / `group`）一个字没有，而消息层才是这个仓库对外的主线；照搬门禁立刻红，且红得
  没意义。新那份按今天的命令面重写，一个命令一条，判据仍是那句"skill 不重述命令面、只带判断"
  （`--help` 才是权威）。门禁原样搬回 `help.test.ts`（`skillInvocations()` 逐字同旧），
  两条路都验过会红：`msg teleport` → "has no such page"，`msg send --bulk` → "does not accept
  --bulk"。CLI 测试 207 → 209。）
- ~~**B5（= TODO1 E3）** 评审清单：CLI 与服务端里**不得出现 `isDid()` 之类的身份类型分支**
  （[vendored-core.md](docs/design/vendored-core.md) §6.3）。~~
  （2026-10-02 审过并修掉唯一一处：`packages/cli/src/commands/auth.ts` 的 `isDidIdentifier`
  用 `didHost` 试一下再决定 `printIdentity` 印 `did:` 还是 `account:`，正是 §6.3 说的"在命令层
  复制一份判断"——[locator.ts](packages/core/src/message/locator.ts) 的 `isDidIdentity` 注释
  已写明那份判定"只在这里使用"。改法是**不由 CLI 判**：`--wallet web3` 这条路径的契约本就要求
  `--address` / `--chain-id`（`buildConnector`），产出的必然是 CAIP-10 账户 id，所以 `document`
  由调用点按自己已知的事实传 `false`，并删掉那个助手。service 侧 `isDid` 零处。）
- ~~**B6（= TODO1 CI）** 仓库里没有 `.github/workflows`，`gh run list` 为空——门禁目前只能在本地
  按 job 分组跑。要真正的 CI 得补 workflow（我可以写，但 `.github/` 那条路径和要不要跑在
  GitHub 上得你定）。~~
  （2026-10-02 用户裁定**要**，已落地 `.github/workflows/ci.yml`，跑在 GitHub 上（远端是
  `eccstartup/AgentX`）。一个 job 四步：`npm ci` → `npm run build` → `typecheck` → `test`。
  两点是刻意的：**`build` 不是形式**——每个包的测试按包名 import `@agentx/core`，而那个名字解析到
  `packages/core/dist`，所以空检出跑 `npm test` 会红得像是测试坏了而不是缺构建；**Node 钉
  `'24'`** 是钉 `engines` 声明的下限（>=24.16.0），声明了最小值却从没跑过它就只是个说法。
  整套顺序在本地从 `rm -rf packages/*/dist` 起验过一遍。e2e 也在里面——它最慢，但它是唯一一个
  能发现"两半各自都对、拼起来不对"的那组。）
- ~~**B7（= TODO1 E5 剩最后一步）** 文档站的 Vercel 连接要你的账号，我做不了。~~
  （2026-10-02 完成。用户接了 Vercel，站上线在 **https://agentx-docs.vercel.app**（中文 `/`、
  英文 `/en/`，两页都验过 200）。仓库侧随之改了三处：`packages/cli/src/help/commands.ts` 的
  `DOCS_BASE` 从 `github.com/eccstartup/connectx/blob/master/githubpages`（**旧仓库旧路径**，
  26 条 `See:` 因此条条 404）改成站点 origin，26 处 `see` 从站上并不存在的
  `cli/api/*.md` 改成 `en/reference/cli`（本站只有这一个 CLI 参考页）；`docs/design/cli.md`
  §3 新增小节说清"文档门禁"在这个仓库的实际射程；
  `README.md` 的文档一节换上线上地址。
  另外把那条门禁**真的做出来**了（`help.test.ts` 第四条）：把每个 `see` 拼成 `vercel/<see>.md`
  在磁盘上找一遍，并钉住 `DOCS_BASE` 是裸 origin、`see` 不带前导斜杠且都在 `/en/` 下。
  三种坏法都验过会红：页名不存在、`DOCS_BASE` 换回旧仓库、`see` 加前导斜杠。射程仍有限——
  它只保证链接活着，不保证文档页和命令面一致，后者要先让文档页由 `commands.ts` 生成。）

---

## C. 下一轮（要新做的）

- **C1 P6 不得对外声明，直到上游给出稳定 code point。**
  见 [e2ee-group.md](docs/design/e2ee-group.md) §13 与 TODO1 D2：MLS `ExtensionType 0xF0A1`
  还是草案私有值，规范说 ANP 在发布 v2 前 MUST 公布稳定注册 code point（§6.3.1 L430、
  §20 L2457）。已落成 `capabilities.ts` 的 `WITHHELD_PROFILES`（`capabilities.test.ts` 钉住
  "只有这一条"）。**上游公布后**：移除扣留、把 P6 放进 `anp.get_capabilities` 的稳定 Profile
  列表，并复核 [e2ee-group.md](docs/design/e2ee-group.md) §13 的那段门禁描述。
- **C2 客户端侧群 MLS 的密码学库。**
  TODO1 D4 已定"内嵌进 `connectx`"（与官方 SDK 同向，官方明写群 MLS 是库调用、不是子进程调用）。
  v1 不受影响，但要真跑群 E2EE 就得写 Rust crate → Node 的 napi 绑定。这是**独立的一块**，
  规模不小，需要你定什么时候开。
- ~~**C3 群 DID 文档的发布路径。**
  §5.2 L220 要求解析 `group_did` 才能找到 Host，而今天没人发布群 DID 文档。这与 A7 是同一类
  问题（谁来托管、托管在哪），要一起定。~~
  （2026-10-02 核过：**这条的前提是错的，不需要做任何事**。原先的判断只看了
  `group_did_documents` 这张表，没注意 `hosted_group_create` 在同一个事务里**也**往
  `did_documents` 写了一份（`messaging/groups/service.py:531-533`），而 `resolve_did_path`
  （`app/routes.py:590`）读的正是 `did_documents`——所以群 DID 文档是**发得出来、解析得到**的，
  `tests/test_group_host.py:152` 就在钉这件事（建组后按
  `/groups/<grp>/<e1_fp>/did.json` 取回，断言 `id` 是 `group_did`、
  `service[0].serviceDid` 是托管服务器自己）。群文档里也不含成员名册，只有 id + 一把验证钥 +
  一条 `ANPMessageService` 服务项，所以"公开可解析"不泄露成员关系。我方这一侧同样无需改动：
  `didToUrl` 对这种 DID 的映射是 `https://<host>/groups/<grp>/<e1_fp>/did.json`
  （`packages/core/src/crypto/resolveDid.ts:520`），与服务器的路由严丝合缝；而
  `packages/service/src` 里没有任何 `groups:` DID 的签发逻辑——
  `AgentXAgent` 不托管群、只按 `ServiceLocator` 统一解析群 DID 去找 Host，与 B3 收敛后的
  口径一致。剩下真正未决的只有"谁来托管"这个设计问题，而它的答案是自洽的：**群挂在谁身上，
  谁的服务器就发布它的文档**，awiki 已经这么做了。上游要不要把这个行为固化成规范条文，
  是上游的事，不是本仓库的缺口。）

---

## D. 工程（沿用 TODO1 的口径）

- 每个 C 任务一次提交，格式 `feat(service): <摘要> (C<编号>)`，同时动 `TODO*.md` +
  `docs/design/*.md` + 源码 + 测试。
- 提交信息末尾 `Co-Authored-By: Claude Code <noreply@anthropic.com>`；PR 描述末尾
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`。
- 不提交密钥。
- 当前基线：`ec61ae8`，`npm run typecheck` 通过，`npm test` 207 + 693 + 620 全绿。
  （2026-10-02 更正计数：服务端那组从 581 长到 620——A3c 的四段各自带了测试。）
  （2026-10-02 B2 之后：多一组，`npm test` = 207 + 693 + **3** + 620，第四组是 `packages/e2e`。
  它一个文件就 4.5 秒——每条用例都真起一个服务、真连一次 socket，所以它比别组长，但不是卡住。）
  （2026-10-02 B4 之后：CLI 那组 207 → **209**，多的是 skill 门禁的两条。）
