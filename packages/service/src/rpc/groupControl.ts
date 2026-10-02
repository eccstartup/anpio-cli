// C13 —— P6 §9 的四条控制面方法：把 P4 已经定下的业务状态落成 MLS 结果。
//
// 四条分两档，与 `groupE2ee.ts` 那两条 Key 方法合起来才是 P6 的全部：
//
//   create                      service-scoped（§4.4.1 L292–293，刻意如此）
//   add / remove / send         group-addressed（§4.4.2）
//
// 安全模式是 `group-e2ee`（§4.3 L273），不是两条 Key 方法那一档 `transport-protected`
// （L272）。**四条都要 `auth.origin_proof`**（§9.2.3 / §9.3.3 / §9.4.3 / §9.5.3 逐字
// "MUST exist"），这是与两条 Key 方法最大的差别——它们靠 KeyPackage 自己的 Object Proof，
// 这四条靠调用方的业务层证明。
//
// §13.6 L1693 又给这四条添了一句两条 Key 方法没有的话：Host **MUST** 受理时施加"完整新鲜度
// 窗口 **+** 一次性 nonce 检查"。两半都不在这个文件里：时间窗由 `auth.ts` 的 `authenticate()`
// 判（它本来就在每次受理前跑），nonce 由 `dispatch.ts` 的 `consumeProofNonce()` 兑——位置
// 为什么在 `perform` 里面，理由写在那两处。
//
// ## 本服务在这里做什么：只记账，不做密码学
//
// §3.6 L199–204 把 Host 钉在成员与见证者的位置上。四条控制动作送到这里的材料
// （`commit_b64u` / `welcome_b64u` / `ratchet_tree_b64u` / `private_message_b64u`）本服务
// **一个字节都不解释**——§11.11 L1386 明说 Host 不做最终 MLS 有效性判断，§13.4 L1649 又
// 说 Host 的检查 **MUST NOT** 取代成员 runtime 的验证。所以这里判的是三件本服务真能判的：
//
//   1. **形状**：该在的字段在不在、`*_b64u` 是不是无填充 base64url、`epoch` 是不是十进制
//      字符串（§14.1 L1708 逐字要求外层对象里的 `epoch` 是十进制字符串）；
//   2. **归属**：KeyPackage 的 owner 是不是这次点名的那个 `(member_did, member_device_id)`，
//      它的 `did_wba_binding` 与那台设备**当前**的清单对不对得上（§6.4 第 4–6 项）；
//   3. **顺序**：这个 `(did, device)` 该不该是 leaf、这个 `epoch` 是不是在往前推、
//      `crypto_group_id` 是不是这个群的那一个。
//
// ## 群级密码学绑定就是投影本身
//
// `crypto_group_id` / `epoch` 的"群当前值"**不另建一张表**（[e2ee-group.md] §5）：MLS 的
// Commit 本来就推进所有成员的 epoch，`add` / `remove` 的 `epoch` 按 §9.3.3 / §9.4.3 是
// "after this add/remove"，于是把新值写到**每一条 active leaf** 上，群级值就是这些行共同
// 说的那句话。`create` 写下的第一行（owner 自己，§9.2.1）就是初始值。这带来一条不变量：
//
//   > 同一群的 active leaf 行上，`crypto_group_id` 与 `epoch` 恒等。
//
// `advanceLeaves()` 是唯一维护它的地方，`currentBinding()` 是唯一读它的地方。§13.5 第 5
// 项"该群当前没有已被接受的 MLS 初始状态"因此就是"这个群的 active 投影是空的"。
//
// ## 计数器：控制动作一个都不推，`send` 只推事件序
//
// §14.1 L1705 逐字："P4 business operation and `group.e2ee.send` enter the group event
// ordering link"——进排序链的只有 `send`。紧接着 L1707 说 `create` / `add` / `remove`
// "**MUST NOT** independently create a new P4 `group_state_version`"，§9.2.4 连
// `group_event_seq` 也一起排除。所以：控制动作两个计数器都不动，`send` 只推 `event_seq`
// （与 P4 的 `group.send` 同级），`group_state_version` 原样回给调用方。
//
// ## v1 挡住的：同 DID 的 Remove 分支
//
// §9.4.2 给 `remove` 两条 caller 分支，第二条是"同一 DID 的另一台已撤销/已失去资格的设备
// 由本 DID 的当前 leaf 移除"。这条**没做**：它的前置条件是"目标设备已撤销或当前 P2 不合
// 资格"——一个**否定**的资格结论，而本服务的资格门禁（`eligibility.ts`）是**肯定**门禁，
// 只对方法表声明的那几对设备判"合格"，没有"要求它不合格"的表达；并且同一句还要求 Host
// 权威验证"发送设备有当前设备管理授权"，而 P2 的清单里没有这个授权概念可读（只有
// `signingAuthorizedBy` / `e2eeAuthorizedBy` 两个关系）。所以 v1 只有 owner 分支，走第二条
// 分支的请求拿到 **5003** `controller_required`。这是**收窄**不是放行——一个合规实现不会
// 把该拒的收下，但它会让那条合法路径暂时不可用。记在 [e2ee-group.md] §4.2。
//
// ## v1 挡住的：proof 是不是那台设备的钥
//
// §13.3 L1626 与 §9.5.3 要求 `send` 的证明"由该设备当前的 P2 签名钥做出"。这一条**做了**
// （见 `sendE2eeMessage`），core 因此把签名底里的 `keyid` 一起交回（`OriginProofOutcome`）。
// 另外三条**没有**这一句（§9.2.3 / §9.3.3 / §9.4.3 只要求 `sender_device_id` 标识一台合格
// 设备），所以那里认到 DID 为止，设备是自报 + 资格判定——与 P5 的立场相同
// （[e2ee-direct.md] §9 第 3 条），没有自造一条规范没给的禁令。

import type { AnpMeta, AnpRejection } from '@agentx/core'
import { anpRejection, profileRejection } from '@agentx/core'
import type { Storage } from '../storage/types'
import type { EligibleDevice } from './eligibility'
import { P1_AUTH_CODES } from './auth'
import {
  emitAddEnvelopes,
  emitIncomingEnvelopes,
  emitRemoveEnvelopes,
} from './groupEnvelopes'
import {
  bindingProblem,
  device,
  groupE2eeError,
  isPlainObject,
  keyPackageShapeProblem,
  nonEmptyString,
  requireServiceTarget,
  senderDeviceOf,
  senderOf,
} from './groupE2ee'
import {
  RECEIPT_MESSAGE,
  activeMemberDids,
  groupReceipt,
  loadGroup,
  requireActiveMember,
  requirePermission,
} from './groups'
import { AnpRefusal, refusal } from './refusal'

export const GROUP_E2EE_CREATE = 'group.e2ee.create'
export const GROUP_E2EE_ADD = 'group.e2ee.add'
export const GROUP_E2EE_REMOVE = 'group.e2ee.remove'
export const GROUP_E2EE_SEND = 'group.e2ee.send'

/** §4.3 L273。四条共用，与 `transport-protected` 那一档分开写：两条规范行，两个值，
 *  合并成一处会让 P6 的这一档跟着 P5 的改动走（`groupE2ee.ts` 上写了同一条理由）。 */
export const GROUP_E2EE_SECURITY_PROFILE = 'group-e2ee'

/** §9.5.3 逐字：`send` 的 `meta.content_type` **MUST** 固定为它。
 *
 *  **不进** `payload.ts` 的 `ACCEPTED_CONTENT_TYPES`：那份清单是"本服务自报认识的内容
 *  类型"，不是准入白名单（`payload.ts` 上写了），而它承载的 Profile 正在被扣留
 *  （§6.3.1 L430 的 codepoint 还没稳定）——对外列一个没有 Profile 能承载的内容类型，
 *  是自相矛盾。 */
export const GROUP_CIPHER_CONTENT_TYPE = 'application/anp-group-cipher+json'

// ---- 请求自身的形状（1003） ----------------------------------------------------

/** 请求自身的形状问题一律 §10.3 L704 的 1003。错的是**请求**，不是材料，也不是权限
 *  （与 `groupE2ee.ts` / `groups.ts` 里那两个同名的私有函数同一条分工）。 */
function shapeProblem(message: string): AnpRejection {
  return anpRejection('anp.invalid_params_shape', message)
}

/** 正文里的一个非空字符串；缺了/空串是 1003。 */
function text(body: Record<string, unknown>, key: string): string {
  const value = body[key]
  if (!nonEmptyString(value)) throw refusal(shapeProblem(`body.${key} MUST be a non-empty string`))
  return value
}

/**
 * 无填充 base64url（§7.1 L489 / §9.3.3 / §9.5.3 的 `*_b64u`）。
 *
 * 只判字符集与"没有填充"——**不**判它是不是能解出一段有意义的字节：`commit_b64u` 之类
 * 的内容归接收方的 MLS runtime（§11.11 L1386）。这里判的是"它至少是按那个编码写的"，
 * 一个带 `+` / `/` / `=` 的串连这一步都过不去。
 */
const BASE64URL = /^[A-Za-z0-9_-]+$/

function isBase64Url(value: unknown): value is string {
  return typeof value === 'string' && value !== '' && BASE64URL.test(value)
}

function base64Url(body: Record<string, unknown>, key: string, code: 'request' | 'material'): string {
  const value = body[key]
  if (isBase64Url(value)) return value
  const message = `body.${key} MUST be no-padding base64url`
  // 请求自己那一层的字段（`crypto_group_id_b64u` / `epoch` / `group_state_ref`）是 1003；
  // `group_cipher_object` **内部**的字段属于那个对象（§7.4），归 5007。分界是"这个字段是
  // 请求要求带的"还是"它是另一个对象自己的成员"。
  throw refusal(code === 'request' ? shapeProblem(message) : groupE2eeError('privateMessageInvalid', message))
}

/** §14.1 L1708：外层对象里的 `epoch` **MUST** 是十进制字符串（§7.3 L491 同一件事）。
 *  用字符串而不是数字是有意的——MLS 的 epoch 是一个不设上限的计数器。 */
function isDecimal(value: unknown): value is string {
  return typeof value === 'string' && /^\d+$/.test(value)
}

function decimal(body: Record<string, unknown>, key: string): string {
  const value = body[key]
  if (!isDecimal(value)) throw refusal(shapeProblem(`body.${key} MUST be a decimal string`))
  return value
}

/**
 * §7.2 L495–499 的 `group_state_ref`。
 *
 * 判三件：它是个对象、`group_did` 与外层 target 一致（§9.2.3 / §9.3.3 / §9.4.3 各写了一遍
 * 这句，字面相同）、`group_state_version` 是十进制字符串。第三件不是规范的点名要求，而是
 * §7.2 说它"至少"要含这个字段——一个不含它的 `group_state_ref` 没有把四个坐标系里的业务
 * 版本带上，那正是这一节存在的理由。
 *
 * `policy_hash` 不判：§7.2 L499 把它写成"如果群策略被哈希过"，是一个条件句。本服务的
 * P4 侧对策略不做哈希，所以这个字段在**本服务能观测到的世界里**没有产生路径；判它就会
 * 拒掉一条合规请求。
 */
function groupStateRef(value: unknown, groupDid: string, method: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw refusal(shapeProblem(`${method} requires an object body.group_state_ref`))
  if (!nonEmptyString(value.group_did)) {
    throw refusal(shapeProblem('body.group_state_ref.group_did MUST be a non-empty string'))
  }
  if (value.group_did !== groupDid) {
    throw refusal(
      shapeProblem(`body.group_state_ref.group_did MUST equal the outer target group_did (${groupDid})`),
    )
  }
  if (!isDecimal(value.group_state_version)) {
    throw refusal(shapeProblem('body.group_state_ref.group_state_version MUST be a decimal string'))
  }
  return value
}

// ---- 请求正文校验（1003） ------------------------------------------------------

/**
 * 四条的正文规则**在这里声明一次**，处理器里再走一遍同一批助手。
 *
 * 跑两遍是两件不同的事，不是重复：
 *
 *   - `validateBody` 由 `dispatch.ts` 在 `deviceAddressed` **之前**调用（L378 vs L387）。
 *     `add` 的设备定址要读 `body.member_did` / `body.member_device_id`，而它在方法表那
 *     一层只是个 `bodyString()`——缺字段会当场抛 `ConnectxError`（500），不是一条体面的
 *     拒绝。所以那两段必须在正文校验这一步就有答案。
 *   - 处理器那一遍在拿到群状态与设备之后跑，借同一次调用把值收窄成 `string`（`text()` 的
 *     返回类型）。**规则本身只有一份**：两个函数调用的是同一批助手。
 *
 * 不加"未知字段"白名单：§9.2.3 / §9.3.3 / §9.4.3 说的都是正文"至少"含那几个字段（`groups.ts`
 * 的 `validateSendBody` 上写了同一条理由）。拒掉规范允许的请求不是严谨。
 *
 * `send` **没有** `validateBody`，这不是漏写：它唯一的正文要求是 `group_cipher_object`，
 * 而 §13.3 L1627 把那一项定在**第 8 项**，并逐字要求前面几项「MUST resolve them in this
 * order, before the policy check 7 and the payload check 8」。把它提前到方法表这一层，
 * 等于让一颗正文有缺的请求抢在"你是不是成员"（第 4 项）之前被拒——那正是那条次序要防的。
 * 而且 `send` 的设备定址只点名调用方自己（不读正文），所以这里也没有非提前读不可的字段。
 */
function caught(err: unknown): AnpRejection | undefined {
  // `groups.ts` 里那份私有的 `caught` 的本地版：助手抛的是 `AnpRefusal`，而 `validateBody`
  // 的契约是"返回拒绝或 `undefined`"。别的异常照旧往上抛——那是代码错。
  if (err instanceof AnpRefusal) return err.rejection
  throw err
}

/** §9.2.3 正文的六项。`creator_key_package` 只判"是对象"：它像不像一个 KeyPackage 是 5001
 *  （`keyPackageShapeProblem`），不是请求自己的形状。 */
export function validateCreateE2eeBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    const groupDid = text(body, 'group_did')
    groupStateRef(body.group_state_ref, groupDid, GROUP_E2EE_CREATE)
    if (!isPlainObject(body.creator_key_package)) {
      throw refusal(shapeProblem(`${GROUP_E2EE_CREATE} requires an object body.creator_key_package`))
    }
    base64Url(body, 'crypto_group_id_b64u', 'request')
    decimal(body, 'epoch')
    text(body, 'suite')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

/** §9.3.3 正文的那几项，以及 §13.4 L1640 第 2 项要读的两段设备身份（`member_did` /
 *  `member_device_id`）。 */
export function validateAddE2eeBody(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined {
  try {
    // `group_state_ref.group_did` 要对着外层 target 判，所以先把 target 取出来——它由
    // `checkMethod` 的 `group-addressed` 保证在场（缺了是方法表与这里不一致，抛）。
    const groupDid = groupTarget(meta)
    text(body, 'member_did')
    text(body, 'member_device_id')
    groupStateRef(body.group_state_ref, groupDid, GROUP_E2EE_ADD)
    base64Url(body, 'crypto_group_id_b64u', 'request')
    decimal(body, 'epoch')
    base64Url(body, 'commit_b64u', 'request')
    base64Url(body, 'welcome_b64u', 'request')
    base64Url(body, 'ratchet_tree_b64u', 'request')
    if (!isPlainObject(body.group_key_package)) {
      throw refusal(shapeProblem(`${GROUP_E2EE_ADD} requires an object body.group_key_package`))
    }
    return undefined
  } catch (err) {
    return caught(err)
  }
}

/** §9.4.3 正文的那几项。比 `add` 少 `group_key_package` / `welcome_b64u` /
 *  `ratchet_tree_b64u`——移除一个 leaf 不需要给谁 Welcome。 */
export function validateRemoveE2eeBody(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined {
  try {
    const groupDid = groupTarget(meta)
    text(body, 'member_did')
    text(body, 'member_device_id')
    groupStateRef(body.group_state_ref, groupDid, GROUP_E2EE_REMOVE)
    base64Url(body, 'crypto_group_id_b64u', 'request')
    decimal(body, 'epoch')
    base64Url(body, 'commit_b64u', 'request')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

// ---- 投影：群当前的密码学绑定 ------------------------------------------------

interface CryptoBinding {
  cryptoGroupId: string
  epoch: string
}

/** 群当前的 `(crypto_group_id, epoch)`，`undefined` = 这个群还没有被接受的 MLS 初始状态
 *  （§13.5 第 5 项）。读第一条 active leaf 就够——文件头那条不变量保证了它们一致。 */
function currentBinding(storage: Storage, groupDid: string): CryptoBinding | undefined {
  const first = storage.activeGroupLeaves(groupDid)[0]
  if (first === undefined) return undefined
  return { cryptoGroupId: first.cryptoGroupId, epoch: first.epoch }
}

/**
 * 把新 `(crypto_group_id, epoch)` 写到每一条 active leaf 上。
 *
 * 这是文件头那条不变量的**唯一**维护点，也是"群级绑定"这个概念的全部实现。新 epoch 是
 * §9.3.3 / §9.4.3 要求调用方报的那个（"after this add/remove"），本服务照抄不推算。
 */
function advanceLeaves(
  storage: Storage,
  groupDid: string,
  binding: CryptoBinding,
  updatedAt: string,
): void {
  for (const leaf of storage.activeGroupLeaves(groupDid)) {
    storage.upsertGroupLeaf({ ...leaf, ...binding, updatedAt })
  }
}

/** `candidate > current`；两边解析不出十进制数时 `undefined`（判不了）。
 *
 *  用 `BigInt` 而不是 `Number`：epoch 是不设上限的计数器，而 `Number` 会在 2^53 之后
 *  悄悄地把两个不同的 epoch 判成相等——那正是"重放了旧 Commit"这一类错误要被抓的地方。 */
function epochAdvances(candidate: string, current: string): boolean | undefined {
  try {
    return BigInt(candidate) > BigInt(current)
  } catch {
    return undefined
  }
}

/** 一条 leaf 行说"这次动作建立了它"。§11.10.3 L1372 的投影要能回答"谁把它放进去的"，
 *  而本服务手里只有这次请求自己的身份，所以记的是它。 */
function actionRef(ctx: GroupControlContext, method: string): string {
  return JSON.stringify({
    method,
    operation_id: ctx.meta.operation_id,
    accepted_at: ctx.acceptedAt,
  })
}

// ---- 请求上下文 --------------------------------------------------------------

export interface GroupControlContext {
  storage: Storage
  /** 本服务的 `serviceDid`：`group.e2ee.create` 的 `meta.target.did` **MUST** 等于它
   *  （§4.4.1 L292–293 把 `create` 定成 service-scoped）。 */
  serviceDid: string
  meta: AnpMeta
  body: Record<string, unknown>
  /** RFC 3339，一次请求一个时刻。 */
  acceptedAt: string
  /** SRO 摘要，`group_receipt.payload_digest` 就是它（与幂等指纹是同一个值）。 */
  requestDigest: string
  /** 这次调用点名的设备，**顺序同 `DeviceAddressed.pairs`**，且都已判过资格。
   *
   *  四条都是 `[0]` 是调用方；`add` 多一个 `[1]`——正文里那个被加入的设备
   *  （[0] 必须是 owner 自己，`pairs[1]` 让 §6.4 的绑定检查与"这台设备合格吗"一次做完）。 */
  devices: readonly EligibleDevice[]
  /** proof 里声明的 `keyid`（A.2 L1018）。`send` 用它 §13.3 第 6 项。 */
  proofKeyId?: string
  /** 被接受的提交的 `params.auth`，**原样**。只有 `group.incoming` 那一档用它：§13.6 L1670
   *  要求重建时把原 proof 连同 `origin_context` 一起保留（[groupEnvelopes.ts] 里装配）。 */
  auth?: unknown
}

/** §4.4.2：`add` / `remove` / `send` 的 `meta.target.did` **就是** `group_did`。 */
function groupTarget(meta: AnpMeta): string {
  const did = meta.target?.did
  if (!nonEmptyString(did)) throw new Error('anp.group.e2ee.v2 requires meta.target.did')
  return did
}

/**
 * §9.2.2 / §9.3.2「owner only」，§9.4.2 的 owner 分支，§16.5 L1895。
 *
 * **非成员与"是成员但不是 owner"回同一个码。** §17 L1922 的 5003 `controller_required`
 * 逐字是"需要控制者"，§13.4/§13.5 第 2 项要求"恰好满足一条授权分支"——那条分支只看
 * owner 身份，不看成员角色高低。分成两个码在 P4 那边有意义（申请入群 vs 要权限），在
 * 密码学控制面上没有第二种动作可做。
 */
function requireOwner(storage: Storage, groupDid: string, actorDid: string): void {
  const member = storage.groupMember(groupDid, actorDid)
  if (member === undefined || member.membershipStatus !== 'active' || member.role !== 'owner') {
    throw refusal(groupE2eeError('controllerRequired', `${actorDid} is not the current owner of ${groupDid}`))
  }
}

/**
 * §13.4 L1640 第 2 项的后半：owner 分支**不只**要求"`meta.sender_did` 是当前 owner"，
 * 还要求 `meta.sender_device_id` 是一台**合格的当前 owner leaf**。
 *
 * 两半分开是因为它们的判据在两处：资格那一半要解析 DID 文档，由 `dispatch.ts` 的设备门禁
 * 在事务外判过（`deviceAddressed` 把调用方那台点名了）；投影这一半在事务里，就是这里。
 *
 * 回 **5013** 而不是 5003：调用方**确实**是 owner，授权那一半成立；错的是它这台设备在这个
 * 群里没有当前 leaf。§17 L1930 的 `leaf_not_current` 逐字说的正是"发送设备不是本群的当前
 * MLS leaf"，而 §11.9.1 L1306 把它列成**发送方侧**的终态信号——所以收到它的是那台设备
 * 自己（这里与 `remove` 的目标 leaf 缺失同码，区别只在谁收到：这里回给调用方自己）。
 *
 * 顺序上它紧跟 `requireOwner`：同属第 2 项，而且"你是谁"判完再判"你这台设备算不算数"是
 * 那条授权分支自己的读法。代价是"群还没有任何 MLS 状态"也从 5004 变成 5013——那也说得通
 * （没有 leaf 的群，owner 这台设备当然不是当前 leaf），而 §13.4 没有给这几项规定次序。
 */
function requireCurrentOwnerLeaf(storage: Storage, groupDid: string, did: string, deviceId: string): void {
  const leaf = storage.groupLeaf(groupDid, did, deviceId)
  if (leaf === undefined || leaf.state !== 'active') {
    throw refusal(
      groupE2eeError('leafNotCurrent', `${did}#${deviceId} is not a current leaf of ${groupDid}`, {
        group_did: groupDid,
        sender_device_id: deviceId,
      }),
    )
  }
}

/**
 * §10.4 L1074 与 §10.5 L1094：该不该暂停新的 `group.e2ee.send`。
 *
 * 两个证人，任一成立即暂停：
 *
 *   - **投影**。投影里有一条 active leaf，它的 `member_did` 已经不是 P4 `active` 成员了。
 *     那正是"整个 P4 成员变 `removed` / `left`，而 MLS 那边还没收尾"这句话的可观测形态——
 *     `create` / `add` / `remove` 建立 leaf 时那个 DID 是 active 的，它变成非 active 之后
 *     必须由 owner 依次 Remove。**DID 更新也走这一条**：§8.12 的改名只换成员行、不动 leaf，所以
 *     旧 DID 的 leaf 从改名那一刻起就落进这句话里，直到最后一次 Remove 把它变成 `terminal`。
 *   - **编排行**（§10.5 的 `group_did_updates`，§11.10.3 要 Host 持久化的那个"在 Add 还是
 *     Remove"）。它是投影那一条的补强而不是替代：投影是重建出来的、重启后自然还在，编排行
 *     记的是**哪一次**更新、还差哪些 leaf，`add` / `remove` 的受理要用到它。一行陈旧到没有
 *     剩余工作时不算数——那是打完收工的残留，或是崩溃留下的，投影才是权威。
 *
 * **单台设备被撤销不触发**：那台设备的 DID 仍然是 active 成员，所以投影这条判不出来，也
 * 不该判——§10.4 L1074 逐字要求此时 Host **MUST NOT** 暂停其它合法发送。编排行那时也不存在
 * （没有换 DID）。 */
function paused(storage: Storage, groupDid: string): boolean {
  const active = new Set(activeMemberDids(storage, groupDid))
  if (storage.activeGroupLeaves(groupDid).some((leaf) => !active.has(leaf.memberDid))) return true
  const pending = didUpdateOrchestration(storage, groupDid)
  return pending !== undefined && pending.remaining.length > 0
}

/** 一次进行中的 §10.5 编排，解析成受理路径要用的形状。 */
interface DidUpdateOrchestration {
  /** 被换掉的那个 DID——它的 leaf 是这次编排要退役的东西。 */
  previousDid: string
  /** 换成的那个 DID——只有它的设备能被这次编排的 Add 加进来。 */
  subjectDid: string
  /** 还没退役的 `(did, device)`。 */
  remaining: readonly (readonly [string, string])[]}

/** 编排行里那两个字段存的是 `(did, device)` 对的数组。只收正好两个字符串的行：多一个少一个
 *  的都不是一对，收进来只会让后面每一处都要再判一次。 */
function pairs(json: string): [string, string][] {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  return parsed.filter(
    (pair): pair is [string, string] =>
      Array.isArray(pair) && pair.length === 2 && typeof pair[0] === 'string' && typeof pair[1] === 'string',
  )
}

/**
 * 读一次编排行。**解析失败当成"没有"**：这一行是本服务自己写的进度记录，读不动说明它坏了，
 * 而坏掉的进度记录不该把群锁在暂停态里——投影那条判据仍然在，该暂停的时候照样暂停。
 */
function didUpdateOrchestration(storage: Storage, groupDid: string): DidUpdateOrchestration | undefined {
  const row = storage.groupDidUpdate(groupDid)
  if (row === undefined) return undefined
  let ref: Record<string, unknown>
  try {
    ref = JSON.parse(row.eventRefJson) as Record<string, unknown>
  } catch {
    return undefined
  }
  if (typeof ref.previous_subject_did !== 'string' || typeof ref.subject_did !== 'string') return undefined
  const done = new Set(pairs(row.doneJson).map((pair) => pair.join('\u0000')))
  return {
    previousDid: ref.previous_subject_did,
    subjectDid: ref.subject_did,
    remaining: pairs(row.expectedJson).filter((pair) => !done.has(pair.join('\u0000'))),
  }
}

/**
 * §10.5："the Group Host **MUST** serialize P6 member-change control actions … the Group Host
 * **MUST NOT** accept an unrelated `group.e2ee.add` or `group.e2ee.remove` until the DID update
 * completes."
 *
 * 判据用编排行里那两个 DID：这次更新的 Add 只能加**新 DID** 的设备，Remove 只能退役**旧
 * DID** 的 leaf。别的都算"无关"，回 5004——与暂停同一个码，因为对调用方而言这是同一件事：
 * 群正忙于一次 DID 更新，先把这次更新走完。
 *
 * 有一条**判不了**、规范也没打算让 Host 判：§10.5 要"全部 Add 成功之后才有第一个 Remove"，
 * 而 Host 数不出 owner 一共选了几台新设备（那是 owner 按 §11.12 第 2 步自己枚举的）。所以
 * 第一次 Remove 被接受时，Host 记的是"Add 阶段结束了"，而不是"我核对过 Add 都成功了"。
 */
function checkDidUpdateMembershipChange(
  storage: Storage,
  groupDid: string,
  method: string,
  memberDid: string,
  memberDeviceId: string,
): void {
  const pending = didUpdateOrchestration(storage, groupDid)
  if (pending === undefined || pending.remaining.length === 0) return
  const refused = (why: string): never => {
    throw refusal(
      groupE2eeError('stateNotReady', `${method} is not part of the pending DID update of ${groupDid}: ${why}`, {
        group_did: groupDid,
      }),
    )
  }
  if (method === GROUP_E2EE_ADD) {
    if (memberDid !== pending.subjectDid) {
      refused(`${memberDid} is not the update's current subject ${pending.subjectDid}`)
    }
    return
  }
  const key = `${memberDid}\u0000${memberDeviceId}`
  if (!pending.remaining.some((pair) => pair.join('\u0000') === key)) {
    refused(`${memberDid}#${memberDeviceId} is not a leaf of the superseded ${pending.previousDid}`)
  }
}

/**
 * 一次匹配的 Remove 被接受之后推进编排行：记下这一对已退役；全部退役就清掉那一行（§10.5
 * "Resume application messages only after the final Remove succeeds"——行没了、旧 leaf 也
 * 都 `terminal` 了，投影与编排行同时解除暂停）。
 */
function advanceDidUpdateOrchestration(
  storage: Storage,
  groupDid: string,
  memberDid: string,
  memberDeviceId: string,
): void {
  const row = storage.groupDidUpdate(groupDid)
  if (row === undefined) return
  const pending = didUpdateOrchestration(storage, groupDid)
  if (pending === undefined) return
  const key = `${memberDid}\u0000${memberDeviceId}`
  const done = pairs(row.doneJson)
  if (!done.some((pair) => pair.join('\u0000') === key)) done.push([memberDid, memberDeviceId])
  const remaining = pairs(row.expectedJson).filter((pair) => !done.some((d) => d.join('\u0000') === pair.join('\u0000')))
  if (remaining.length === 0) {
    storage.clearGroupDidUpdate(groupDid)
    return
  }
  storage.upsertGroupDidUpdate({ ...row, progress: 'remove-pending', doneJson: JSON.stringify(done) })
}

/** §13.5 第 5 项 / §9.3.3 / §9.4.3 共同要的那件事：这次动作的 `crypto_group_id` 与 `epoch`
 *  是不是叠在这个群**当前**的密码学绑定上。三处错用三个码，理由见各自的调用点。 */
function checkAgainstBinding(
  current: CryptoBinding | undefined,
  cryptoGroupId: string,
  epoch: string,
  method: string,
): void {
  if (current === undefined) {
    // 这个群还没有被接受的 MLS 初始状态：`add` / `remove` / `send` 都无从而来。
    throw refusal(
      groupE2eeError('stateNotReady', `${method} requires an accepted MLS initial state for this group`),
    )
  }
  // §17 L1924：`crypto_group_id` 与这个群当前的绑定不一致。**不是** 5005——那是"同一个群
  // 的同一个坐标轴上有人在往回走"，而这里是"你说的这个群不是这个群"。
  if (current.cryptoGroupId !== cryptoGroupId) {
    throw refusal(
      groupE2eeError('cryptoGroupMismatch', `body.crypto_group_id_b64u is not this group's current crypto_group_id`, {
        expected: current.cryptoGroupId,
      }),
    )
  }
  const advances = epochAdvances(epoch, current.epoch)
  if (advances !== true) {
    // §9.3.3 / §9.4.3 逐字"`epoch` MUST indicate the new epoch after this add/remove"。
    // 不大于当前值就是冲突；判不了（库里那个值不是十进制）也按冲突处理——fail closed，
    // 宁可让 owner 重试，也不接受一个说不清次序的 Commit。
    throw refusal(
      groupE2eeError('epochConflict', `body.epoch MUST be the epoch after this ${method} (current ${current.epoch})`, {
        current: current.epoch,
      }),
    )
  }
}

// ---- create ------------------------------------------------------------------

/**
 * `group.e2ee.create`（§9.2）—— 建立 MLS 群状态并把 owner 自己作为初始成员放进去。
 *
 * 判据的顺序照抄 §13.5 那五项：proof（`dispatch` 已判）→ owner 与设备 → KeyPackage 的
 * 归属与绑定 → 坐标完整 → **该群当前没有已被接受的 MLS 初始状态**。
 *
 * "已经有初始状态"有两种：`crypto_group_id` 不同（**5006**，§17 L1924 逐字"`group_did` 与
 * `crypto_group_id` 的绑定不一致"——这正是 §14.5 说的分叉）与完全相同（**5005**，同一个
 * 群在同一组坐标上被初始化了两次）。两者要调用方做的事不同：前者是"你搞错群了"，后者是
 * "这个请求重来过"。
 *
 * §9.2.4 逐字：**MUST NOT** 新建 P4 业务群（P4 的 `group.create` 早就建好了，§9.2.1），
 * 也**不再独立产生** `group_state_version` / `group_event_seq`——所以这个函数一个计数器
 * 都不碰。它写下的唯一东西是 owner 那一行 leaf。
 */
export function createE2eeGroup(ctx: GroupControlContext): Record<string, unknown> {
  requireServiceTarget(ctx)
  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = senderDeviceOf(ctx.meta)

  const groupDid = text(ctx.body, 'group_did')
  // §9.2.1 与 §13.5 的前提：业务群已经在 P4 那边建好了。没有就是"这个 group_did 不由本服务
  // 托管"，回 P4 的 3000（`loadGroup` 里写了这样处理的理由）。
  loadGroup(ctx.storage, groupDid)
  requireOwner(ctx.storage, groupDid, senderDid)

  // §9.2.3 正文的六项。`suite` 只判"在不在"：本服务不认识任何 suite 的名字，把它当白名单
  // 就是拿一个本服务不该有的判断去拒人（§11.11 L1386）。
  const creator = ctx.body.creator_key_package
  if (!isPlainObject(creator)) {
    throw refusal(shapeProblem(`${GROUP_E2EE_CREATE} requires an object body.creator_key_package`))
  }
  const shape = keyPackageShapeProblem(creator)
  if (shape !== undefined) throw refusal(shape)
  // §9.2.3 的两条归属规则。与 §8.1.2 的发布侧同形，所以同码（5002）：这份 KeyPackage 自身
  // 可以完全合规，错的是它不属于送它来的那台设备。
  if (creator.owner_did !== senderDid) {
    throw refusal(
      groupE2eeError('didBindingInvalid', `body.creator_key_package.owner_did MUST equal meta.sender_did (${senderDid})`, {
        key_package_id: creator.key_package_id,
      }),
    )
  }
  if (creator.owner_device_id !== senderDeviceId) {
    throw refusal(
      groupE2eeError(
        'didBindingInvalid',
        `body.creator_key_package.owner_device_id MUST equal meta.sender_device_id (${senderDeviceId})`,
        { key_package_id: creator.key_package_id },
      ),
    )
  }
  // §13.5 第 3 项的后半："其 binding extension 匹配当前 P2 Manifest"。清单那一半由资格门禁
  // 在事务外判过，且是对着**同一份**文档判的，所以这里直接用那次解析出来的文档验 proof。
  const owner = device(ctx, 0, 'creator')
  const binding = bindingProblem(creator, senderDid, owner)
  if (binding !== undefined) throw refusal(binding)

  const ref = groupStateRef(ctx.body.group_state_ref, groupDid, GROUP_E2EE_CREATE)
  const cryptoGroupId = base64Url(ctx.body, 'crypto_group_id_b64u', 'request')
  const epoch = decimal(ctx.body, 'epoch')
  text(ctx.body, 'suite')

  // §13.5 第 5 项。
  const current = currentBinding(ctx.storage, groupDid)
  if (current !== undefined) {
    if (current.cryptoGroupId !== cryptoGroupId) {
      throw refusal(
        groupE2eeError(
          'cryptoGroupMismatch',
          `${groupDid} already has an accepted MLS state under a different crypto_group_id`,
          { expected: current.cryptoGroupId },
        ),
      )
    }
    throw refusal(
      groupE2eeError('epochConflict', `${groupDid} already has an accepted MLS initial state at epoch ${current.epoch}`),
    )
  }

  // §9.2.1：owner 作为初始成员。§9.2.3 让 `epoch` 取 "0" 是 SHOULD，不是 MUST——照抄调用方
  // 报的那个值，不替它改。
  ctx.storage.upsertGroupLeaf({
    groupDid,
    memberDid: senderDid,
    memberDeviceId: senderDeviceId,
    cryptoGroupId,
    epoch,
    state: 'active',
    addedByRefJson: actionRef(ctx, GROUP_E2EE_CREATE),
    updatedAt: ctx.acceptedAt,
  })

  // §9.2.4 的成功响应。
  return {
    created: true,
    group_did: groupDid,
    group_state_ref: ref,
    crypto_group_id_b64u: cryptoGroupId,
    epoch,
    accepted_at: ctx.acceptedAt,
  }
}

// ---- add ---------------------------------------------------------------------

/**
 * `group.e2ee.add`（§9.3）—— 把一个 P4 `active` 成员的一台合格设备 leaf 加进密码学群。
 *
 * 同一个 DID 的第二台设备是**另一次** Add，不新建 P4 成员（§9.3.1）——所以这里改的只有
 * 投影，一个 P4 成员行都不碰（§9.3.4 逐字："`group.e2ee.add` itself MUST NOT change the
 * P4 business state"，业务状态早就由 P4 定好了）。
 *
 * 三处 `*_b64u`（`commit` / `welcome` / `ratchet_tree`）只判编码（§9.3.3）。它们的内容是
 * MLS 的事，验它的地方是被加进去的那台设备的 runtime。
 */
export function addE2eeMember(ctx: GroupControlContext): Record<string, unknown> {
  const groupDid = groupTarget(ctx.meta)
  loadGroup(ctx.storage, groupDid)
  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = senderDeviceOf(ctx.meta)
  requireOwner(ctx.storage, groupDid, senderDid)
  requireCurrentOwnerLeaf(ctx.storage, groupDid, senderDid, senderDeviceId)

  const memberDid = text(ctx.body, 'member_did')
  const memberDeviceId = text(ctx.body, 'member_device_id')
  const ref = groupStateRef(ctx.body.group_state_ref, groupDid, GROUP_E2EE_ADD)
  const cryptoGroupId = base64Url(ctx.body, 'crypto_group_id_b64u', 'request')
  const epoch = decimal(ctx.body, 'epoch')
  const commitB64u = base64Url(ctx.body, 'commit_b64u', 'request')
  const welcomeB64u = base64Url(ctx.body, 'welcome_b64u', 'request')
  const ratchetTreeB64u = base64Url(ctx.body, 'ratchet_tree_b64u', 'request')

  const keyPackage = ctx.body.group_key_package
  if (!isPlainObject(keyPackage)) {
    throw refusal(shapeProblem(`${GROUP_E2EE_ADD} requires an object body.group_key_package`))
  }
  const shape = keyPackageShapeProblem(keyPackage)
  if (shape !== undefined) throw refusal(shape)
  // §9.3.3 的两条归属规则：这份 KeyPackage 必须是**这次点名的那台设备**的。`owner_device_id`
  // 与 `did_wba_binding.device_id` 相等已经由形状检查判过（§7.3 L557）。
  if (keyPackage.owner_did !== memberDid) {
    throw refusal(
      groupE2eeError('didBindingInvalid', `body.group_key_package.owner_did MUST equal body.member_did (${memberDid})`, {
        key_package_id: keyPackage.key_package_id,
      }),
    )
  }
  if (keyPackage.owner_device_id !== memberDeviceId) {
    throw refusal(
      groupE2eeError(
        'didBindingInvalid',
        `body.group_key_package.owner_device_id MUST equal body.member_device_id (${memberDeviceId})`,
        { key_package_id: keyPackage.key_package_id },
      ),
    )
  }
  // 被加进来的那台设备当前合不合资格、它的绑定与当前清单对不对得上——一次判完。这台设备
  // 由 `deviceAddressed` 点名（`methods.ts`），所以 `devices[1]` 已经解析过了。
  const memberDevice = device(ctx, 1, 'member')
  const binding = bindingProblem(keyPackage, memberDid, memberDevice)
  if (binding !== undefined) throw refusal(binding)

  // §9.3.3 普通路："`member_did` MUST be a current P4 `active` member"。不是 → 5004
  // `state_not_ready`（§17 L1923："状态尚未就绪"）——业务层还没把这个人放进群，密码学层
  // 无从跟上。**不是** 3000：调用方（owner）是成员，缺的那一半是**目标**。
  const member = ctx.storage.groupMember(groupDid, memberDid)
  if (member === undefined || member.membershipStatus !== 'active') {
    throw refusal(groupE2eeError('stateNotReady', `${memberDid} is not an active member of ${groupDid}`))
  }
  // §10.5 的串行化。位置在"新 DID 是 active 成员吗"之后、坐标与 KeyPackage 之前：一条**属于
  // 这次更新**的 Add（加的是新 DID 的设备）从这一关走过去，其余的在动任何状态之前就被挡下。
  checkDidUpdateMembershipChange(ctx.storage, groupDid, GROUP_E2EE_ADD, memberDid, memberDeviceId)
  // §9.3.3："the exact `(member_did, member_device_id)` leaf MUST NOT already exist; another
  // leaf with the same DID is not a conflict"——所以比的是**精确二元组**，不是 DID。
  const existing = ctx.storage.groupLeaf(groupDid, memberDid, memberDeviceId)
  if (existing !== undefined && existing.state === 'active') {
    throw refusal(
      groupE2eeError('epochConflict', `${memberDid}#${memberDeviceId} is already an active leaf of ${groupDid}`),
    )
  }

  checkAgainstBinding(currentBinding(ctx.storage, groupDid), cryptoGroupId, epoch, GROUP_E2EE_ADD)

  // §8.2.4 L769：对应的 `group.e2ee.add` 被接受之后，本服务手里那一枚 KeyPackage
  // **MUST** 标记为 `consumed`。'missing' 放过——这份材料可能来自**另一台**消息服务
  // （§8.2.3 的领取本来就是跨域的，P8 §5.3.1 L261），本服务没有发过它，也就没有"消耗"
  // 可记。'already-consumed' 就是 §17 L1930 的 5012。
  const consumed = ctx.storage.markGroupKeyPackageConsumed(memberDid, memberDeviceId, String(keyPackage.key_package_id))
  if (consumed === 'already-consumed') {
    throw refusal(
      groupE2eeError('keyPackageConsumed', `key_package ${String(keyPackage.key_package_id)} was already consumed`, {
        key_package_id: keyPackage.key_package_id,
      }),
    )
  }

  // Commit 推进所有人的 epoch（§9.3.3 的 `epoch` 是 "after this add"），新 leaf 落在同一个
  // 坐标上。两条写完之后文件头那条不变量仍成立。
  advanceLeaves(ctx.storage, groupDid, { cryptoGroupId, epoch }, ctx.acceptedAt)
  ctx.storage.upsertGroupLeaf({
    groupDid,
    memberDid,
    memberDeviceId,
    cryptoGroupId,
    epoch,
    state: 'active',
    addedByRefJson: actionRef(ctx, GROUP_E2EE_ADD),
    updatedAt: ctx.acceptedAt,
  })

  // §12.3 L1447：一次 Add 投两样——Commit 给**加完之后**的每条 active leaf（含新 leaf），
  // Welcome 只给新 leaf。取投影必须在这两次写之后：`leaves` 是"这次 Add 之后"的状态。
  emitAddEnvelopes(ctx, {
    groupDid,
    leaves: ctx.storage.activeGroupLeaves(groupDid),
    groupStateRef: ref,
    cryptoGroupId,
    epoch,
    memberDid,
    memberDeviceId,
    commitB64u,
    welcomeB64u,
    ratchetTreeB64u,
  })

  // §9.3.4 的成功响应。
  return {
    accepted: true,
    group_did: groupDid,
    member_did: memberDid,
    member_device_id: memberDeviceId,
    group_state_ref: ref,
    crypto_group_id_b64u: cryptoGroupId,
    epoch,
    accepted_at: ctx.acceptedAt,
  }
}

// ---- remove ------------------------------------------------------------------

/**
 * `group.e2ee.remove`（§9.4）—— 精确移除一台设备的一个 leaf。
 *
 * v1 只实现 owner 分支（文件头写了同 DID 分支缺在哪）。owner 分支下 §9.4.3 的两条规则由
 * 本服务能观测到的东西分开：
 *
 *   - P4 把 `member_did` 标成 `removed` / `left` → 他**没有** active 状态了；
 *   - DID 仍是 `active`，移除的是失去了资格或被群策略移掉的那一台 → 他**有** active 状态。
 *
 * 两条都接受，因为**判它们不是这一层的义务**：§9.4.1 说触发可能是 P4 移除、设备失去资格、
 * 群策略、或 DID 更新编排，而 §13.4 L1649 说 Host 的检查 MUST NOT 取代成员 runtime 的
 * 最终验证。本服务判的是"这个精确 leaf 在不在、坐标对不对"——那两件事它有权威。
 *
 * **目标 leaf 不在投影里回 5004，不是 5013。** 5013 `leaf_not_current` 是 §11.9.1 L1306
 * 列的**发送方侧**终态信号（"我发的消息被拒了，说明我已经不在群里"），回给的是**那台设备
 * 自己**——在这条方法上就是调用方（`requireCurrentOwnerLeaf`，§13.4 L1640 第 2 项），不是
 * `body.member_did` 那台要被移除的设备。把目标缺失也报成 5013，等于把一条"你该收敛了"的
 * 信号发给一个正要离开的人。这条区分要保住。
 */
export function removeE2eeMember(ctx: GroupControlContext): Record<string, unknown> {
  const groupDid = groupTarget(ctx.meta)
  loadGroup(ctx.storage, groupDid)
  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = senderDeviceOf(ctx.meta)
  requireOwner(ctx.storage, groupDid, senderDid)
  requireCurrentOwnerLeaf(ctx.storage, groupDid, senderDid, senderDeviceId)

  const memberDid = text(ctx.body, 'member_did')
  const memberDeviceId = text(ctx.body, 'member_device_id')
  const ref = groupStateRef(ctx.body.group_state_ref, groupDid, GROUP_E2EE_REMOVE)
  const cryptoGroupId = base64Url(ctx.body, 'crypto_group_id_b64u', 'request')
  const epoch = decimal(ctx.body, 'epoch')
  // §9.4.3 只要求 `commit_b64u` 是编码合法的 MLSMessage。内容对不对归接收方的 runtime。
  const commitB64u = base64Url(ctx.body, 'commit_b64u', 'request')

  // §9.4.3："The exact `(member_did, member_device_id)` leaf MUST exist in the current MLS
  // state"。terminal 的行**不算**——那台设备已经被移出去了，再移一次是无标的之箭。
  const leaf = ctx.storage.groupLeaf(groupDid, memberDid, memberDeviceId)
  if (leaf === undefined || leaf.state !== 'active') {
    throw refusal(
      groupE2eeError('stateNotReady', `${memberDid}#${memberDeviceId} is not an active leaf of ${groupDid}`),
    )
  }
  // §10.5 的串行化，与 `add` 那一条对称：这次更新的 Remove 只能退役**旧 DID** 的 leaf。
  checkDidUpdateMembershipChange(ctx.storage, groupDid, GROUP_E2EE_REMOVE, memberDid, memberDeviceId)

  checkAgainstBinding(currentBinding(ctx.storage, groupDid), cryptoGroupId, epoch, GROUP_E2EE_REMOVE)

  advanceLeaves(ctx.storage, groupDid, { cryptoGroupId, epoch }, ctx.acceptedAt)
  // §11 的 DDL 注释：terminal 的行**留着**，否则同一 `(did, device)` 重新加入时 Host 分不出
  // "第一次进群"与"重新加入"（§10.3 L1066 的触发条件要用到"该精确设备当前没有 Leaf"）。
  ctx.storage.upsertGroupLeaf({
    ...leaf,
    cryptoGroupId,
    epoch,
    state: 'terminal',
    updatedAt: ctx.acceptedAt,
  })
  // 旧 DID 的 leaf 退役一格。放在写投影之后：若这是最后一次，编排行与那条 leaf 的 `terminal`
  // 必须同生同灭，否则会出现"行清了、leaf 还是 active"或反过来的一瞬——两者都是暂停判据。
  advanceDidUpdateOrchestration(ctx.storage, groupDid, memberDid, memberDeviceId)

  // §12.3 L1455：Commit 给每条**保留的** leaf，最终通知给被移除的那一条。取投影在 terminal
  // 写之后——被移除的那条已不在 `activeGroupLeaves` 里，所以它只会收到最终通知，不再收到任何
  // 新的应用信封（§12.6 L1516 那句 MUST NOT 的机械保证）。
  emitRemoveEnvelopes(ctx, {
    groupDid,
    retainedLeaves: ctx.storage.activeGroupLeaves(groupDid),
    subjectDid: memberDid,
    subjectDeviceId: memberDeviceId,
    groupStateRef: ref,
    cryptoGroupId,
    epoch,
    commitB64u,
  })

  // §9.4.4 的成功响应。
  return {
    accepted: true,
    group_did: groupDid,
    member_did: memberDid,
    member_device_id: memberDeviceId,
    group_state_ref: ref,
    crypto_group_id_b64u: cryptoGroupId,
    epoch,
    accepted_at: ctx.acceptedAt,
  }
}

// ---- send --------------------------------------------------------------------

/**
 * `group.e2ee.send`（§9.5）—— 收下一颗已经排好序的 MLS 密文对象。
 *
 * 判定次序严格照抄 §13.3 L1620–1627 八项里的 4/5/6，**以及它的次序要求**：
 *
 *   4. `sender_did` 是 P4 `active` 成员     → **3000** `group.not_member`
 *   5. `sender_device_id` 当前合格           → core 的 1015–1018（资格门禁在事务外跑过）
 *      └ 合格但这个二元组不在当前投影里      → **5013** `leaf_not_current`
 *   6. proof 由那台设备的当前签名钥做出      → **1005** `anp.unauthorized`
 *
 * §13.3 L1625 明说这三条 MUST 映射到**互不相同**的稳定错误、且按此次序判。第 5 项的分岔是
 * 本服务加的一层：资格门禁只管"这台设备在不在当前清单里、宣告全不全"，管不到"它是不是
 * 这个群的 leaf"。**5013 绝不折叠进前两个**（§11.9.1 L1306 的第五个权威信号），否则一台
 * 只被移除了 leaf 的设备永远收敛不了——它的 DID 还是 active、设备还是合格的，前两个信号
 * 永远不会为它触发。
 *
 * 一处已知偏离：`dispatch.ts` 的资格门禁在事务外、处理器之前跑（资格要解析 DID 文档，事务
 * 里不能有网络往返），所以"**既**不是成员**又**设备不合格"的请求拿到的是设备码而不是
 * 3000。可达的三种状态里，第三种（DID active、设备合格、没有 leaf）判得分毫不差。
 * [e2ee-group.md] §7 记了这条。
 *
 * 成功只意味着**本服务接受并排序**了这一颗密文对象，不意味着所有成员都解得开（§9.5 的成功
 * 语义）。本服务没有解密能力，也就没有立场说更多。
 */
export function sendE2eeMessage(ctx: GroupControlContext): Record<string, unknown> {
  const groupDid = groupTarget(ctx.meta)
  const view = loadGroup(ctx.storage, groupDid)
  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = senderDeviceOf(ctx.meta)

  const messageId = ctx.meta.message_id
  const operationId = ctx.meta.operation_id
  if (!nonEmptyString(messageId) || !nonEmptyString(operationId)) {
    throw new Error(`${GROUP_E2EE_SEND} requires meta.message_id and meta.operation_id`)
  }

  // §9.5.3：`content_type` **MUST** 固定为这一个。判它在成员判定之前——这是**请求**自己的
  // 形状（1003），而 §13.3 那八项是"这个人有没有资格发"；形状先于身份，与 `checkMethod`
  // 里"Profile 规则先于 target 建模"是同一条次序。
  if (ctx.meta.content_type !== GROUP_CIPHER_CONTENT_TYPE) {
    throw refusal(
      shapeProblem(`${GROUP_E2EE_SEND} requires meta.content_type ${GROUP_CIPHER_CONTENT_TYPE}`),
    )
  }

  // §13.3 第 4 项。
  const sender = requireActiveMember(ctx.storage, groupDid, senderDid)

  // §13.3 第 5 项的后半：这个合格二元组映射到**当前投影里的那个 leaf**。§13.3 L1626 逐字
  // "maps to the current leaf in the projection"。
  const leaf = ctx.storage.groupLeaf(groupDid, senderDid, senderDeviceId)
  if (leaf === undefined || leaf.state !== 'active') {
    throw refusal(
      groupE2eeError(
        'leafNotCurrent',
        `${senderDid}#${senderDeviceId} is not a current leaf of ${groupDid}`,
        { group_did: groupDid, sender_device_id: senderDeviceId },
      ),
    )
  }

  // §13.3 第 6 项：证明由**那台设备的当前签名钥**做出。core 把签名底里的 keyid 交回
  // （`OriginProofOutcome.keyid`），于是这一条是字符串比较。锚点那一半（keyid 属于
  // `meta.sender_did`）已经由 `authenticate()` 判过。
  //
  // 码取 1005：§17 这一段（5000–5013）没有一条说"你没通过认证"，而 §9.5.3 这一句正是在
  // 说"这个证明不是那台设备做出的"——与 `authenticate()` 里那两类失败同一件事，所以复用
  // 方法表给这一族的那对码，不发明一个。
  const expectedKeyId = device(ctx, 0, 'sender').entry.signingKeyId
  if (ctx.proofKeyId !== expectedKeyId) {
    throw refusal(
      profileRejection(
        P1_AUTH_CODES.invalidProof.code,
        P1_AUTH_CODES.invalidProof.anpCode,
        `the origin proof MUST be made with ${senderDid}#${senderDeviceId}'s current signing_key_id (${expectedKeyId})`,
      ),
    )
  }

  // §10.4 L1074 / §10.5 L1094 的暂停。位置在成员与 leaf 之后、策略之前：这是一个**群级**
  // 的临时状态，不是这个人的问题——先让"你不是成员/你的 leaf 不在"这两条具体信号出去
  // （它们对那台设备是终态信号，不能被一个临时状态盖掉），再谈群现在能不能收消息。
  if (paused(ctx.storage, groupDid)) {
    throw refusal(
      groupE2eeError(
        'stateNotReady',
        `${groupDid} is paused until the pending MLS membership changes complete`,
        { group_did: groupDid },
      ),
    )
  }

  // §13.3 第 7 项。码是 P4 的 3003（§11.3 L1074–1085 把"是成员但不够格"定在权限表里）。
  requirePermission(view.policy, sender.role, 'send')

  // §13.3 第 8 项：`group_cipher_object` 完整且格式正确（§7.4 L570–590）。
  const cipher = ctx.body.group_cipher_object
  if (!isPlainObject(cipher)) {
    throw refusal(
      groupE2eeError('privateMessageInvalid', `${GROUP_E2EE_SEND} requires an object body.group_cipher_object`),
    )
  }
  const cipherGroupId = base64Url(cipher, 'crypto_group_id_b64u', 'material')
  base64Url(cipher, 'private_message_b64u', 'material')
  const cipherEpoch = cipher.epoch
  if (!isDecimal(cipherEpoch)) {
    throw refusal(
      groupE2eeError('privateMessageInvalid', 'body.group_cipher_object.epoch MUST be a decimal string'),
    )
  }
  // §7.4 L590：`group_state_ref.group_did` **MUST** 等于外层 target 的 `group_did`。与外层
  // 对不上是两种说法打架，是 1003（与 `add`/`remove` 那两处同一条分界）。
  const cipherRef = cipher.group_state_ref
  if (!isPlainObject(cipherRef) || !nonEmptyString(cipherRef.group_did)) {
    throw refusal(
      groupE2eeError(
        'privateMessageInvalid',
        'body.group_cipher_object.group_state_ref MUST be an object with a non-empty group_did',
      ),
    )
  }
  if (cipherRef.group_did !== groupDid) {
    throw refusal(
      shapeProblem(`body.group_cipher_object.group_state_ref.group_did MUST equal the outer target group_did (${groupDid})`),
    )
  }

  // §14.5 L1739 说的"多个不可调和的 `crypto_group_id`"在 Host 这一侧的可观测形态：这颗密文
  // 说自己属于另一个密码学群。`crypto_group_id` 是 MLS 的 group_id，**不随 epoch 变**——所以
  // 这里对不上就是"你和我说的不是同一个群"，回 5006。
  //
  // **反过来，`epoch` 不判。** §13.3 那八项里没有它，而一个较早的 epoch 是**合法**的：一颗
  // 在 Commit 之前产生、之后才送达的消息仍然必须被收下（§12.6 的队列本来就按 epoch 排队）。
  // 拿当前 epoch 卡它，等于把正常乱序判成分叉。
  const current = currentBinding(ctx.storage, groupDid)
  if (current === undefined) {
    throw refusal(groupE2eeError('stateNotReady', `${groupDid} has no accepted MLS state`))
  }
  if (current.cryptoGroupId !== cipherGroupId) {
    throw refusal(
      groupE2eeError('cryptoGroupMismatch', 'body.group_cipher_object names a different crypto_group_id', {
        expected: current.cryptoGroupId,
      }),
    )
  }

  // §14.1 L1705：`group.e2ee.send` 进群事件排序链——**只**推 `group_event_seq`，`epoch` 的
  // 推进是密码学层的另一回事。§10.6 与 P4 的 `group.send` 同级，所以 `group_state_version`
  // 不动，响应里回的是受理时的快照。
  const counters = ctx.storage.advanceGroupCounters(groupDid, false)
  const receipt = groupReceipt({
    receiptType: RECEIPT_MESSAGE,
    groupDid,
    stateVersion: counters.groupStateVersion,
    eventSeq: counters.groupEventSeq,
    subjectMethod: GROUP_E2EE_SEND,
    operationId,
    actorDid: senderDid,
    acceptedAt: ctx.acceptedAt,
    payloadDigest: ctx.requestDigest,
    messageId,
  })

  // §12.5 L1491：每条 active leaf 一封 `group.incoming`，逐叶只变 target 与设备。取投影在这里
  // （受理之后、`advanceGroupCounters` 之后）——`body` 里那两个序号就是这次受理推出来的值，
  // 正是接收方要用来排队的坐标。
  emitIncomingEnvelopes(ctx, {
    groupDid,
    leaves: ctx.storage.activeGroupLeaves(groupDid),
    cipher,
    receipt,
    groupStateVersion: String(counters.groupStateVersion),
    groupEventSeq: String(counters.groupEventSeq),
  })

  // §9.5.4 的成功响应。
  return {
    accepted: true,
    group_did: groupDid,
    message_id: messageId,
    operation_id: operationId,
    // §7.9 L506–507 与 §6.3 L249：两个计数器一律**字符串**。
    group_event_seq: String(counters.groupEventSeq),
    group_state_version: String(counters.groupStateVersion),
    accepted_at: ctx.acceptedAt,
    // §9.5.3：响应里的 `epoch` 是**被接受的那一份**的 epoch（那颗密文自己报的），不是群当前
    // 的 epoch——两者在乱序投递时本来就可能不同。
    epoch: cipherEpoch,
    group_receipt: receipt,
  }
}
