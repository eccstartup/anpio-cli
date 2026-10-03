// 方法表 —— 每个方法自己声明的东西。
//
// 信封层面能查的（jsonrpc / id / method / params 形状）在 core 的 `parseEnvelope` 里，
// §3 那张表里剩下的两行要的正是这个文件：目标建模模式（P1 §6.2.5.1 L361–378）与
// "还有哪些 `meta` 字段是这个方法必须带的"。
//
// 表放在一起而不是散在 handler 里，是因为这几件事**必须一起看**才对得上：目标模式错了
// 回哪个码、这个方法的 proof 缺失算 1005 还是 2005、幂等键的 `target_scope` 取哪个字段。
// 分开写就会有一处不一致，而那种不一致运行起来只表现为"某个码回得不对"，很难察觉。

import {
  anpRejection,
  ConnectxError,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
  type AnpTarget,
  type AnpTargetKind,
} from '@agentx/core'
import { DIRECT_AUTH_CODES, GROUP_AUTH_CODES, P1_AUTH_CODES, type AuthErrorCodes } from './auth'
import {
  DIRECT_E2EE_PROFILE,
  DIRECT_E2EE_SECURITY_PROFILE,
  DIRECT_E2EE_DEVICE,
  directSendDeviceAddressed,
  directSendParams,
} from './e2ee'
import {
  GET_PREKEY_BUNDLE,
  PUBLISH_PREKEY_BUNDLE,
  keyMethodParams,
  validateGetBundleBody,
  validatePublishBody,
} from './keys'
import {
  GET_KEY_PACKAGE,
  GROUP_E2EE_DEVICE,
  GROUP_E2EE_KEY_SECURITY_PROFILE,
  GROUP_E2EE_PROFILE,
  PUBLISH_KEY_PACKAGE,
  validateGetKeyPackageBody,
  validatePublishKeyPackageBody,
} from './groupE2ee'
import {
  GROUP_E2EE_ADD,
  GROUP_E2EE_CREATE,
  GROUP_E2EE_REMOVE,
  GROUP_E2EE_SECURITY_PROFILE,
  GROUP_E2EE_SEND,
  validateAddE2eeBody,
  validateCreateE2eeBody,
  validateRemoveE2eeBody,
} from './groupControl'
import type { DeviceAddressed, DevicePair } from './eligibility'
import {
  ATTACHMENT_ABORT_OBJECT,
  ATTACHMENT_COMMIT_OBJECT,
  ATTACHMENT_CREATE_SLOT,
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  ATTACHMENT_PROFILE,
  ATTACHMENT_SECURITY_PROFILE,
  attachmentScope,
  ticketScope,
  validateAbortBody,
  validateCommitBody,
  validateCreateSlotBody,
  validateTicketBody,
} from './attachments'
import {
  GROUP_ADD,
  GROUP_CREATE,
  GROUP_GET_INFO,
  GROUP_JOIN,
  GROUP_LEAVE,
  GROUP_PROFILE,
  GROUP_REMOVE,
  GROUP_SECURITY_PROFILE,
  GROUP_SEND,
  GROUP_UPDATE_POLICY,
  GROUP_UPDATE_PROFILE,
  validateAddBody,
  validateCreateBody,
  validateGetInfoBody,
  validateJoinBody,
  validateLeaveBody,
  validateRemoveBody,
  validateSendBody,
  validateUpdatePolicyBody,
  validateUpdateProfileBody,
} from './groups'
import { EXTENSION_PROFILE, SYNC_DELTA, validateDeltaBody } from './inbox'
import {
  CONTACTS_LIST,
  CONTACTS_PROFILE,
  CONTACTS_PUT,
  CONTACTS_REMOVE,
  validateContactPutBody,
  validateContactRemoveBody,
  validateContactsListBody,
} from './contacts'
import {
  GROUP_REMARKS_LIST,
  GROUP_REMARKS_PROFILE,
  GROUP_REMARKS_PUT,
  GROUP_REMARKS_REMOVE,
  validateGroupRemarkPutBody,
  validateGroupRemarkRemoveBody,
  validateGroupRemarksListBody,
} from './groupRemarks'
import { STREAM_ACK, STREAM_AUTH, STREAM_PROFILE, validateStreamAckBody, validateStreamAuthBody } from './stream'
import { validatePayloadBody } from './payload'

/**
 * P1 §6.2.5.1 L361–378 的四种模式，加上本服务给取件面自定的第五种。
 *
 * `endpoint-local` 是"允许省略 target"，不是"target 随便写"——它同样没有一个 `kind`
 * 要对上，所以下面那张表里它是 `undefined`。
 *
 * `self-addressed` 是取件面的建模（[message-service.md](../..) §9.1.1）：P1 A.4 L1070
 * 把 endpoint-local 方法引入 `origin_proof` 时的目标建模**指名交给 Profile 定义**，
 * 而取件面正是一组这样的方法。它的语义是"target 必须在，`kind` 是 `agent`，且 `did`
 * 就是签名者本人"——三项一起才是"读自己的信箱"，少最后一项就是"代别人读"。
 */
export type TargetMode = 'agent-addressed' | 'group-addressed' | 'service-scoped' | 'endpoint-local' | 'self-addressed'

const TARGET_KIND: Record<TargetMode, AnpTargetKind | undefined> = {
  'agent-addressed': 'agent',
  'group-addressed': 'group',
  'service-scoped': 'service',
  'endpoint-local': undefined,
  'self-addressed': 'agent',
}

/** `meta` 里可以被方法声明点名的那几个字段。
 *
 *  用 `keyof AnpMeta` 而不是 `string` 是有意的：这个类型让表里写错字段名成为**编译错误**。
 *  写成 `string` 的话 `requiredMeta: ['messageId']` 编译得过，运行时又永远查不出缺失
 *  ——一条静默失效的 MUST。 */
export type MetaField = keyof AnpMeta

export interface MethodSpec {
  name: string
  /** P1 §6.2.5.1 L361–378：`meta.target.kind` 必须对上这个模式，否则 1014（L382）。 */
  targetMode: TargetMode
  /** 本服务为这个方法实现了哪些 `meta.profile`（P1 §6.2.2 L277）。不在表里 → 1001。 */
  profiles: readonly string[]
  /** 同上，`meta.security_profile`（P1 §6.2.3）→ 1002。 */
  securityProfiles: readonly string[]
  /** 这个方法**必须**带的 `meta` 字段，缺一个 → 1003。
   *  `target` 不在这里：它由 `targetMode` 管，报的码不同（1014 而不是 1003）。 */
  requiredMeta: readonly MetaField[]
  /** **不得**出现的 `meta` 字段，出现即 1003。 */
  forbiddenMeta: readonly MetaField[]
  /** 这次调用是否必须带 `auth.origin_proof`。 */
  requiresOriginProof(meta: AnpMeta): boolean
  /** 证明不通过时用哪一对码（P1 §10.3 L706 vs P3 §11 L599–600）。 */
  authCodes: AuthErrorCodes
  /** Profile 层对 `params` 的校验——**整个** `params`，因为有些规则同时要看 `meta` 与
   *  `auth`。缺省表示这个方法没有这一类规则。
   *
   *  两个静态数组（`requiredMeta` / `forbiddenMeta`）表达不了的东西都在这里：`direct.send`
   *  在 Base 下禁设备 selector、在 v2 下要求它，同一个字段两套相反的要求，只有在知道
   *  `meta.profile` 之后才判得了。
   *
   *  它在 `checkMethod` 的最后一步跑，不是单独一次调用——**这是有意的**。"这个方法还有
   *  哪些 MUST 没查"必须只有一个答案，而它一旦分开，流上那条路径（`stream/session.ts`）
   *  就会漏掉它，且不会有任何东西红。 */
  validateParams?(params: AnpParams): AnpRejection | undefined
  /** Profile 层对 `body` 的校验。缺省表示这个方法没有正文规则。
   *
   *  签名收 `meta` 而不只是 `body`：`direct.send` 的正文规则要用 `content_type` 判
   *  负载字段对不对得上，而那是 `meta` 里的。 */
  validateBody?(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined
  /** 这次调用是不是**设备定址**的（P5 §9.3 L823–824）。`undefined` = 不是。
   *
   *  只有设备定址的调用才把设备 selector 放进幂等键（§9.1 L639），也只有它才要验那两台
   *  设备的资格（§10.7 L1388）。两件后果都从这里出，见 {@link DeviceAddressed}。
   *
   *  收 `body` 是因为 **P5 §7.2 的目标设备写在正文里**：`direct.e2ee.get_prekey_bundle` 的
   *  `meta.target.did` 是**服务**的 DID（§7.2 L543），要点名的那台设备在
   *  `body.target_device_id`。固定签名收不到它，而"哪台设备"正是这个方法要判的那一件事。 */
  deviceAddressed?(meta: AnpMeta, body: Record<string, unknown>): DeviceAddressed | undefined
  /** Profile 定义的幂等 `target_scope`（P1 §9.1 L635 + P3 §8.2 L437–442）。
   *  `undefined` 表示这个方法不改状态，也就不进幂等台账。 */
  targetScope?: (meta: AnpMeta, body: Record<string, unknown>) => string
}

export const DIRECT_SEND = 'direct.send'

export const GET_CAPABILITIES = 'anp.get_capabilities'

/**
 * P1 §8.2：**发现的最后一环**，也是唯一可以不认证调用的方法。
 *
 * 匿名是这一条的核心：§8.2.1 L543–544 允许省略 `meta.sender_did`，所以这里**不**要
 * `origin_proof`——一个还没有任何信任关系的调用方至少要能问出"你会什么"。没有 proof 就
 * 没有锚点，`callerAnchor()` 也就不给这个方法算。
 *
 * `endpoint-local`（可以省略 target）照 §8.2.1 L524–538 那个请求例子：它没有 target。
 * 正文同样没有规则：§8.2.1 没给这个请求定义任何 body 字段，为规范没定义的东西发明一个
 * 1003，拒掉的会是规范允许的请求。**不要 `operation_id`**——§6.2.6 L388 只对"会改变状态
 * 的操作"要求它，而这里什么都不改（例子里有它，例子不是规范）。
 */
const GET_CAPABILITIES_SPEC: MethodSpec = {
  name: GET_CAPABILITIES,
  targetMode: 'endpoint-local',
  profiles: ['anp.core.binding.v1'],
  securityProfiles: ['transport-protected'],
  requiredMeta: [],
  forbiddenMeta: [],
  requiresOriginProof: () => false,
  authCodes: P1_AUTH_CODES,
}

/**
 * 直连私聊。`meta.target.kind` 必须是 `agent`（P3 §5.1 L172）。
 *
 * **两个 Profile 走同一个方法名**（P3 §4.3 L161 的 Overlay 规矩）：P5 的
 * `anp.direct.e2ee.v2` 不新开一个方法，它把 `direct.send` 最外层那套 wire 契约换掉。所以
 * 下面每一处要看 `profile` 说话的地方都是**同一件事的两面**，而不是两个方法的差异。
 *
 * v2 那条路上本服务做的事只有一件：把这颗不透明密文放进收件设备的邮箱（§10.7 L1391）。
 * 它不解密、不重加密、不 fan-out（§10.7 L1392），也不解析正文——包括不去查 §3.7 那两个
 * id 与正文里的字段对不对得上，那是收件设备的事。
 */
const DIRECT_SEND_SPEC: MethodSpec = {
  name: DIRECT_SEND,
  targetMode: 'agent-addressed',
  profiles: ['anp.direct.base.v1', DIRECT_E2EE_PROFILE],
  securityProfiles: ['transport-protected', DIRECT_E2EE_SECURITY_PROFILE],
  requiredMeta: ['sender_did', 'operation_id', 'message_id', 'content_type'],
  // 两个 selector 在 Base 下禁、在 v2 下必带，静态数组表达不了，所以在 `validateParams`
  // 里（`e2ee.ts`）。这里留空不是"没有规则"，规则连同 v2 那份一起写在那一处。
  forbiddenMeta: [],
  // P3 §6.4 L290 要求 base + transport-protected 必须带 `auth`。P3 §4.3 L161 让
  // `anp.direct.e2ee.v2` 整个覆盖掉这条强制要求（该 Overlay 用建链材料与 AAD 认证发送方，
  // 为的是保住更强的可否认性），§3.8 L140 进一步禁止 v2 出现 `auth`。
  requiresOriginProof: (meta) => meta.profile !== DIRECT_E2EE_PROFILE,
  authCodes: DIRECT_AUTH_CODES,
  validateParams: directSendParams,
  // P3 §6 的负载互斥规则与 P4 §7.6 逐字相同，所以两个 Profile 共用一份（`payload.ts`）。
  //
  // **v2 不走它**，而且不是因为"以后再说"：`payloadFieldRequiredBy` 对任何 `+json` 都要
  // `body.payload`，而 v2 的正文是 E2EE 承载对象**放在顶层**（§16.1–16.4：`session_id`
  // / `suite` / `recipient_bundle_id` / `ciphertext_b64u` …），没有 `payload` 这个键。
  // 让它在这里跑，等于每一条合法的 v2 请求都被自己的正文校验拒掉。
  validateBody: (body, meta) =>
    meta.profile === DIRECT_E2EE_PROFILE ? undefined : validatePayloadBody(body, meta.content_type ?? ''),
  deviceAddressed: directSendDeviceAddressed,
  // P3 §8.2 L437–442：`(sender_did, target.did, method, operation_id)`。P5 §10.7 L1391 在
  // 这四段之后加上两台设备，那一段由 `deviceAddressed` 交出去，这里照旧。
  targetScope: (meta) => {
    const target = meta.target
    // dispatch 已经查过目标绑定（1014），所以这里必定存在。抛而不是兜一个空串：
    // 空串会算出一个谁也不会再命中的键，那比当场炸掉更坏。
    if (target === undefined) throw new ConnectxError('message_invalid', 'direct.send requires meta.target')
    return target.did
  },
}

/**
 * 本服务自定的扩展面（取件面 §9、通讯录 TODO6 §3）共有的那几项。
 *
 * 两个扩展族在这一层完全同形：自己那个 `x_` Profile、只认 `transport-protected`、要
 * proof、认证失败回 P1 §10.3 L706 的公共码（**这两族都没有规范给的私有码**，`1005` 是
 * 公共段里唯一说"没通过认证"的那个）、目标必须是自己（§9.1.1）。差异只有正文校验与是否
 * 改状态，所以下面每个方法只写这两件，其余从这来。
 *
 * `profile` 是参数而不是常量：`x_agentx.inbox.v1` 与 `x_agentx.contacts.v1` 服务的是
 * 两件不同的事，而 P1 §6.2.2 L277 说 `meta.profile` 是"本次请求的唯一解释"——把"读我的
 * 信箱"与"改我的通讯录"写成同一个解释，等于让一个只实现了前者的服务看起来实现了后者。
 */
function extensionSpec(
  name: string,
  profile: string,
  validateBody: (body: Record<string, unknown>) => AnpRejection | undefined,
  targetScope?: (meta: AnpMeta) => string,
): MethodSpec {
  return {
    name,
    targetMode: 'self-addressed',
    profiles: [profile],
    securityProfiles: ['transport-protected'],
    // §9.1 那一段线上形状里，每个方法都带 `operation_id`（P1 §6.2.6）与 `sender_did`
    // （要 proof 就必须有锚点）。`message_id` / `content_type` 是消息自己的字段，
    // 取件面读的是"消息们"，不是"一条消息"，所以不在这里。
    requiredMeta: ['sender_did', 'operation_id'],
    forbiddenMeta: [],
    requiresOriginProof: () => true,
    authCodes: P1_AUTH_CODES,
    validateBody: (body) => validateBody(body),
    ...(targetScope !== undefined ? { targetScope: (meta) => targetScope(meta) } : {}),
  }
}

/** 扩展面里改状态的那几条共用的幂等作用域：就是这本子自己的主人，与 `direct.send` 取
 *  `target.did` 同理。收 `method` 只为把"哪一条方法要求 target"写进那句不该发生的错误里。 */
function selfScope(method: string): (meta: AnpMeta) => string {
  return (meta) => {
    const target = meta.target
    if (target === undefined) throw new ConnectxError('message_invalid', `${method} requires meta.target`)
    return target.did
  }
}

/** §9.3 那张表里**还在**的那一条。另外三条（`inbox.get` / `inbox.mark_read` /
 *  `message.get_batch`）2026-10-03 随读侧搬回本地一起退场了，理由见 `inbox.ts` 抬头：
 *  它们没有调用者了，而 `sync.delta` 是这一族里唯一一件服务端做得了的事（补齐）。 */
const SYNC_DELTA_SPEC = extensionSpec(SYNC_DELTA, EXTENSION_PROFILE, validateDeltaBody)

/**
 * 通讯录（TODO6 §3，C14）。
 *
 * `list` 不改状态，所以没有 `targetScope`；`put` / `remove` 改，两条各自进幂等台账
 * （`operation_id` 因此有意义：同一个 `operation_id` 重试拿到同一份答复）。
 *
 * 目标是**自己**（`self-addressed`）——一本通讯录是"我"的记忆，主人就是签名者。这条绑定
 * 是这一族唯一的授权：它保证 `owner_did` 永远是验过签的那一个，而不是请求方自己写的话，
 * 所以 A 的备注 C 看不见。
 */
const CONTACTS_LIST_SPEC = extensionSpec(CONTACTS_LIST, CONTACTS_PROFILE, validateContactsListBody)
const CONTACTS_PUT_SPEC = extensionSpec(
  CONTACTS_PUT,
  CONTACTS_PROFILE,
  validateContactPutBody,
  selfScope(CONTACTS_PUT),
)
const CONTACTS_REMOVE_SPEC = extensionSpec(
  CONTACTS_REMOVE,
  CONTACTS_PROFILE,
  validateContactRemoveBody,
  selfScope(CONTACTS_REMOVE),
)

/**
 * 群备注（TODO6 §4.2，C14 的另一半）。
 *
 * 与通讯录同形，理由也同形：目标是**自己**（`self-addressed`），所以 `owner_did` 永远是
 * 验过签的签名者，A 给群起的名字 C 看不见；`list` 不改状态所以没有 `targetScope`，
 * `put` / `remove` 各自进幂等台账。
 *
 * 与通讯录**不同**的是 Profile（`x_agentx.group_remarks.v1`）——一本是"我给这些人起的
 * 名字"，一本是"我给这些群起的名字"，P1 §6.2.2 L277 说 Profile 是本次请求的唯一解释，
 * 两件事不能共用一个解释。
 */
const GROUP_REMARKS_LIST_SPEC = extensionSpec(
  GROUP_REMARKS_LIST,
  GROUP_REMARKS_PROFILE,
  validateGroupRemarksListBody,
)
const GROUP_REMARKS_PUT_SPEC = extensionSpec(
  GROUP_REMARKS_PUT,
  GROUP_REMARKS_PROFILE,
  validateGroupRemarkPutBody,
  selfScope(GROUP_REMARKS_PUT),
)
const GROUP_REMARKS_REMOVE_SPEC = extensionSpec(
  GROUP_REMARKS_REMOVE,
  GROUP_REMARKS_PROFILE,
  validateGroupRemarkRemoveBody,
  selfScope(GROUP_REMARKS_REMOVE),
)

/**
 * 流上的两个传输方法（realtime.md §4、§6）。
 *
 * 形状与取件面完全同构——自己那个 Profile、只认 `transport-protected`、要 proof、目标必须是
 * 自己——因为它们服务的是**同一个**信箱，只是换了一条传输。`x_agentx.stream.v1` 而不复用
 * `x_agentx.inbox.v1`，是 §9 定的：`meta.profile` 是"本次请求的唯一解释"（P1 §6.2.2 L277），
 * 而"我要订阅"与"我要读一页"不是同一种解释。
 *
 * 都没有 `targetScope`：两者都不进幂等台账。`stream.auth` 的重放只是又注册一次订阅（连接
 * 本来就是一次性的），`stream.ack` 的重放是 `advanceCursor` 的原地不动——那个访问器按
 * **取大值**推进，重复投递同一个 `seq` 不改任何东西。
 */
const STREAM_AUTH_SPEC: MethodSpec = {
  name: STREAM_AUTH,
  targetMode: 'self-addressed',
  profiles: [STREAM_PROFILE],
  securityProfiles: ['transport-protected'],
  requiredMeta: ['sender_did', 'operation_id'],
  forbiddenMeta: [],
  requiresOriginProof: () => true,
  authCodes: P1_AUTH_CODES,
  validateBody: (body) => validateStreamAuthBody(body),
}

const STREAM_ACK_SPEC: MethodSpec = {
  name: STREAM_ACK,
  targetMode: 'self-addressed',
  profiles: [STREAM_PROFILE],
  securityProfiles: ['transport-protected'],
  requiredMeta: ['sender_did', 'operation_id'],
  forbiddenMeta: [],
  requiresOriginProof: () => true,
  authCodes: P1_AUTH_CODES,
  validateBody: (body) => validateStreamAckBody(body),
}

/**
 * 群组（P4 `anp.group.base.v2`，C9）。
 *
 * 九个方法在这一层几乎同形：同一个 Profile、只认 `transport-protected`、要 proof、认证
 * 失败回 P4 §12 L1162–1163 那一对码、目标建模是群。差异只有三处，正是下面每个条目写的
 * 那三处：目标建模、必带的 `meta`、正文规则，以及是否进幂等台账。
 *
 * `group_did` **就是**幂等键的第二段（§9.1 L635 的 `target_scope` + §10.4）：同一次
 * `operation_id` 只有落在同一个群下才算重放。`group.create` 取 `meta.target.did` 而不是
 * 去要一个 `serviceDid`——那条路要求方法表在构造时就知道配置，而 `group.create` 的处理器
 * 已经强制 `meta.target.did` 等于本服务的 `serviceDid`，凡是被受理的创建，两者就是同一个
 * 值；被拒绝的创建不落幂等行（`acceptOperation` 里 `perform` 抛出即回滚）。
 */
function groupScope(meta: AnpMeta): string {
  const target = meta.target
  if (target === undefined) throw new ConnectxError('message_invalid', 'group methods require meta.target')
  return target.did
}

interface GroupSpecInput {
  name: string
  targetMode: TargetMode
  requiredMeta: readonly MetaField[]
  validateBody: (body: Record<string, unknown>, meta: AnpMeta) => AnpRejection | undefined
  /** 缺省要 proof。`group.get_info` 是唯一一个匿名可达的，所以它自己给一个。 */
  requiresOriginProof?: (meta: AnpMeta) => boolean
  /** 不给就不进幂等台账——只有 `group.get_info` 是这样（它不改任何状态）。 */
  targetScope?: (meta: AnpMeta) => string
}

function groupSpec(input: GroupSpecInput): MethodSpec {
  return {
    name: input.name,
    targetMode: input.targetMode,
    profiles: [GROUP_PROFILE],
    securityProfiles: [GROUP_SECURITY_PROFILE],
    requiredMeta: input.requiredMeta,
    // 没有一条规范 MUST 禁止群方法带设备 selector：P4 §7.5 给 `group.send` 留了 P5 的
    // Overlay 路，而 §10.4 的幂等作用域里也含设备维度。P3 那条 `forbiddenMeta` 是私聊
    // Base 自己的事（P1 §10.3 L724），照搬过来会拒掉规范允许的请求。
    forbiddenMeta: [],
    requiresOriginProof: input.requiresOriginProof ?? (() => true),
    authCodes: GROUP_AUTH_CODES,
    validateBody: input.validateBody,
    ...(input.targetScope !== undefined ? { targetScope: input.targetScope } : {}),
  }
}

/** §8.1.2 L626：目标是**服务**（`meta.target` 必须指向本服务），不是群——群还没有。 */
const GROUP_CREATE_SPEC = groupSpec({
  name: GROUP_CREATE,
  targetMode: 'service-scoped',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateCreateBody(body),
  targetScope: groupScope,
})

/**
 * §8.2：**匿名可读**（`public` / `listed`），所以这里没有一条必带的 `meta`。
 *
 * 而 `requiresOriginProof` 取值不该是 `false`：匿名省掉的是 `sender_did`，不是"带上
 * `sender_did` 时就可以不验签"。取 `false` 会留下一条缝——一个没有 proof 的请求声称
 * `meta.sender_did` 是某个成员，方法表照样放行，`group.get_info` 随后用那个**未被验证**
 * 的 DID 去查成员关系，把 `private` 群的资料与成员列表发出去。规范在这里只有一句
 * "`private` 的群 MUST 要求身份"（L658–659），怎么执行是这一层的事：有 `sender_did`
 * 就必须有 proof，没有 `sender_did` 就是匿名，由处理器按 `discoverability` 决定给多少。
 *
 * 没有 `targetScope`：它一个字节都不写。
 */
const GROUP_GET_INFO_SPEC = groupSpec({
  name: GROUP_GET_INFO,
  targetMode: 'group-addressed',
  requiredMeta: [],
  validateBody: (body) => validateGetInfoBody(body),
  requiresOriginProof: (meta) => meta.sender_did !== undefined,
})

const GROUP_JOIN_SPEC = groupSpec({
  name: GROUP_JOIN,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateJoinBody(body),
  targetScope: groupScope,
})

const GROUP_ADD_SPEC = groupSpec({
  name: GROUP_ADD,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateAddBody(body),
  targetScope: groupScope,
})

const GROUP_REMOVE_SPEC = groupSpec({
  name: GROUP_REMOVE,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateRemoveBody(body),
  targetScope: groupScope,
})

const GROUP_LEAVE_SPEC = groupSpec({
  name: GROUP_LEAVE,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateLeaveBody(body),
  targetScope: groupScope,
})

const GROUP_UPDATE_PROFILE_SPEC = groupSpec({
  name: GROUP_UPDATE_PROFILE,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateUpdateProfileBody(body),
  targetScope: groupScope,
})

const GROUP_UPDATE_POLICY_SPEC = groupSpec({
  name: GROUP_UPDATE_POLICY,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id'],
  validateBody: (body) => validateUpdatePolicyBody(body),
  targetScope: groupScope,
})

/** §8.9.3 L856–862：`content_type` 与 `message_id` 与私聊同样必带——前者决定负载字段，
 *  后者是 §10.3 L1046–1052 消息级重复识别三元组里的那一段。 */
const GROUP_SEND_SPEC = groupSpec({
  name: GROUP_SEND,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'operation_id', 'message_id', 'content_type'],
  validateBody: (body, meta) => validateSendBody(body, meta),
  targetScope: groupScope,
})

/**
 * 附件与对象传输（P7 `anp.attachment.v1`，C10）。
 *
 * 四条都是 **service-scoped**（§10.1 L797–798）：目标是公开服务的 `serviceDid`，不是某个
 * agent、也不是群——对象与消息是两回事，`create_slot` 的时候连消息都还没有。`targetMode`
 * 只判 `kind`，"`target.did` 就是这个 serviceDid"由处理器自己判（`requireServiceTarget()`），
 * 因为那条 MUST 要的是配置里的值，不是方法表构造时就有的东西。
 *
 * **都要 `origin_proof`，这是本实现的选择。** §10.1 L800 说 v1 **不要求**在 Object 控制服务
 * 端再验一次终端业务证明——那一跳由 P8 的 `serviceDid + HTTP Message Signatures` 保证
 * （L799）。同域没有那一跳，于是只剩 `meta.sender_did` 这个自报字段，而 `get_download_ticket`
 * 要拿它去判"你是不是有权的那个请求者"。所以同域这一侧仍然要 proof；跨域那一侧等 C11 把外层
 * 服务认证做出来，那时它才成为一条独立的放行路径（`attachments.md` §6）。
 *
 * **幂等作用域**：前三条取 `attachment_id`（各自只针对一个槽位所属的附件），
 * `get_download_ticket` 取 §7.2 L434 的三元组——票据的绑定键与授权记录的键是同一个，没有
 * 理由各取一套。四条都改状态（最后一条要落一行票据），所以四条都进幂等台账。
 */
function attachmentSpec(
  name: string,
  validateBody: (body: Record<string, unknown>, meta: AnpMeta) => AnpRejection | undefined,
  targetScope: (meta: AnpMeta, body: Record<string, unknown>) => string,
): MethodSpec {
  return {
    name,
    targetMode: 'service-scoped',
    profiles: [ATTACHMENT_PROFILE],
    securityProfiles: [ATTACHMENT_SECURITY_PROFILE],
    requiredMeta: ['sender_did', 'operation_id'],
    // §10.1 L802：这几条方法的 wire 模型里没有设备 selector，设备认证与路由上下文都是
    // 部署私有信息。§9.4 L691 与 §10.5.3 L1035 在票据那一侧又说了一遍。所以带上了就拒。
    forbiddenMeta: ['sender_device_id', 'recipient_device_id'],
    requiresOriginProof: () => true,
    authCodes: P1_AUTH_CODES,
    validateBody,
    targetScope,
  }
}

const ATTACHMENT_CREATE_SLOT_SPEC = attachmentSpec(
  ATTACHMENT_CREATE_SLOT,
  (body) => validateCreateSlotBody(body),
  attachmentScope,
)

const ATTACHMENT_COMMIT_OBJECT_SPEC = attachmentSpec(
  ATTACHMENT_COMMIT_OBJECT,
  (body) => validateCommitBody(body),
  attachmentScope,
)

const ATTACHMENT_ABORT_OBJECT_SPEC = attachmentSpec(
  ATTACHMENT_ABORT_OBJECT,
  (body) => validateAbortBody(body),
  attachmentScope,
)

const ATTACHMENT_GET_DOWNLOAD_TICKET_SPEC = attachmentSpec(
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  (body, meta) => validateTicketBody(body, meta),
  ticketScope,
)

/**
 * 密钥控制面（P5 §7，C12）。
 *
 * 两条方法在这一层同形：同一个 Profile（`anp.direct.e2ee.v2` 与 `direct.send` 共用，
 * §4.3 L161 的 Overlay 规矩）、`transport-protected`（§7.1 L467 与 §9.3 L821 是同一句
 * ——密钥控制面只走这一档）、`service-scoped`（目标必须是**目标 Agent 暴露的那个服务**，
 * §7.1 L466）、都要 `sender_did` / `sender_device_id` / `operation_id`。
 *
 * ## 为什么不要 `origin_proof`，而且**拒收** `auth`
 *
 * §7.1 L492 明写这条方法"does not require an additional business-layer `origin_proof`"
 * ——这是 §3.8 L140 对 v2 那条规矩的同一件事：认证由建链材料与 AAD 承担。而 §7.1 L472 与
 * §7.2 L548 又都写着未协商扩展时 `params.auth` **MUST** 缺省。两句合起来，`auth` 既不能
 * 要求也不能允许，所以 `validateParams` 见到它就拒（1003，与 `directSendParams` 同理由）。
 *
 * 这不是一个鉴权缺口。发布这条路上，真正的认证是 **Bundle 自己的 Object Proof**：§6.5 第 2
 * 项要求它由该设备清单里那条 `signing_key_id` 签出，而那把私钥只有那台设备有。领取这条路
 * 本来就不按调用方身份授权——它交回的是**目标设备的公开材料**，谁问都一样。
 * 见 `keys.ts` 的文件头与 `docs/design/e2ee-direct.md` §9。
 *
 * ## 两档 `targetScope` 不同，这不是手滑
 *
 * §7.1 的幂等键元组是 `(sender_did, sender_device_id, target.did, method, operation_id)`，
 * §7.2 的是同一串**再加一个 `target_did`**——领取的地址里多一个"问谁要"。`target_device_id`
 * 已经由设备段承载（`deviceSelector`），所以这里只差 `target_did` 那一段。两条方法各自取
 * 自己规范里逐字给出的那一段，而不是"看起来差不多就复用"。
 */
const KEY_SECURITY_PROFILE = 'transport-protected'

/** `requiredMeta` 保证了这两个字段在场，所以缺了就是方法表与处理器不一致——抛。
 *  兜空串会让一个代码错误变成一个 1017（"设备不合格"），那是把两件事说成一件。 */
function senderPair(meta: AnpMeta, method: string): DevicePair {
  const identity = meta.sender_did
  const deviceId = meta.sender_device_id
  if (identity === undefined || deviceId === undefined) {
    throw new ConnectxError('message_invalid', `${method} requires meta.sender_did and meta.sender_device_id`)
  }
  return { identity, deviceId }
}

/** 正文里的一个非空字符串。实现在 `validateBody` 之后才被调用，所以这里只做类型收窄；
 *  取不到仍然是当场抛——一个跑到这里的空串说明两处校验对不上了。 */
function bodyString(body: Record<string, unknown>, key: string): string {
  const value = body[key]
  if (typeof value !== 'string' || value === '') {
    throw new ConnectxError('message_invalid', `body.${key} must be a non-empty string`)
  }
  return value
}

/** `checkMethod` 保证 `meta.target` 在（`service-scoped` 是必须带 target 的模式），
 *  所以这里同 `direct.send` 的 `targetScope`：抛而不是兜空串。 */
function serviceTargetDid(meta: AnpMeta, method: string): string {
  const target = meta.target
  if (target === undefined) throw new ConnectxError('message_invalid', `${method} requires meta.target`)
  return target.did
}

interface KeySpecInput {
  name: string
  validateBody: (body: Record<string, unknown>) => AnpRejection | undefined
  deviceAddressed: (meta: AnpMeta, body: Record<string, unknown>) => DeviceAddressed
  targetScope: (meta: AnpMeta, body: Record<string, unknown>) => string
}

function keySpec(input: KeySpecInput): MethodSpec {
  return {
    name: input.name,
    targetMode: 'service-scoped',
    profiles: [DIRECT_E2EE_PROFILE],
    securityProfiles: [KEY_SECURITY_PROFILE],
    requiredMeta: ['sender_did', 'sender_device_id', 'operation_id'],
    // §7.1 / §7.2 都没有禁止任何 `meta` 字段——不像 P7 那样明说 wire 模型里没有设备
    // selector。规范没说禁就不自造一个禁令（P1 §10.3 L724 只在 Base 私聊那一处点过名）。
    forbiddenMeta: [],
    // §7.1 L492 逐字。见上面那一段。
    requiresOriginProof: () => false,
    // 到不了：`requiresOriginProof` 恒假，`authenticate()` 从不被调用。填一个合规的值只是
    // 方法表的完整性要求——这一族没有规范给的私有认证码（P5 §13 L1533–1545 那一段里
    // 4000–4012 全是关于**材料**的，没有一条说"你没通过认证"）。
    authCodes: P1_AUTH_CODES,
    validateParams: keyMethodParams,
    validateBody: (body) => input.validateBody(body),
    deviceAddressed: (meta, body) => input.deviceAddressed(meta, body),
    targetScope: (meta, body) => input.targetScope(meta, body),
  }
}

const PUBLISH_PREKEY_BUNDLE_SPEC = keySpec({
  name: PUBLISH_PREKEY_BUNDLE,
  validateBody: validatePublishBody,
  // §7.1 L476：这条方法点名的设备**只有发布方自己一台**——`meta.target.did` 是服务的 DID，
  // 收件人无从谈起（这条路上没有收件人）。
  deviceAddressed: (meta) => ({
    pairs: [senderPair(meta, PUBLISH_PREKEY_BUNDLE)],
    requirement: DIRECT_E2EE_DEVICE,
  }),
  // §7.1 的键元组：`meta.target.did` 就是那个 `target.did`，设备那一段由 `deviceAddressed`
  // 交出去（`idempotencyKey()` 收到 `deviceSelectors` 时自己追加）。
  targetScope: (meta) => serviceTargetDid(meta, PUBLISH_PREKEY_BUNDLE),
})

const GET_PREKEY_BUNDLE_SPEC = keySpec({
  name: GET_PREKEY_BUNDLE,
  validateBody: validateGetBundleBody,
  // 两台：调用方自己，以及正文里的目标设备（§7.2 L572 要求服务端**按 §4.1.1 验证精确的
  // `(target_did, target_device_id)`**，那就是这份 `pairs` 的第二项要交给 `checkDevice` 的
  // 两段）。顺序与规范一致：`pairs[0]` 是调用方，`pairs[1]` 是被问的那台。
  deviceAddressed: (meta, body) => ({
    pairs: [
      senderPair(meta, GET_PREKEY_BUNDLE),
      { identity: bodyString(body, 'target_did'), deviceId: bodyString(body, 'target_device_id') },
    ],
    requirement: DIRECT_E2EE_DEVICE,
    // §7.2 L578 与 §12.4 L1515：设备一旦失去资格，MUST 停止**返回**它的 PreKey 材料。
    // 所以重放也要重判——这与 `direct.send` 相反，理由写在 `DeviceAddressed.recheckOnReplay`。
    recheckOnReplay: true,
  }),
  // §7.2 的键元组比 §7.1 多一个 `target_did`。`meta.target.did` 对被本服务受理的请求是常量
  // （§7.2 L543 要求它等于 `serviceDid`），所以这里只有一个变量，`/` 分隔不可能歧义。
  targetScope: (meta, body) => `${serviceTargetDid(meta, GET_PREKEY_BUNDLE)}/${bodyString(body, 'target_did')}`,
})

/**
 * P6 的两条 KeyPackage 方法（§8，C13）。
 *
 * 与上面 P5 那一对同形——`service-scoped`、要 `sender_did` / `sender_device_id` /
 * `operation_id`、`requiresOriginProof` 恒假——但**不是同一档安全模式**：§4.3 L272 把这两条
 * 连同 `group.e2ee.notice` 定在 `transport-protected`，`group-e2ee` 留给四条控制方法
 * （L273）。Profile 也换成了 `anp.group.e2ee.v2`：§4.3 L264 要求 P6 请求的 `meta.profile`
 * **MUST** 等于它，所以这两条与 P4 那九个不共用 Profile，尽管目标建模与它们相邻。
 *
 * ## 为什么不写 `validateParams`（与 P5 那两条的差别）
 *
 * P5 §7.1 L472 与 §7.2 L548 都逐字写着未协商扩展时 `params.auth` **MUST** 缺省，
 * 所以那一对在 `keyMethodParams` 里把它拒掉。**P6 §8 没有这句话**：§8.1.2 与 §8.2.2 的
 * 字段清单里没有 `auth`，认证约束一节只说"v2 不要求为该方法额外定义新的业务层
 * `origin_proof`"（§8.1.2 L706）。
 *
 * 两句合起来是：这里既不要求它、也不禁止它。自造一条禁令会拒掉规范允许的请求，而规范在
 * 这一处没有给过禁令（P1 §10.3 L724 那条 1003 说的是私聊 Base 自己的字段）。
 *
 * ## `targetScope` 两档不同，与 P5 同理
 *
 * §8.2 的幂等键元组比 §8.1 多一个 `target_did`——领取的地址里多一个"问谁要"。
 * `target_device_id` 已经由设备段承载（`deviceSelector`），所以这里只差 `target_did`。
 */
function groupE2eeKeySpec(input: KeySpecInput): MethodSpec {
  return {
    name: input.name,
    targetMode: 'service-scoped',
    profiles: [GROUP_E2EE_PROFILE],
    securityProfiles: [GROUP_E2EE_KEY_SECURITY_PROFILE],
    requiredMeta: ['sender_did', 'sender_device_id', 'operation_id'],
    forbiddenMeta: [],
    // §8.1.2 L706 逐字。§8.2.2 L739 另说"匿名获取 KeyPackage 不属于 v2 MTI"，但 L740
    // 把最小互通定在 hop / service 级认证——同域明文没有那一跳时，这条方法剩下的认证是
    // 目标设备的资格（下面的 `deviceAddressed`）。缺口与 P5 同源，记在 e2ee-group.md。
    requiresOriginProof: () => false,
    // 到不了（`requiresOriginProof` 恒假）。填一个合规的值只是方法表的完整性要求。
    authCodes: P1_AUTH_CODES,
    validateBody: (body) => input.validateBody(body),
    deviceAddressed: (meta, body) => input.deviceAddressed(meta, body),
    targetScope: (meta, body) => input.targetScope(meta, body),
  }
}

const PUBLISH_KEY_PACKAGE_SPEC = groupE2eeKeySpec({
  name: PUBLISH_KEY_PACKAGE,
  validateBody: validatePublishKeyPackageBody,
  // §8.1.2 L697：点名的设备**只有发布方自己一台**——`meta.target.did` 是服务的 DID。
  deviceAddressed: (meta) => ({
    pairs: [senderPair(meta, PUBLISH_KEY_PACKAGE)],
    requirement: GROUP_E2EE_DEVICE,
  }),
  // §8.1 的键元组：`meta.target.did` 就是那个 `target.did`。
  targetScope: (meta) => serviceTargetDid(meta, PUBLISH_KEY_PACKAGE),
})

const GET_KEY_PACKAGE_SPEC = groupE2eeKeySpec({
  name: GET_KEY_PACKAGE,
  validateBody: validateGetKeyPackageBody,
  // 两台：调用方自己，以及正文里的目标设备（§8.2.2 L734–735 要求 `sender_device_id` 标识
  // 合格设备，§8.1.2/§8.2.4 L767 要求返回前按当前 Manifest 重验**目标**设备）。顺序与规范
  // 一致：`pairs[0]` 是调用方，`pairs[1]` 是被问的那台。
  deviceAddressed: (meta, body) => ({
    pairs: [
      senderPair(meta, GET_KEY_PACKAGE),
      { identity: bodyString(body, 'target_did'), deviceId: bodyString(body, 'target_device_id') },
    ],
    requirement: GROUP_E2EE_DEVICE,
    // §8.2.4 L767：设备一旦失去资格，MUST 停止**返回**它的 KeyPackage 材料。这条 MUST 说的
    // 是"返回前"，所以重放也要重判——与 `get_prekey_bundle` 同一档，理由写在
    // `DeviceAddressed.recheckOnReplay`。
    recheckOnReplay: true,
  }),
  // §8.2 的键元组比 §8.1 多一个 `target_did`。`meta.target.did` 对被受理的请求是常量
  // （§8.2.2 L732 要求它等于 `serviceDid`），所以这里只有一个变量，`/` 分隔不可能歧义。
  targetScope: (meta, body) => `${serviceTargetDid(meta, GET_KEY_PACKAGE)}/${bodyString(body, 'target_did')}`,
})

/**
 * P6 的四条控制面方法（§9，C13）。
 *
 * 与上面那一对是两个不同的位置：Profile 相同（§4.3 L264 要求 P6 请求的 `meta.profile`
 * **MUST** 是 `anp.group.e2ee.v2`），但安全模式是 `group-e2ee`（§4.3 L273），而且**四条都
 * 要 `auth.origin_proof`**（§9.2.3 / §9.3.3 / §9.4.3 / §9.5.3 逐字 "MUST exist"）。
 *
 * 认证失败回 P1 的公共码 1005：§17 L1930 逐字要求这类失败复用 P1 Core 的错误，P6 自己不
 * 定义第二套认证码段（5000–5013 里没有一条说"你没通过认证"）。
 *
 * 目标建模分两档，不是随手挑的：§4.4.1 L292–293 把 `create` 定成 **service-scoped**（那时
 * 群还没有密码学状态，`meta.target` 指向服务），§4.4.2 把另外三条定成 **group-addressed**
 * （`meta.target.did` 就是 `group_did`）。
 *
 * `deviceAddressed` 四条都有，但配的对数不同：`create` / `remove` / `send` 只点调用方自己
 * 一台（`devices[0]`），`add` 点两台——第二台是正文里那个被加入的设备（§13.4 第 5 项要判
 * 它"该不该是 leaf"，而资格门禁正好是判"这台设备此刻算不算数"的那一处）。
 *
 * **没有 `recheckOnReplay`**：§13.4 L1647 逐字要求 Add / Remove 的重试有幂等语义，§9.1 L630
 * 要求重试拿到同一个结果——而资格是**当下**的事实。重放时重判会让一台后来失去资格的调用方
 * 设备把一次早已受理的操作变成错误。这与 `get_prekey_bundle` 那一档正好相反（那里交回的是
 * 密钥材料，§7.2 L578 要求在**返回前**重验）。
 */
interface GroupControlSpecInput {
  name: string
  targetMode: 'service-scoped' | 'group-addressed'
  requiredMeta: readonly MetaField[]
  /** `send` 不给：它唯一那条正文要求属于 §13.3 的第 8 项，必须排在成员判定之后。
   *  理由写在 `groupControl.ts` 的正文校验一节。 */
  validateBody?: (body: Record<string, unknown>, meta: AnpMeta) => AnpRejection | undefined
  deviceAddressed: (meta: AnpMeta, body: Record<string, unknown>) => DeviceAddressed
  targetScope: (meta: AnpMeta, body: Record<string, unknown>) => string
}

function groupControlSpec(input: GroupControlSpecInput): MethodSpec {
  return {
    name: input.name,
    targetMode: input.targetMode,
    profiles: [GROUP_E2EE_PROFILE],
    securityProfiles: [GROUP_E2EE_SECURITY_PROFILE],
    requiredMeta: input.requiredMeta,
    // §4.3 L266 要求每个设备发起的 P6 请求带 `sender_device_id`，规范没有禁止任何 `meta`
    // 字段——自造一条禁令会拒掉规范允许的请求（与上面两条 Key 方法同一条理由）。
    forbiddenMeta: [],
    requiresOriginProof: () => true,
    authCodes: P1_AUTH_CODES,
    ...(input.validateBody !== undefined ? { validateBody: input.validateBody } : {}),
    deviceAddressed: (meta, body) => input.deviceAddressed(meta, body),
    targetScope: (meta, body) => input.targetScope(meta, body),
  }
}

const GROUP_E2EE_CREATE_SPEC = groupControlSpec({
  name: GROUP_E2EE_CREATE,
  targetMode: 'service-scoped',
  requiredMeta: ['sender_did', 'sender_device_id', 'operation_id'],
  validateBody: (body) => validateCreateE2eeBody(body),
  // §13.5 第 2 项：点名的设备是**owner 自己那一台**（§9.2.1 让 owner 成为初始成员）。
  deviceAddressed: (meta) => ({
    pairs: [senderPair(meta, GROUP_E2EE_CREATE)],
    requirement: GROUP_E2EE_DEVICE,
  }),
  // 幂等作用域取**正文里的** `group_did`，不是 `meta.target.did`（那是本服务的 DID）。
  // P6 没有给这一族的 `target_scope` 定字面值（§14.1 只说这三条控制动作不自己产生 P4 的
  // `group_state_version`），所以取"这次操作是关于谁的"：对 `create` 来说那个群在正文里。
  // 取服务 DID 会让同一个发送方在两个群上的两次创建共用一段作用域——`operation_id` 撞上就
  // 是一条 1008，而它们本是两件事。另外三条的群在 `meta.target.did`，于是四条合起来是同一
  // 条不变量:**一次 P6 操作的幂等作用域就是它所针对的那个群**。
  targetScope: (_meta, body) => bodyString(body, 'group_did'),
})

const GROUP_E2EE_ADD_SPEC = groupControlSpec({
  name: GROUP_E2EE_ADD,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'sender_device_id', 'operation_id'],
  validateBody: validateAddE2eeBody,
  // 两台：调用方（owner 自己）与被加入的那台。顺序与 `groupControl.ts` 的读法一致
  // （`device(ctx, 0)` 是 owner，`device(ctx, 1)` 是 `body.member_*`）。
  deviceAddressed: (meta, body) => ({
    pairs: [
      senderPair(meta, GROUP_E2EE_ADD),
      { identity: bodyString(body, 'member_did'), deviceId: bodyString(body, 'member_device_id') },
    ],
    requirement: GROUP_E2EE_DEVICE,
  }),
  targetScope: groupScope,
})

const GROUP_E2EE_REMOVE_SPEC = groupControlSpec({
  name: GROUP_E2EE_REMOVE,
  targetMode: 'group-addressed',
  requiredMeta: ['sender_did', 'sender_device_id', 'operation_id'],
  validateBody: validateRemoveE2eeBody,
  // **只有一台**：`remove` 的被移除设备不需要是合格设备（§9.4.3 那条"失去资格或被策略移掉
  // 的那一台"正是要移除它的理由），把它也点名会让一次合法的移除因为目标设备不合格而被
  // 1017 拒掉。判它在不在投影里的是处理器（5004 / 5013）。
  deviceAddressed: (meta) => ({
    pairs: [senderPair(meta, GROUP_E2EE_REMOVE)],
    requirement: GROUP_E2EE_DEVICE,
  }),
  targetScope: groupScope,
})

const GROUP_E2EE_SEND_SPEC = groupControlSpec({
  name: GROUP_E2EE_SEND,
  targetMode: 'group-addressed',
  // §9.5.3：`message_id` / `content_type` 与 P4 的 `group.send` 同样必带——前者是 §10.3 的
  // 消息级识别三元组里那一段，后者**固定**为 `application/anp-group-cipher+json`（那个值判
  // 在处理器里，因为它是"值对不对"而 `requiredMeta` 只管"在不在"）。
  requiredMeta: ['sender_did', 'sender_device_id', 'operation_id', 'message_id', 'content_type'],
  deviceAddressed: (meta) => ({
    pairs: [senderPair(meta, GROUP_E2EE_SEND)],
    requirement: GROUP_E2EE_DEVICE,
  }),
  targetScope: groupScope,
})

/** `POST /anp-im/rpc` 认得的方法。两个传输方法**不在其中**——理由写在 `stream.ts`。 */
const METHODS: readonly MethodSpec[] = [
  GET_CAPABILITIES_SPEC,
  DIRECT_SEND_SPEC,
  PUBLISH_PREKEY_BUNDLE_SPEC,
  GET_PREKEY_BUNDLE_SPEC,
  PUBLISH_KEY_PACKAGE_SPEC,
  GET_KEY_PACKAGE_SPEC,
  GROUP_E2EE_CREATE_SPEC,
  GROUP_E2EE_ADD_SPEC,
  GROUP_E2EE_REMOVE_SPEC,
  GROUP_E2EE_SEND_SPEC,
  GROUP_CREATE_SPEC,
  GROUP_GET_INFO_SPEC,
  GROUP_JOIN_SPEC,
  GROUP_ADD_SPEC,
  GROUP_REMOVE_SPEC,
  GROUP_LEAVE_SPEC,
  GROUP_UPDATE_PROFILE_SPEC,
  GROUP_UPDATE_POLICY_SPEC,
  GROUP_SEND_SPEC,
  ATTACHMENT_CREATE_SLOT_SPEC,
  ATTACHMENT_COMMIT_OBJECT_SPEC,
  ATTACHMENT_ABORT_OBJECT_SPEC,
  ATTACHMENT_GET_DOWNLOAD_TICKET_SPEC,
  SYNC_DELTA_SPEC,
  CONTACTS_LIST_SPEC,
  CONTACTS_PUT_SPEC,
  CONTACTS_REMOVE_SPEC,
  GROUP_REMARKS_LIST_SPEC,
  GROUP_REMARKS_PUT_SPEC,
  GROUP_REMARKS_REMOVE_SPEC,
]

/** 方法表里 `group.*` 那一族。分发与测试都从这里问"哪些是群方法"，不再各写一份名单。 */
export function groupMethodNames(): readonly string[] {
  return METHODS.filter((spec) => spec.profiles.includes(GROUP_PROFILE)).map((spec) => spec.name)
}

/** 两张表的全部方法，不分传输。
 *
 *  能力清单要回答的是"本服务实现了哪些 Profile"，那个问题与传输无关：`stream.auth` 只在
 *  WebSocket 上可达，但它的 Profile 一样要出现在自我描述里（realtime.md §9）。上面把控制
 *  面与流分成两张表是为了**查得到**——"这个方法的 Profile 是哪几个"必须只有一处答案——
 *  不是为了能力清单。 */
export function allMethods(): readonly MethodSpec[] {
  return [...METHODS, STREAM_AUTH_SPEC, STREAM_ACK_SPEC]
}

export function lookupMethod(name: string): MethodSpec | undefined {
  return METHODS.find((spec) => spec.name === name)
}

/** 流上那两个方法的表。与 `METHODS` 分开查，是因为它们出自两条不同的传输，而"这个方法在
 *  这条传输上认不认"必须只有一处答案——合起来的话，`stream.auth` 会在 HTTP 上也可达。 */
export function lookupStreamMethod(name: string): MethodSpec | undefined {
  return name === STREAM_AUTH ? STREAM_AUTH_SPEC : name === STREAM_ACK ? STREAM_ACK_SPEC : undefined
}

/** `meta.target` 是否满足这个方法声明的建模模式（P1 §6.2.5.1 L363–378）。
 *  `target` 缺失由调用方先判（那是 1003），到这里只判 `kind` 对不对。 */
export function targetBindingHolds(spec: MethodSpec, target: AnpTarget | undefined): boolean {
  const kind = TARGET_KIND[spec.targetMode]
  // endpoint-local：允许省略，也就没有 kind 可以对错。
  if (kind === undefined) return true
  return target?.kind === kind
}

/**
 * 方法自己声明的那些 MUST，按 §3 那张表的顺序查一遍。
 *
 * 信封层面查不到的都在这里：Profile（§6.2.2 L277）、安全模式（§6.2.3）、这个方法还要求
 * 哪些 `meta` 字段、以及目标建模模式（§6.2.5.1 L382）。`parseEnvelope` 已经保证 `meta`
 * 是个对象、`target` 的形状合法、`kind` 是三个词之一，所以这里只判"这个方法要不要求"。
 *
 * 收的是整个 `params` 而不是 `meta`：中间要跑 `validateParams`（它同时看 `meta` 与
 * `auth`），而"查全这个方法的 MUST"必须**只有一处入口**——收 `meta` 的话，那一处就成了
 * 可选的、能被下一个调用点忘掉的散装检查。
 *
 * **缺失 `target` 报 1003，不是 1014**：L382 那条 MUST 说的是"`kind` 与声明的模式不一致"，
 * 前提是 `target` 在；一个连 `target` 都没有的请求，错的是 `params` 的形状（§10.3 L704）。
 * 这是本实现的读法，规范没有为"该有却没有"单独配码。
 */
export function checkMethod(spec: MethodSpec, params: AnpParams): AnpRejection | undefined {
  const { meta } = params
  if (!spec.profiles.includes(meta.profile)) {
    return anpRejection('anp.unsupported_profile', `${spec.name} does not implement profile ${meta.profile}`)
  }
  if (!spec.securityProfiles.includes(meta.security_profile)) {
    return anpRejection(
      'anp.unsupported_security_profile',
      `${spec.name} does not implement security profile ${meta.security_profile}`,
    )
  }
  for (const field of spec.requiredMeta) {
    if (meta[field] === undefined) {
      return anpRejection('anp.invalid_params_shape', `${spec.name} requires meta.${field}`)
    }
  }
  for (const field of spec.forbiddenMeta) {
    if (meta[field] !== undefined) {
      return anpRejection('anp.invalid_params_shape', `${spec.name} forbids meta.${field}`)
    }
  }

  // Profile 层那条按 `meta.profile` 分派的规则在 target 之前：它判的是"这两个 Profile 各自
  // 的字段要求"（设备 selector 在不在、`content_type` 是哪一类、`auth` 该不该在），而那些
  // 字段与 `target` 无关。target 那几条判的是**目标建模模式**，是另一回事；v2 请求缺
  // `target` 时该收到的是 1003（形状），不是 1014。
  const profileRefusal = spec.validateParams?.(params)
  if (profileRefusal !== undefined) return profileRefusal

  // §6.2.5 L341 与 §6.2.5.1 L377–380：target 必不必填，由建模模式决定。L1068 再补一条
  // ——只要这个方法要 `origin_proof`，`meta.target` 就 MUST 存在，因为 `@target-uri` 要用
  // 它的 kind 与 did（L1062）。两条取并：一个 endpoint-local 方法将来若要 proof，仍然
  // 必须带 target，而那正是 L1070 要求它的 Profile 显式定义的东西。
  const needsTarget = spec.targetMode !== 'endpoint-local' || spec.requiresOriginProof(meta)
  if (meta.target === undefined) {
    if (!needsTarget) return undefined
    return anpRejection(
      'anp.invalid_params_shape',
      `${spec.name} is ${spec.targetMode} and requires meta.target`,
    )
  }
  if (!targetBindingHolds(spec, meta.target)) {
    return anpRejection(
      'anp.invalid_target_binding',
      `${spec.name} is ${spec.targetMode}; meta.target.kind MUST be ${String(TARGET_KIND[spec.targetMode])}`,
      { details: { received: meta.target.kind } },
    )
  }
  // §9.1.1：取件面的 `target.did` 必须就是签名者。前一条只保证了 `kind` 对，这一条才是
  // "读的是自己的信箱"。做成显式拒绝而不是靠"反正也读不到"——那是一种隐式结果，一旦
  // 别处把 `ownerOf()` 写成了 `meta.target.did` 就会变成越权读，而且没有任何测试会红。
  if (spec.targetMode === 'self-addressed' && meta.target.did !== meta.sender_did) {
    return anpRejection(
      'anp.invalid_target_binding',
      `${spec.name} is self-addressed; meta.target.did MUST equal meta.sender_did`,
    )
  }
  return undefined
}
