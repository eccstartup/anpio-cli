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
  type AnpRejection,
  type AnpTarget,
  type AnpTargetKind,
} from '@agentx/core'
import { DIRECT_AUTH_CODES, GROUP_AUTH_CODES, P1_AUTH_CODES, type AuthErrorCodes } from './auth'
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
import {
  EXTENSION_PROFILE,
  INBOX_GET,
  INBOX_MARK_READ,
  MESSAGE_GET_BATCH,
  SYNC_DELTA,
  validateDeltaBody,
  validateGetBatchBody,
  validateInboxGetBody,
  validateMarkReadBody,
} from './inbox'
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
  /** Profile 层对 `body` 的校验。缺省表示这个方法没有正文规则。
   *
   *  签名收 `meta` 而不只是 `body`：`direct.send` 的正文规则要用 `content_type` 判
   *  负载字段对不对得上，而那是 `meta` 里的。 */
  validateBody?(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined
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

/** 直连私聊。`meta.target.kind` 必须是 `agent`（P3 §5.1 L172）。 */
const DIRECT_SEND_SPEC: MethodSpec = {
  name: DIRECT_SEND,
  targetMode: 'agent-addressed',
  profiles: ['anp.direct.base.v1'],
  securityProfiles: ['transport-protected'],
  requiredMeta: ['sender_did', 'operation_id', 'message_id', 'content_type'],
  // P3 §7.1.2 L362：设备 selector 只属于 P5 v2。P1 §10.3 L724 说 Base 操作收到 selector
  // 就按"非法参数"处理——1015–1018 那四个码专给设备定址 Overlay，这里不许用。
  forbiddenMeta: ['sender_device_id', 'recipient_device_id'],
  // P3 §6.4 L290 要求 base + transport-protected 必须带 `auth`。P3 §4.3 L161 让
  // `anp.direct.e2ee.v2` 整个覆盖掉这条强制要求（该 Overlay 用建链材料与 AAD 认证发送方，
  // 为的是保住更强的可否认性）。那个 profile 是 C12 的，届时加进上面的 `profiles` 即可，
  // 判断保持写在这一处。
  requiresOriginProof: (meta) => meta.profile !== 'anp.direct.e2ee.v2',
  authCodes: DIRECT_AUTH_CODES,
  // P3 §6 的负载互斥规则与 P4 §7.6 逐字相同，所以两个 Profile 共用一份（`payload.ts`）。
  validateBody: (body, meta) => validatePayloadBody(body, meta.content_type ?? ''),
  // P3 §8.2 L437–442：`(sender_did, target.did, method, operation_id)`。
  targetScope: (meta) => {
    const target = meta.target
    // dispatch 已经查过目标绑定（1014），所以这里必定存在。抛而不是兜一个空串：
    // 空串会算出一个谁也不会再命中的键，那比当场炸掉更坏。
    if (target === undefined) throw new ConnectxError('message_invalid', 'direct.send requires meta.target')
    return target.did
  },
}

/**
 * 取件面（message-service.md §9）共有的那几项。
 *
 * 四个方法在这一层完全同形：自己那个 Profile、只认 `transport-protected`、要 proof、
 * 认证失败回 P1 §10.3 L706 的公共码（**这一族没有规范给的私有码**，`1005` 是公共段里
 * 唯一说"没通过认证"的那个）、目标必须是自己（§9.1.1）。差异只有正文校验与是否改状态，
 * 所以下面每个方法只写这两件，其余从这来。
 */
function extensionSpec(
  name: string,
  validateBody: (body: Record<string, unknown>) => AnpRejection | undefined,
  targetScope?: (meta: AnpMeta) => string,
): MethodSpec {
  return {
    name,
    targetMode: 'self-addressed',
    profiles: [EXTENSION_PROFILE],
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

/** 四个读方法不改状态，所以只有 `inbox.mark_read` 带 `targetScope`——它也是这一族里
 *  唯一进幂等台账的。作用域就是信箱主人，与 `direct.send` 取 `target.did` 同理。 */
function selfScope(meta: AnpMeta): string {
  const target = meta.target
  if (target === undefined) throw new ConnectxError('message_invalid', `${INBOX_MARK_READ} requires meta.target`)
  return target.did
}

const INBOX_GET_SPEC = extensionSpec(INBOX_GET, validateInboxGetBody)
const INBOX_MARK_READ_SPEC = extensionSpec(INBOX_MARK_READ, validateMarkReadBody, selfScope)
const MESSAGE_GET_BATCH_SPEC = extensionSpec(MESSAGE_GET_BATCH, validateGetBatchBody)
const SYNC_DELTA_SPEC = extensionSpec(SYNC_DELTA, validateDeltaBody)

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

/** `POST /anp-im/rpc` 认得的方法。两个传输方法**不在其中**——理由写在 `stream.ts`。 */
const METHODS: readonly MethodSpec[] = [
  GET_CAPABILITIES_SPEC,
  DIRECT_SEND_SPEC,
  GROUP_CREATE_SPEC,
  GROUP_GET_INFO_SPEC,
  GROUP_JOIN_SPEC,
  GROUP_ADD_SPEC,
  GROUP_REMOVE_SPEC,
  GROUP_LEAVE_SPEC,
  GROUP_UPDATE_PROFILE_SPEC,
  GROUP_UPDATE_POLICY_SPEC,
  GROUP_SEND_SPEC,
  INBOX_GET_SPEC,
  INBOX_MARK_READ_SPEC,
  MESSAGE_GET_BATCH_SPEC,
  SYNC_DELTA_SPEC,
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
 * **缺失 `target` 报 1003，不是 1014**：L382 那条 MUST 说的是"`kind` 与声明的模式不一致"，
 * 前提是 `target` 在；一个连 `target` 都没有的请求，错的是 `params` 的形状（§10.3 L704）。
 * 这是本实现的读法，规范没有为"该有却没有"单独配码。
 */
export function checkMethod(spec: MethodSpec, meta: AnpMeta): AnpRejection | undefined {
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
