// C9 —— 群组（P4 `anp.group.base.v2`）在 Group Host 这一侧的语义。
//
// 本服务就是 P4 §3.2 L86–90 说的 **Group Host Service**：所有改变群状态的操作经它受理与
// 排序。这个文件装的是"受理之后做什么"——方法表要哪些 `meta`、幂等键取什么，在
// `methods.ts` 里；信封、认证、分发顺序在各自那几层。
//
// 三件事在这里定形，它们是 P4 最容易写错的地方：
//
// 1. **什么推进什么**（§6.2–§6.3）。状态变更推进 `group_state_version`，群消息只推进
//    `group_event_seq`，两者都推进 `group_event_seq`。
// 2. **两个通知的 `sender_did` 不是一回事**（§8.10 L880 vs §8.11 L921）：`group.incoming`
//    的发起者是**原始发送方**，`group.state_changed` 的发起者是**群自己**。
// 3. **判定一律走 `group_policy`**（§11.3 L1074–1085），不看服务端隐含规则。
//
// 所有拒绝都抛 `AnpRefusal`：那让"查库才能判"的拒绝落在事务**里面**，从而满足 §9.1 L641
// 要求的"以新身份拒绝之前先返回旧 DID 下的幂等重放结果"（`refusal.ts` 有完整说明）。

import { randomBytes } from 'node:crypto'
import {
  anpRejection,
  buildMessageNotification,
  ConnectxError,
  profileRejection,
  type AnpAuth,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
} from '@agentx/core'
import type { DeliveryRecord, Storage } from '../storage/types'
import { attachmentGrantsFor, insertAttachmentGrants } from './attachments'
import { isNonEmptyString, unknownField } from './body'
import { validatePayloadBody } from './payload'
import { AnpRefusal, refusal } from './refusal'

export const GROUP_PROFILE = 'anp.group.base.v2'
/** §8.5 L211：作为独立运行的基础群 Profile 时，安全模式只能是这一个。 */
export const GROUP_SECURITY_PROFILE = 'transport-protected'

export const GROUP_INCOMING = 'group.incoming'
export const GROUP_STATE_CHANGED = 'group.state_changed'

export const GROUP_CREATE = 'group.create'
export const GROUP_GET_INFO = 'group.get_info'
export const GROUP_JOIN = 'group.join'
export const GROUP_ADD = 'group.add'
export const GROUP_REMOVE = 'group.remove'
export const GROUP_LEAVE = 'group.leave'
export const GROUP_UPDATE_PROFILE = 'group.update_profile'
export const GROUP_UPDATE_POLICY = 'group.update_policy'
export const GROUP_SEND = 'group.send'

/** §7.10.2 L585–591 的标准事件类型。这里只列 C9 会产生的那些。 */
const EVENT_MEMBER_ACTIVATED = 'member-activated'
const EVENT_MEMBER_REMOVED = 'member-removed'
const EVENT_MEMBER_LEFT = 'member-left'
const EVENT_PROFILE_UPDATED = 'group-profile-updated'
const EVENT_POLICY_UPDATED = 'group-policy-updated'

/** §7.9 L497–498 的两种回执。 */
const RECEIPT_OPERATION = 'group-operation-accepted'
const RECEIPT_MESSAGE = 'group-message-accepted'

// ---- 错误码 ------------------------------------------------------------------

function pair(code: number, anpCode: string): { code: number; anpCode: string } {
  return { code, anpCode }
}

/**
 * §12 L1153–1164 里**本服务会发**的那几个。走 `profileRejection` 而不是 `anpRejection`：
 * 这一段不在 P1 的公共表里，码值也不在 1000–1021 之间。
 *
 * 没在这里的三个，是因为它们在本服务里**没有产生路径**，留一个发不出去的码比造个场景去
 * 用它诚实：
 * - 3002 `group.admission_not_allowed`：§8.3.2 L686 明写非 `open-join` 时 SHOULD 回
 *   `group.policy_violation`；v1 的入群也没有带外凭据这类前置条件（§3.7 L135）。
 * - 3007 `group.host_unavailable`：本服务就是 Host，"Host 暂不可用"是它自己不可用。
 * - 3010 `group.invalid_group_receipt`：v1 同域收不到别家的回执，这一族没有验证方。
 */
const GROUP_ERRORS = {
  notMember: pair(3000, 'group.not_member'),
  alreadyMember: pair(3001, 'group.already_member'),
  policyViolation: pair(3003, 'group.policy_violation'),
  memberConflict: pair(3005, 'group.member_conflict'),
  securityModeRequired: pair(3006, 'group.security_mode_required'),
} as const

type GroupErrorName = keyof typeof GROUP_ERRORS

function groupError(name: GroupErrorName, message: string): AnpRejection {
  const codes = GROUP_ERRORS[name]
  return profileRejection(codes.code, codes.anpCode, message)
}

/** §7.1 L349–358 的结构是硬的：值域与键集都是 MUST。违反的是**对象定义**，所以回 1003
 *  （`anp.invalid_params_shape`），不是 3003——3003 留给"你没这个权限"（groups.md §8）。 */
function shapeProblem(message: string): AnpRejection {
  return anpRejection('anp.invalid_params_shape', message)
}

// ---- 群策略与资料 ------------------------------------------------------------

const ADMISSION_MODES = ['admin-add', 'open-join'] as const
const PERMISSION_KEYS = ['send', 'add', 'remove', 'update_profile', 'update_policy'] as const
const ROLES = ['owner', 'admin', 'member'] as const

type Role = (typeof ROLES)[number]
type PermissionKey = (typeof PERMISSION_KEYS)[number]

/**
 * §6.4 L279–291 的层级。要求 `member` 时 `admin` / `owner` 自动满足。
 *
 * 两个方向的兜底都是**失败关闭**：要求一个不认识的角色时没人满足得了他，而一个不认识的
 * 成员角色满足不了任何要求。表里查不到就当 0/无穷，不抛错——策略对象已经在写的路上验过
 * 了（`policyProblem`），这里再炸一次只会把一次可诊断的拒绝变成 500。
 */
const ROLE_RANK: Readonly<Record<string, number>> = { member: 1, admin: 2, owner: 3 }

function roleSatisfies(role: string, required: string): boolean {
  const have = ROLE_RANK[role] ?? 0
  const need = ROLE_RANK[required] ?? Number.POSITIVE_INFINITY
  return have >= need
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** §7.1 L347–358 的结构校验。返回第一处问题的说明，或 `undefined`。 */
function policyProblem(policy: Record<string, unknown>): string | undefined {
  const mode = policy.admission_mode
  if (typeof mode !== 'string' || !(ADMISSION_MODES as readonly string[]).includes(mode)) {
    return `group_policy.admission_mode MUST be one of ${ADMISSION_MODES.join(', ')}`
  }
  const permissions = policy.permissions
  if (!isPlainObject(permissions)) return 'group_policy.permissions MUST be an object'
  const keys = Object.keys(permissions)
  // 「包含且仅包含」：少一个键与多一个键都是违反对象定义。
  const missing = PERMISSION_KEYS.filter((key) => !keys.includes(key))
  const extra = keys.filter((key) => !(PERMISSION_KEYS as readonly string[]).includes(key))
  if (missing.length > 0 || extra.length > 0) {
    return `group_policy.permissions MUST contain exactly ${PERMISSION_KEYS.join(', ')}`
  }
  for (const key of PERMISSION_KEYS) {
    const value = permissions[key]
    if (typeof value !== 'string' || !(ROLES as readonly string[]).includes(value)) {
      return `group_policy.permissions.${key} MUST be one of ${ROLES.join(', ')}`
    }
  }
  // `max_members` 是**十进制字符串**（§7.1 L371）——本服务要拿它比大小，所以它的类型
  // 必须在这里就被钉住，不能等到比较那一刻才发现是个数字或一句别的话。
  const max = policy.max_members
  if (max !== undefined && (typeof max !== 'string' || !/^\d+$/.test(max))) {
    return 'group_policy.max_members MUST be a decimal string'
  }
  return undefined
}

/**
 * §7.4 L414 的 `discoverability` 只说 MAY、只列推荐值，没说缺省。本服务取最紧的那个并在
 * 写入时就落成实体：缺省成 `public` 会把一个刚建好的群默认公开，而那个错误是**安静**的
 * ——暴露的是资料与成员列表，不是一条报错。[groups.md](../docs/design/groups.md) §4 记了
 * 这是本服务的选择。
 *
 * 在**每次写**的时候materialize，而不是读的时候兜：`group.update_profile` 的一个 `null`
 * 能把这一项删掉，读时兜的话那一刻起群就变成公开的了。
 */
function profileDefaults(profile: Record<string, unknown>): Record<string, unknown> {
  return profile.discoverability === undefined ? { ...profile, discoverability: 'private' } : profile
}

/**
 * RFC 7386 JSON Merge Patch（§8.7.2 L780、§8.8.2 L806）。
 *
 * 三条：`null` 删键；两边都是对象才递归；**其余一律替换**——数组在这条规则下不出现在
 * "两边都是对象"里，所以整段换掉，不会按下标合并。返回新对象，不改参数：调用方手上那个
 * 是从库里读出来解析的，就地改会让"失败就不落库"变成一句空话。
 */
function mergePatch(
  target: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...target }
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) {
      delete merged[key]
      continue
    }
    const current = merged[key]
    merged[key] = isPlainObject(value) && isPlainObject(current) ? mergePatch(current, value) : value
  }
  return merged
}

// ---- 成员与授权 --------------------------------------------------------------

interface GroupView {
  groupDid: string
  hostServiceDid: string
  stateVersion: number
  eventSeq: number
  profile: Record<string, unknown>
  policy: Record<string, unknown>
  creatorDid: string
  createdAt: string
}

function loadGroup(storage: Storage, groupDid: string): GroupView {
  const row = storage.group(groupDid)
  // 本服务不托管这个 `group_did`，回给调用方的是"你不是该群成员"（3000）。规范没有为
  // "群不存在"配码，而这两种情形对调用方没有分别；更重要的是，后者不会泄露一个私有群
  // 是否存在过。
  if (row === undefined) throw refusal(groupError('notMember', `group ${groupDid} is not hosted here`))
  return {
    groupDid: row.groupDid,
    hostServiceDid: row.hostServiceDid,
    stateVersion: row.groupStateVersion,
    eventSeq: row.groupEventSeq,
    profile: JSON.parse(row.groupProfileJson) as Record<string, unknown>,
    policy: JSON.parse(row.groupPolicyJson) as Record<string, unknown>,
    creatorDid: row.creatorDid,
    createdAt: row.createdAt,
  }
}

function activeMemberDids(storage: Storage, groupDid: string): string[] {
  return storage
    .groupMembers(groupDid)
    .filter((member) => member.membershipStatus === 'active')
    .map((member) => member.memberDid)
}

/**
 * 调用方当前是 `active` 成员，返回他这一行。
 *
 * §11.3 L1074–1085 把成员身份与权限分成两步：**不是成员**（3000）与**是成员但不够格**
 * （3003）是两种拒绝，而 §8.2.2 L659 又要求私有群的读取者必须有身份。合成一步会让
 * "我不是成员"与"我不够权限"回同一个码，调用方就无从知道该去申请入群还是去要权限。
 */
function requireActiveMember(storage: Storage, groupDid: string, actorDid: string) {
  const member = storage.groupMember(groupDid, actorDid)
  if (member === undefined || member.membershipStatus !== 'active') {
    throw refusal(groupError('notMember', `${actorDid} is not an active member of ${groupDid}`))
  }
  return member
}

/** §11.3：权限键全部来自 `group_policy.permissions`，没有服务端的隐含规则。 */
function requirePermission(policy: Record<string, unknown>, memberRole: string, key: PermissionKey): void {
  const permissions = policy.permissions
  const required = isPlainObject(permissions) ? permissions[key] : undefined
  if (typeof required !== 'string' || !roleSatisfies(memberRole, required)) {
    throw refusal(
      groupError('policyViolation', `group_policy.permissions.${key} requires at least ${String(required)}`),
    )
  }
}

/** §7.1 L370：`max_members` 数的是 `active` **DID** 数，同一 DID 下的设备仍只算一个。 */
function withinMemberLimit(policy: Record<string, unknown>, activeCount: number, adding: number): boolean {
  const max = policy.max_members
  if (typeof max !== 'string' || !/^\d+$/.test(max)) return true
  return activeCount + adding <= Number(max)
}

// ---- 请求上下文 --------------------------------------------------------------

export interface GroupContext {
  storage: Storage
  /** 本服务的 `serviceDid`：`group.create` 的目标必须等于它，`group_did` 也挂在它下面。 */
  serviceDid: string
  meta: AnpMeta
  body: Record<string, unknown>
  auth?: AnpAuth
  /** RFC 3339。由调用方给（一次请求一个时刻），测试才好钉住它。 */
  acceptedAt: string
  /** 这次请求的 Signed Request Object 摘要 —— `group_receipt.payload_digest` 就是它。 */
  requestDigest: string
  /** 事务提交之后才用得上的投递，见 `direct.ts` 里同名字段的说明。 */
  onDelivery?: (record: DeliveryRecord) => void
}

export type GroupHandler = (ctx: GroupContext) => Record<string, unknown>

function actorOf(meta: AnpMeta): string {
  const did = meta.sender_did
  // 方法表把 `sender_did` 标成必填，走到这里必然在。抛而不是兜空串：空串会算出一个谁也
  // 不会再命中的成员身份，那比当场炸掉更坏。
  if (did === undefined || did === '') {
    throw new ConnectxError('message_invalid', 'group methods require meta.sender_did')
  }
  return did
}

function targetOf(meta: AnpMeta): string {
  const did = meta.target?.did
  if (did === undefined || did === '') {
    throw new ConnectxError('message_invalid', 'group methods require meta.target.did')
  }
  return did
}

function operationIdOf(meta: AnpMeta): string {
  const id = meta.operation_id
  if (id === undefined || id === '') {
    throw new ConnectxError('message_invalid', 'state-changing group methods require meta.operation_id')
  }
  return id
}

/** §7.9 L500–504 的 `group_receipt`，`proof` 缺席的理由见 [groups.md](../docs/design/groups.md) §7。 */
function groupReceipt(input: {
  receiptType: string
  groupDid: string
  stateVersion: number
  eventSeq: number
  subjectMethod: string
  operationId: string
  actorDid: string
  acceptedAt: string
  payloadDigest: string
  messageId?: string
}): Record<string, unknown> {
  return {
    receipt_type: input.receiptType,
    group_did: input.groupDid,
    // §7.9 L506–507 与 §6.3 L249：两个都是**字符串**，不是数字。
    group_state_version: String(input.stateVersion),
    group_event_seq: String(input.eventSeq),
    subject_method: input.subjectMethod,
    operation_id: input.operationId,
    ...(input.messageId !== undefined ? { message_id: input.messageId } : {}),
    actor_did: input.actorDid,
    accepted_at: input.acceptedAt,
    payload_digest: input.payloadDigest,
  }
}

// ---- 通知 --------------------------------------------------------------------

/** 排一行投递 + 一份出站推送。事务里只写，真正解析对端与发 HTTP 的是 delivery worker。 */
function deliver(ctx: GroupContext, recipientDid: string, messageId: string, method: string, params: AnpParams): void {
  const record = ctx.storage.appendDelivery({
    ownerDid: recipientDid,
    messageId,
    method,
    paramsJson: JSON.stringify(params),
    acceptedAt: ctx.acceptedAt,
  })
  ctx.onDelivery?.(record)
  ctx.storage.enqueueOutbox({
    recipientDid,
    payloadJson: JSON.stringify(
      buildMessageNotification({
        method,
        meta: params.meta,
        body: params.body,
        ...(params.auth !== undefined ? { auth: params.auth } : {}),
      }),
    ),
    nextAttemptAt: ctx.acceptedAt,
  })
}

interface StateChange {
  eventType: string
  subjectMethod: string
  actorDid: string
  stateVersion: number
  eventSeq: number
  subjectDid?: string
  membershipStatus?: string
}

/**
 * 落一个 §7.10 的事件并按 §8.11 通知出去。
 *
 * 收件人是**变更之后**的 `active` 成员，减去发起人自己（他知道自己刚做了什么，而且
 * `group.incoming` 那条线上的既有取舍就是不给自己写投递行）。`member-removed` /
 * `member-left` 另按 §8.11 L926–928 的例外，把**同一个**事件对象再给 `subject_did` 发一份
 * ——此时他已经不是 `active`，这一步是那封"最后一封信"唯一能到达他的地方。
 *
 * 那封最终信封的重试与保留靠 outbox 自己的尝试上界（[message-service.md] §8.4 的
 * fail-closed：到顶丢行）。这就是 §8.11 要的"显式的部署上限"，本服务不为它另造一套机制。
 */
function announce(ctx: GroupContext, change: StateChange): void {
  const groupDid = targetOf(ctx.meta)
  const event: Record<string, unknown> = {
    event_id: `evt-${groupDid}-${String(change.eventSeq)}`,
    event_type: change.eventType,
    group_did: groupDid,
    group_state_version: String(change.stateVersion),
    group_event_seq: String(change.eventSeq),
    subject_method: change.subjectMethod,
    changed_at: ctx.acceptedAt,
    actor_did: change.actorDid,
    ...(change.subjectDid !== undefined ? { subject_did: change.subjectDid } : {}),
    ...(change.membershipStatus !== undefined ? { membership_status: change.membershipStatus } : {}),
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid,
      stateVersion: change.stateVersion,
      eventSeq: change.eventSeq,
      subjectMethod: change.subjectMethod,
      operationId: operationIdOf(ctx.meta),
      actorDid: change.actorDid,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }

  ctx.storage.appendGroupEvent({
    groupDid,
    eventSeq: change.eventSeq,
    eventType: change.eventType,
    payloadJson: JSON.stringify(event),
    occurredAt: ctx.acceptedAt,
  })

  const recipients = activeMemberDids(ctx.storage, groupDid).filter((did) => did !== change.actorDid)
  const subject = change.subjectDid
  // 那封"最后一封信"**只**给被移除 / 已离群的人（§8.11 L926–928）。条件必须两条事件类型都
  // 点名：`member-activated` 的 subject 同样不在 recipients 里（他刚被加进来，而 actor 是
  // 别人），照"subject 不在 recipients 里"发就会给每个新成员多发一份自作用域的通知。
  const left = change.eventType === EVENT_MEMBER_REMOVED || change.eventType === EVENT_MEMBER_LEFT
  const final = left && subject !== undefined && !recipients.includes(subject) ? [subject] : []

  for (const recipient of [...recipients, ...final]) {
    const meta: AnpMeta = {
      profile: GROUP_PROFILE,
      // §8.11 L919：这个通知的安全模式写死 `transport-protected`，与群的策略无关。
      security_profile: GROUP_SECURITY_PROFILE,
      // §8.11 L921：发起者是**群自己**，不是触发这次变更的那个成员。
      sender_did: groupDid,
      target: { kind: 'agent', did: recipient },
    }
    deliver(ctx, recipient, event.event_id as string, GROUP_STATE_CHANGED, { meta, body: event })
  }
}

// ---- body 校验 ---------------------------------------------------------------

/**
 * 本文件里每个方法都这么查一遍：**只认它那一条规范段落点名过的正文字段**。
 *
 * 对 `group.join` / `group.add` 这不是风格问题：§8.3.2 L681 与 §8.4.2 L698 都写着正文
 * **MUST NOT** 包含名称、稳定主体字段或其它成员标识，而"其它成员标识"没有可枚举的
 * 内容——只有一张白名单能把这条 MUST NOT 真的执行下去。
 *
 * `group.send` 是**例外**，见它自己的校验函数：它的正文是应用层负载。
 */
function rejectUnknown(body: Record<string, unknown>, allowed: readonly string[]): void {
  const unknown = unknownField(body, allowed)
  if (unknown !== undefined) throw refusal(unknown)
}

function optionalObject(body: Record<string, unknown>, field: string): Record<string, unknown> | undefined {
  const value = body[field]
  if (value === undefined) return undefined
  if (!isPlainObject(value)) throw refusal(shapeProblem(`body.${field} MUST be an object`))
  return value
}

function requiredObject(body: Record<string, unknown>, field: string): Record<string, unknown> {
  const value = optionalObject(body, field)
  if (value === undefined) throw refusal(shapeProblem(`body.${field} MUST exist`))
  return value
}

function optionalText(body: Record<string, unknown>, field: string): void {
  const value = body[field]
  if (value !== undefined && typeof value !== 'string') {
    throw refusal(shapeProblem(`body.${field} MUST be a string`))
  }
}

function flag(body: Record<string, unknown>, field: string): void {
  const value = body[field]
  if (value !== undefined && typeof value !== 'boolean') {
    throw refusal(shapeProblem(`body.${field} MUST be a boolean`))
  }
}

/** §8.4.2 L700 / §7.2 L384：省略 `role` 时解释为 `member`；给了就必须是三档之一。 */
function roleOf(value: unknown, where: string): Role {
  if (value === undefined) return 'member'
  if (typeof value !== 'string' || !(ROLES as readonly string[]).includes(value)) {
    throw refusal(shapeProblem(`${where} MUST be one of ${ROLES.join(', ')}`))
  }
  return value as Role
}

interface InitialMember {
  memberDid: string
  role: Role
}

/** §8.1.2 L629：`initial_members` 的每一项 MUST 含 `member_did`，MAY 含 `role`。 */
function initialMembersOf(body: Record<string, unknown>): InitialMember[] {
  const value = body.initial_members
  if (value === undefined) return []
  if (!Array.isArray(value)) throw refusal(shapeProblem('body.initial_members MUST be an array'))
  return value.map((entry, index) => {
    if (!isPlainObject(entry)) {
      throw refusal(shapeProblem(`body.initial_members[${String(index)}] MUST be an object`))
    }
    const memberDid = entry.member_did
    if (!isNonEmptyString(memberDid)) {
      throw refusal(shapeProblem(`body.initial_members[${String(index)}].member_did MUST be a non-empty string`))
    }
    return { memberDid, role: roleOf(entry.role, `body.initial_members[${String(index)}].role`) }
  })
}

const CREATE_FIELDS = ['group_profile', 'group_policy', 'initial_members'] as const
const GET_INFO_FIELDS = ['include_policy', 'include_member_list'] as const
const JOIN_FIELDS = ['reason_text'] as const
const ADD_FIELDS = ['member_did', 'role', 'reason_text'] as const
const REMOVE_FIELDS = ['member_did', 'reason_text'] as const
const LEAVE_FIELDS: readonly string[] = []
const UPDATE_PROFILE_FIELDS = ['group_profile_patch'] as const
const UPDATE_POLICY_FIELDS = ['group_policy_patch'] as const

export function validateCreateBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, CREATE_FIELDS)
    // §8.1.2 L627：`group_policy` MUST 存在，而且**现在**就得立得住——一个本服务解释不了
    // 的策略对象，就是一个本服务治理不了的群。
    const problem = policyProblem(requiredObject(body, 'group_policy'))
    if (problem !== undefined) return shapeProblem(problem)
    optionalObject(body, 'group_profile')
    initialMembersOf(body)
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateGetInfoBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, GET_INFO_FIELDS)
    flag(body, 'include_policy')
    flag(body, 'include_member_list')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateJoinBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, JOIN_FIELDS)
    optionalText(body, 'reason_text')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateAddBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, ADD_FIELDS)
    if (!isNonEmptyString(body.member_did)) return shapeProblem('body.member_did MUST be a non-empty string')
    roleOf(body.role, 'body.role')
    optionalText(body, 'reason_text')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateRemoveBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, REMOVE_FIELDS)
    if (!isNonEmptyString(body.member_did)) return shapeProblem('body.member_did MUST be a non-empty string')
    optionalText(body, 'reason_text')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateLeaveBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, LEAVE_FIELDS)
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateUpdateProfileBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, UPDATE_PROFILE_FIELDS)
    // §8.7.2 L780：patch 用 RFC 7386 语义，所以它必须是个 JSON 对象。§7.4 的字段全是
    // MAY，合并之后没有可违反的结构——这一族只查到"是个对象"为止。
    requiredObject(body, 'group_profile_patch')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

export function validateUpdatePolicyBody(body: Record<string, unknown>): AnpRejection | undefined {
  try {
    rejectUnknown(body, UPDATE_POLICY_FIELDS)
    requiredObject(body, 'group_policy_patch')
    return undefined
  } catch (err) {
    return caught(err)
  }
}

/**
 * `group.send`（§8.9.3 L856–862）。
 *
 * 与上面七个不同的**只有一点**：这里不查未知字段。正文就是应用层负载，§8.9.3 的四个字段
 * 是"可包含"而不是"仅包含"，P3 §6.2.6 L274 还允许发送方自定义内容类型，那类消息的字段
 * 只有发送方自己认得。往这里加白名单，拒掉的会是规范允许的请求。
 */
export function validateSendBody(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined {
  return validatePayloadBody(body, meta.content_type ?? '')
}

function caught(err: unknown): AnpRejection | undefined {
  if (err instanceof AnpRefusal) return err.rejection
  throw err
}

// ---- 处理器 ------------------------------------------------------------------

/** `group_did` 的随机段：128 位无填充 base64url，理由见 [groups.md](../docs/design/groups.md) §2。 */
function newGroupId(): string {
  return randomBytes(16).toString('base64url')
}

function createGroup(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const target = targetOf(ctx.meta)
  // §8.1.2 L626：`meta.target.did` MUST 等于目标 `ANPMessageService.serviceDid`。这条不是
  // 目标建模（那个查的是 `kind`），所以由处理器判，错的是目标绑定而不只是参数形状。
  if (target !== ctx.serviceDid) {
    throw refusal(anpRejection('anp.invalid_target_binding', `group.create MUST target ${ctx.serviceDid}`))
  }
  const policy = requiredObject(ctx.body, 'group_policy')
  const profile = profileDefaults(optionalObject(ctx.body, 'group_profile') ?? {})
  const members = initialMembersOf(ctx.body)

  const groupDid = `${ctx.serviceDid}:g:${newGroupId()}`
  // §6.2 L237 与 §6.2 L244 的初值：创建自己占掉 1/1。`initial_members` 是**这一次**状态
  // 变更的一部分，不另开版本号——见 [groups.md](../docs/design/groups.md) §7 里这条取舍。
  ctx.storage.insertGroup({
    groupDid,
    hostServiceDid: ctx.serviceDid,
    groupStateVersion: 1,
    groupEventSeq: 1,
    groupProfileJson: JSON.stringify(profile),
    groupPolicyJson: JSON.stringify(policy),
    createdAt: ctx.acceptedAt,
    creatorDid: actor,
  })
  ctx.storage.upsertGroupMember({
    groupDid,
    memberDid: actor,
    role: 'owner',
    membershipStatus: 'active',
    stateVersion: 1,
    joinedAt: ctx.acceptedAt,
  })
  for (const member of members) {
    if (member.memberDid === actor) continue
    ctx.storage.upsertGroupMember({
      groupDid,
      memberDid: member.memberDid,
      role: member.role,
      membershipStatus: 'active',
      stateVersion: 1,
      joinedAt: ctx.acceptedAt,
      addedBy: actor,
    })
  }

  return {
    group_did: groupDid,
    group_state_version: '1',
    group_event_seq: '1',
    created_at: ctx.acceptedAt,
    creator_did: actor,
    group_profile: profile,
    group_policy: policy,
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid,
      stateVersion: 1,
      eventSeq: 1,
      subjectMethod: GROUP_CREATE,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function getGroupInfo(ctx: GroupContext): Record<string, unknown> {
  const groupDid = targetOf(ctx.meta)
  const view = loadGroup(ctx.storage, groupDid)
  const actor = ctx.meta.sender_did
  const viewer = actor === undefined ? undefined : ctx.storage.groupMember(groupDid, actor)
  const isMember = viewer !== undefined && viewer.membershipStatus === 'active'

  // §8.2.2 L658–659：`private` 的群**MUST** 要求身份。匿名省的是身份，不是定址——
  // `meta.target` 仍然必填，`kind` 仍然是 `group`。
  if (!isMember && view.profile.discoverability === 'private') {
    throw refusal(
      groupError('notMember', `group ${groupDid} is private; group.get_info requires an active member`),
    )
  }

  const includePolicy = ctx.body.include_policy === true
  const includeMemberList = ctx.body.include_member_list === true
  // §8.2.2 L660：请求的投影超出可见范围 **MUST** 回 `group.policy_violation`。可见范围就是
  // "当前是 `active` 成员"，非成员与匿名者只拿资料快照（§13.3 L1189–1190 要的就是这个）。
  if ((includePolicy || includeMemberList) && !isMember) {
    throw refusal(
      groupError('policyViolation', `${groupDid} only discloses its policy and member list to active members`),
    )
  }

  const result: Record<string, unknown> = {
    group_did: groupDid,
    group_state_version: String(view.stateVersion),
    group_profile: view.profile,
  }
  if (isMember) {
    // §8.2.3 L674：十进制字符串，数的是 `active` DID。
    result.member_count = String(ctx.storage.countActiveMembers(groupDid))
    if (includePolicy) result.group_policy = view.policy
    if (includeMemberList) {
      result.member_list = ctx.storage
        .groupMembers(groupDid)
        // §8.2.3 L676：`member_list` SHOULD 只含当前 `active` 成员。
        .filter((member) => member.membershipStatus === 'active')
        .map(memberObject)
    }
  }
  return result
}

/**
 * §7.2 L373–392 的 `group_member`。
 *
 * 字段名与响应里那几处**不一样**，这是照抄规范而不是笔误：成员对象用 `agent_did` /
 * `status`，而 `group.join` / `group.add` 的响应用 `member_did`（§8.3.3 L694、§8.4.3
 * L711）、`group.leave` 用 `leaver_did`（§8.6.4 L763）。身份就是这一处那个 `agent_did`。
 */
function memberObject(member: {
  memberDid: string
  role: string
  membershipStatus: string
  joinedAt?: string
  addedBy?: string
}): Record<string, unknown> {
  return {
    agent_did: member.memberDid,
    role: member.role,
    status: member.membershipStatus,
    ...(member.joinedAt !== undefined ? { joined_at: member.joinedAt } : {}),
    ...(member.addedBy !== undefined ? { added_by: member.addedBy } : {}),
  }
}

/** `group.join` / `group.add` 共用的那一步：把一行成员关系变成 `active`。 */
function activate(
  ctx: GroupContext,
  view: GroupView,
  memberDid: string,
  role: Role,
  addedBy: string | undefined,
  stateVersion: number,
): void {
  ctx.storage.upsertGroupMember({
    groupDid: view.groupDid,
    memberDid,
    role,
    membershipStatus: 'active',
    stateVersion,
    joinedAt: ctx.acceptedAt,
    ...(addedBy !== undefined ? { addedBy } : {}),
  })
}

function joinGroup(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  // §8.3.2 L681：成员 DID 精确等于 `meta.sender_did`——没有 `body.member_did` 这条路。
  const existing = ctx.storage.groupMember(view.groupDid, actor)
  if (existing !== undefined && existing.membershipStatus === 'active') {
    throw refusal(groupError('alreadyMember', `${actor} is already an active member of ${view.groupDid}`))
  }
  // §8.3.2 L686：不在 `open-join` 且没有更新既有成员关系时 MUST 拒绝，SHOULD 回 3003。
  // 走到这里"既有成员关系"要么不存在、要么是 `left` / `removed`，所以只看 `admission_mode`。
  if (view.policy.admission_mode !== 'open-join') {
    throw refusal(groupError('policyViolation', `${view.groupDid} does not allow open-join`))
  }
  if (!withinMemberLimit(view.policy, ctx.storage.countActiveMembers(view.groupDid), 1)) {
    throw refusal(groupError('policyViolation', `${view.groupDid} is at its max_members limit`))
  }

  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  activate(ctx, view, actor, roleOf(existing?.role, 'role'), undefined, groupStateVersion)
  announce(ctx, {
    eventType: EVENT_MEMBER_ACTIVATED,
    subjectMethod: GROUP_JOIN,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
    subjectDid: actor,
    membershipStatus: 'active',
  })

  return {
    group_did: view.groupDid,
    member_did: actor,
    membership_status: 'active',
    group_state_version: String(groupStateVersion),
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_JOIN,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function addMember(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)
  requirePermission(view.policy, self.role, 'add')

  const memberDid = ctx.body.member_did
  if (!isNonEmptyString(memberDid)) throw refusal(shapeProblem('body.member_did MUST be a non-empty string'))
  const role = roleOf(ctx.body.role, 'body.role')
  const existing = ctx.storage.groupMember(view.groupDid, memberDid)
  // §12 L1156：3001 说的是"目标**已经**是群成员"。曾经是成员不是现在是成员——`left` /
  // `removed` 走重新激活那条路，`joined_at` / `added_by` 覆盖成这一次的。
  if (existing !== undefined && existing.membershipStatus === 'active') {
    throw refusal(groupError('alreadyMember', `${memberDid} is already an active member of ${view.groupDid}`))
  }
  if (!withinMemberLimit(view.policy, ctx.storage.countActiveMembers(view.groupDid), 1)) {
    throw refusal(groupError('policyViolation', `${view.groupDid} is at its max_members limit`))
  }

  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  activate(ctx, view, memberDid, role, actor, groupStateVersion)
  announce(ctx, {
    eventType: EVENT_MEMBER_ACTIVATED,
    subjectMethod: GROUP_ADD,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
    subjectDid: memberDid,
    membershipStatus: 'active',
  })

  return {
    group_did: view.groupDid,
    member_did: memberDid,
    membership_status: 'active',
    group_state_version: String(groupStateVersion),
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_ADD,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function removeMember(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)
  requirePermission(view.policy, self.role, 'remove')

  const memberDid = ctx.body.member_did
  if (!isNonEmptyString(memberDid)) throw refusal(shapeProblem('body.member_did MUST be a non-empty string'))
  const target = ctx.storage.groupMember(view.groupDid, memberDid)
  // §8.5.3 L725：目标不是 `active`（含不存在）**MUST** 拒绝，但规范没给码。用 3005 而不是
  // 3000：3000 的定义是"**调用方**不是该群成员"，而这里调用方是成员，冲突的是目标的成员状态。
  if (target === undefined || target.membershipStatus !== 'active') {
    throw refusal(groupError('memberConflict', `${memberDid} is not an active member of ${view.groupDid}`))
  }

  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  ctx.storage.upsertGroupMember({
    groupDid: view.groupDid,
    memberDid,
    role: target.role,
    membershipStatus: 'removed',
    stateVersion: groupStateVersion,
    ...(target.joinedAt !== undefined ? { joinedAt: target.joinedAt } : {}),
    ...(target.addedBy !== undefined ? { addedBy: target.addedBy } : {}),
  })
  announce(ctx, {
    eventType: EVENT_MEMBER_REMOVED,
    subjectMethod: GROUP_REMOVE,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
    subjectDid: memberDid,
    membershipStatus: 'removed',
  })

  return {
    group_did: view.groupDid,
    member_did: memberDid,
    membership_status: 'removed',
    group_state_version: String(groupStateVersion),
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_REMOVE,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function leaveGroup(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  // §8.6.2 L749：只要求 `meta.sender_did` 是当前成员，没有权限键——离群不需要谁的许可。
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)

  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  ctx.storage.upsertGroupMember({
    groupDid: view.groupDid,
    memberDid: actor,
    role: self.role,
    membershipStatus: 'left',
    stateVersion: groupStateVersion,
    ...(self.joinedAt !== undefined ? { joinedAt: self.joinedAt } : {}),
    ...(self.addedBy !== undefined ? { addedBy: self.addedBy } : {}),
  })
  announce(ctx, {
    eventType: EVENT_MEMBER_LEFT,
    subjectMethod: GROUP_LEAVE,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
    subjectDid: actor,
    membershipStatus: 'left',
  })

  return {
    group_did: view.groupDid,
    leaver_did: actor,
    group_state_version: String(groupStateVersion),
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_LEAVE,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function updateProfile(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)
  requirePermission(view.policy, self.role, 'update_profile')

  // 校验的是**合并之后**的对象，不是 patch 本身（[groups.md] §8）。§7.4 的字段全是 MAY，
  // 所以这里没有可违反的结构，`profileDefaults` 是唯一要补的一步。
  const merged = profileDefaults(mergePatch(view.profile, requiredObject(ctx.body, 'group_profile_patch')))
  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  ctx.storage.updateGroupProfile(view.groupDid, JSON.stringify(merged))
  announce(ctx, {
    eventType: EVENT_PROFILE_UPDATED,
    subjectMethod: GROUP_UPDATE_PROFILE,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
  })

  return {
    group_did: view.groupDid,
    group_state_version: String(groupStateVersion),
    group_profile: merged,
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_UPDATE_PROFILE,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function updatePolicy(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)
  requirePermission(view.policy, self.role, 'update_policy')

  const merged = mergePatch(view.policy, requiredObject(ctx.body, 'group_policy_patch'))
  // 一个 patch 可以塞进第六个权限键、或把 `admission_mode` 改成任意串，而 patch 本身完全
  // 合法——所以查的是合并结果。违反的是对象定义，回 1003（`shapeProblem`）。
  const problem = policyProblem(merged)
  if (problem !== undefined) throw refusal(shapeProblem(problem))

  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, true)
  ctx.storage.updateGroupPolicy(view.groupDid, JSON.stringify(merged))
  announce(ctx, {
    eventType: EVENT_POLICY_UPDATED,
    subjectMethod: GROUP_UPDATE_POLICY,
    actorDid: actor,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
  })

  return {
    group_did: view.groupDid,
    group_state_version: String(groupStateVersion),
    group_policy: merged,
    group_receipt: groupReceipt({
      receiptType: RECEIPT_OPERATION,
      groupDid: view.groupDid,
      stateVersion: groupStateVersion,
      eventSeq: groupEventSeq,
      subjectMethod: GROUP_UPDATE_POLICY,
      operationId: operationIdOf(ctx.meta),
      actorDid: actor,
      acceptedAt: ctx.acceptedAt,
      payloadDigest: ctx.requestDigest,
    }),
  }
}

function sendToGroup(ctx: GroupContext): Record<string, unknown> {
  const actor = actorOf(ctx.meta)
  const view = loadGroup(ctx.storage, targetOf(ctx.meta))
  const self = requireActiveMember(ctx.storage, view.groupDid, actor)
  requirePermission(view.policy, self.role, 'send')

  const messageId = ctx.meta.message_id
  if (messageId === undefined || messageId === '') {
    throw new ConnectxError('message_invalid', 'group.send requires meta.message_id')
  }
  const operationId = operationIdOf(ctx.meta)

  // §10.3 L1046–1052 的消息级重复识别，正对着 `messages` 的三元组主键
  // `(sender_did, group_did, message_id)`——与 `direct.send` 同一套。走到这里说明操作级
  // 未命中（C4 的 `perform` 只在未命中时被调用），所以这是"另一个 `operation_id` 指着一条
  // 已收下的消息"。回它当初那一份，不再存第二行、不再排第二条投递。
  const existing = ctx.storage.message(actor, view.groupDid, messageId)
  if (existing !== undefined) {
    // §8.9.4 L868–875 要的 `group_event_seq` / `group_state_version` 就在这里用上：规范说
    // 后者是"该消息被接受时所属的群状态快照"（§6.2 L239），不是现在这一刻的。
    return {
      accepted: true,
      group_did: view.groupDid,
      message_id: existing.messageId,
      operation_id: operationId,
      group_event_seq: String(existing.groupEventSeq ?? 0),
      group_state_version: String(existing.groupStateVersion ?? view.stateVersion),
      accepted_at: existing.acceptedAt,
    }
  }

  // §10.2 L1031–1032：群消息**推进** `group_event_seq`、**不动** `group_state_version`。
  const { groupStateVersion, groupEventSeq } = ctx.storage.advanceGroupCounters(view.groupDid, false)

  ctx.storage.insertMessage({
    messageId,
    senderDid: actor,
    targetDid: view.groupDid,
    profile: ctx.meta.profile,
    securityProfile: ctx.meta.security_profile,
    contentType: ctx.meta.content_type ?? '',
    bodyJson: JSON.stringify(ctx.body),
    acceptedAt: ctx.acceptedAt,
    groupEventSeq,
    groupStateVersion,
  })

  // §9.2 L656：`group.send` 由 Group Host 接受后，**为每个附件创建一条 Access Grant**，
  // 而 Group Host 就是本服务。与消息行、群事件在同一个事务里——这就是 C9 与 C10 的接口线。
  // 上面那条重复消息的分支同样不做：Grant 在第一次受理时已经落了。
  insertAttachmentGrants(
    ctx.storage,
    attachmentGrantsFor({
      contentType: ctx.meta.content_type ?? '',
      securityProfile: ctx.meta.security_profile,
      body: ctx.body,
      messageId,
      groupDid: view.groupDid,
      createdAt: ctx.acceptedAt,
    }),
  )

  const receipt = groupReceipt({
    receiptType: RECEIPT_MESSAGE,
    groupDid: view.groupDid,
    stateVersion: groupStateVersion,
    eventSeq: groupEventSeq,
    subjectMethod: GROUP_SEND,
    operationId,
    actorDid: actor,
    acceptedAt: ctx.acceptedAt,
    payloadDigest: ctx.requestDigest,
    messageId,
  })

  // 投递只给**其余** active 成员：发送者自己那一半由 `messages` 行在取件面补出来
  // （[message-service.md] §9.3），给他也写一行会让同一条消息在两条路上各出现一次。
  const body = {
    group_did: view.groupDid,
    group_state_version: String(groupStateVersion),
    group_event_seq: String(groupEventSeq),
    accepted_at: ctx.acceptedAt,
    group_receipt: receipt,
    ...ctx.body,
  }
  for (const recipient of activeMemberDids(ctx.storage, view.groupDid)) {
    if (recipient === actor) continue
    const meta: AnpMeta = {
      profile: GROUP_PROFILE,
      security_profile: ctx.meta.security_profile,
      // §8.10 L880：发起者是**原始发送方**，不是群自己——这与 `group.state_changed`
      // 恰好相反，是 P4 最容易写错的一行。
      sender_did: actor,
      target: { kind: 'agent', did: recipient },
      operation_id: operationId,
      message_id: messageId,
      content_type: ctx.meta.content_type ?? '',
    }
    deliver(ctx, recipient, messageId, GROUP_INCOMING, {
      meta,
      // §8.10 L905–907：`auth` 原样带走，中间服务 MUST NOT 重签——重签会把业务原发者的
      // 证明换成这个服务的，跨域链条上"谁发的"就变了。
      ...(ctx.auth !== undefined ? { auth: ctx.auth } : {}),
      body,
    })
  }

  return {
    accepted: true,
    group_did: view.groupDid,
    message_id: messageId,
    operation_id: operationId,
    group_event_seq: String(groupEventSeq),
    group_state_version: String(groupStateVersion),
    accepted_at: ctx.acceptedAt,
    group_receipt: receipt,
  }
}

/**
 * 方法名 → 处理器。
 *
 * 没有 `group.member_did_update`：§8.12 L934 说它是**保留的 Host 动作标识，不是
 * JSON-RPC 方法**，客户端调用它 MUST 收到 `-32601`。它在方法表里也没有条目，所以
 * `lookupMethod()` 根本不会把它交给这一层。
 */
export const GROUP_HANDLERS: Readonly<Record<string, GroupHandler>> = {
  [GROUP_CREATE]: createGroup,
  [GROUP_GET_INFO]: getGroupInfo,
  [GROUP_JOIN]: joinGroup,
  [GROUP_ADD]: addMember,
  [GROUP_REMOVE]: removeMember,
  [GROUP_LEAVE]: leaveGroup,
  [GROUP_UPDATE_PROFILE]: updateProfile,
  [GROUP_UPDATE_POLICY]: updatePolicy,
  [GROUP_SEND]: sendToGroup,
}
