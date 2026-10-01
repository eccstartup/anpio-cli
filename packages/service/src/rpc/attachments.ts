// C10 —— P7 附件与对象传输，Object Service 这一侧的控制面。
//
// 四条方法（`create_slot` / `commit_object` / `abort_object` / `get_download_ticket`）都是
// **service-scoped**（§10.1 L797–800）：目标是服务的 `serviceDid`，不是某个 agent 或群。
// 这个文件装"受理之后做什么"；方法表要哪些 `meta`、幂等键取什么，在 `methods.ts` 里；字节
// 怎么进出，在 `dataplane.ts` 里。
//
// 三件事在这里定形，它们是 P7 最容易写错的地方：
//
// 1. **`object_uri` 是一个不透明 id，不是摘要**。`create_slot` 的响应里必须带它
//    （§10.2.3 L884），而那一刻字节还没上传，摘要根本不存在——只有 `expected_digest`
//    （一个 MAY 字段）能提前给，而那是调用方自己说的，不是我们知道的。§14.2 的示例也把
//    两者写成了不同的值（`.../upload/slot-70001` 与 `.../objects/obj-abc`）。所以随机段
//    在创建时铸出来，磁盘上的文件名才是摘要。
// 2. **字节的完整性主张与授权是两件事**。`commit_object` 成功 **不等于** 谁能下载
//    （§10.3.2 L930）：授权在承载清单的消息被受理之后才由 Grant 长出（§9.2 L652–656），
//    而 Grant 由 `direct.ts` / `groups.ts` 在**它们的**事务里落库——那个公共入口是本文
//    末尾的 `attachmentGrantsFor()`。
// 3. **票据签发的校验是七条**（§9.6 L710–718），其中第 7 条是对**当前**群状态的实时
//    判定，不是消息时刻的快照（§9.8 L734）。
//
// 所有"查库才能判"的拒绝都抛 `AnpRefusal`（`refusal.ts` 有完整说明）：它们必须落在
// `acceptOperation` 的事务**里面**，否则一次早已受理的重试会被重新判一遍。

import { createHash, randomBytes } from 'node:crypto'
import {
  anpRejection,
  ConnectxError,
  profileRejection,
  type AnpMeta,
  type AnpRejection,
} from '@agentx/core'
import type { ObjectStore } from '../objects'
import type { Storage, StoredAttachmentGrant } from '../storage/types'
import { refusal } from './refusal'

export const ATTACHMENT_PROFILE = 'anp.attachment.v1'
/** §10.1 L783–784：这一段方法的默认安全模式只有这一个。 */
export const ATTACHMENT_SECURITY_PROFILE = 'transport-protected'

/** §6.1 L349 / §6.2 L360：承载清单的消息用这个内容类型。 */
export const ATTACHMENT_MANIFEST_CONTENT_TYPE = 'application/anp-attachment-manifest+json'

export const ATTACHMENT_CREATE_SLOT = 'attachment.create_slot'
export const ATTACHMENT_COMMIT_OBJECT = 'attachment.commit_object'
export const ATTACHMENT_ABORT_OBJECT = 'attachment.abort_object'
export const ATTACHMENT_GET_DOWNLOAD_TICKET = 'attachment.get_download_ticket'

/** 数据面的两条路由。`upload_uri` / `object_uri` 由这里拼出来，路由表也读这里——
 *  两处各写一份字面量，改动时只会有一半动。 */
export const UPLOAD_PATH = '/anp-im/upload'
export const OBJECTS_PATH = '/anp-im/objects'

/**
 * 上传槽的存活时间。**规范没有给这个数**（§9.5 L696 只给了票据的 5 分钟），所以这是本
 * 服务的选择：15 分钟够一个几 MiB 的对象在慢链路上传完，又不至于让一个永不提交的槽
 * 长期占着 `object_uri`。
 */
export const SLOT_TTL_MS = 15 * 60 * 1000

/** §9.5 L696：下载票据的默认有效期 **SHOULD NOT** 超过 5 分钟。 */
export const TICKET_TTL_MS = 5 * 60 * 1000

const ENCRYPTION_MODES = ['none', 'object-e2ee'] as const
const MESSAGE_SECURITY_PROFILES = ['transport-protected', 'direct-e2ee', 'group-e2ee'] as const

// ---- 错误码 ------------------------------------------------------------------

function pair(code: number, anpCode: string): { code: number; anpCode: string } {
  return { code, anpCode }
}

/**
 * §12 L1084–1100 里**本服务会发**的那几个。走 `profileRejection` 而不是 `anpRejection`：
 * 这一段不在 P1 的公共表里，码值也不在 1000–1021 之间。
 *
 * 没在这里的两个都没有产生路径，留一个发不出去的码比造个场景去用它诚实：
 * - 6004 `unsupported_mime_type`：v1 不设 MIME 白名单（attachments.md §10）。
 * - 6011 `decrypt_failed`：`object-e2ee` 的对象在本服务眼里就是字节，解密是客户端的
 *   义务（§8.5 L602–622）。
 *
 * 6007 `download_ticket_invalid` **只有数据面发**（不认识的令牌、已被作废的令牌），控制面
 * 这一侧没有它的位置——`get_download_ticket` 是**签发**，此时还没有令牌可判。
 */
const ATTACHMENT_ERRORS = {
  slotNotFound: pair(6000, 'anp.attachment.slot_not_found'),
  slotExpired: pair(6001, 'anp.attachment.slot_expired'),
  commitTokenInvalid: pair(6002, 'anp.attachment.commit_token_invalid'),
  objectTooLarge: pair(6003, 'anp.attachment.object_too_large'),
  grantNotFound: pair(6005, 'anp.attachment.grant_not_found'),
  unauthorizedRequester: pair(6006, 'anp.attachment.unauthorized_requester'),
  downloadTicketInvalid: pair(6007, 'anp.attachment.download_ticket_invalid'),
  ticketBindingMismatch: pair(6008, 'anp.attachment.ticket_binding_mismatch'),
  ticketExpired: pair(6009, 'anp.attachment.ticket_expired'),
  digestMismatch: pair(6010, 'anp.attachment.digest_mismatch'),
  objectUnavailable: pair(6012, 'anp.attachment.object_unavailable'),
  encryptionPolicyViolation: pair(6013, 'anp.attachment.encryption_policy_violation'),
} as const

export type AttachmentErrorName = keyof typeof ATTACHMENT_ERRORS

/** 数据面也要发这一族码（6000/6001/6003/6007/6008/6009/6012），所以它是导出的。 */
export function attachmentError(
  name: AttachmentErrorName,
  message: string,
  details?: Record<string, unknown>,
): AnpRejection {
  const codes = ATTACHMENT_ERRORS[name]
  return profileRejection(codes.code, codes.anpCode, message, details !== undefined ? { details } : {})
}

/** 形状问题一律 §10.3 L704 的 1003：错的是参数，不是权限、不是对象状态。 */
function shapeProblem(message: string): AnpRejection {
  return anpRejection('anp.invalid_params_shape', message)
}

// ---- 请求上下文 --------------------------------------------------------------

export interface AttachmentContext {
  storage: Storage
  /** 本服务的 `serviceDid`：四条方法的 `meta.target.did` 都必须等于它（§10.1 L798）。 */
  serviceDid: string
  /** `upload_uri` / `object_uri` 挂在这个基址下面。 */
  publicUrl: string
  /** 对象字节。`commit_object` 要搬文件、`abort_object` 要丢暂存，都在事务里做——
   *  那是本地 `rename` / `unlink`，不是网络往返（`attachments.md` §4）。 */
  objects: ObjectStore
  meta: AnpMeta
  body: Record<string, unknown>
  /** RFC 3339。由调用方给（一次请求一个时刻），测试才好钉住它。 */
  acceptedAt: string
}

export type AttachmentHandler = (ctx: AttachmentContext) => Record<string, unknown>

// ---- 铸标识符 ----------------------------------------------------------------

/** 一段 128 位无填充 base64url。`slot_id` 与 `object_uri` 的随机段用它：22 个字符，撞不上，
 *  且不含路径分隔符。 */
function newId(): string {
  return randomBytes(16).toString('base64url')
}

/** 上传令牌与提交令牌：256 位。上传令牌是 `upload_uri` 里那一整段凭据（数据面的 PUT 没有
 *  `origin_proof` 可依），提交令牌是 `commit_object` 唯一的凭据，两者都按不可猜来设计。 */
function newToken(): string {
  return randomBytes(32).toString('base64url')
}

/** 票据存的是这个，不是令牌本身：它是一张 bearer 凭据，台账里不该有明文。 */
export function sha256b64u(value: string): string {
  return createHash('sha256').update(value).digest('base64url')
}

export function uploadUriFor(publicUrl: string, uploadToken: string): string {
  return `${publicUrl}${UPLOAD_PATH}/${uploadToken}`
}

/**
 * `object_uri` 由基址与一个不透明的对象 id 拼成。见本文件开头第 1 条：它不是摘要，也
 * **不要求**是摘要。
 *
 * 这个函数同时被 `create_slot`（铸出来）与数据面（拿路径段还原出同一个字符串去查槽位）
 * 调用，所以"`object_uri` 长什么样"只有一处定义。
 */
export function objectUriFor(publicUrl: string, objectId: string): string {
  return `${publicUrl}${OBJECTS_PATH}/${objectId}`
}

/** §10.1 L798：`meta.target.did` **MUST** 等于本服务的公开 `serviceDid`。
 *
 *  这一条**不**在 `targetBindingHolds` 里——那里只判 `target.kind`（`methods.ts` L426）。
 * 所以每个 service-scoped 方法的处理器自己判，与 `group.create` 对 `serviceDid` 的做法
 * 一致（`groups.ts` 的 `createGroup`）。错的是目标绑定，不只是参数形状。 */
function requireServiceTarget(ctx: AttachmentContext): void {
  if (ctx.meta.target?.did !== ctx.serviceDid) {
    throw refusal(anpRejection('anp.invalid_target_binding', `attachment methods MUST target ${ctx.serviceDid}`))
  }
}

function actorOf(meta: AnpMeta): string {
  const did = meta.sender_did
  // 方法表把 `sender_did` 标成必填，走到这里必然在。抛而不是兜空串：空串会算出一个谁也
  // 不会再命中的身份，那比当场炸掉更坏。
  if (did === undefined || did === '') {
    throw new ConnectxError('message_invalid', 'attachment methods require meta.sender_did')
  }
  return did
}

function expiresAt(from: string, ttlMs: number): string {
  return new Date(Date.parse(from) + ttlMs).toISOString()
}

/** 过期是用到这一行时对 `expires_at` 的一次判定，不是行上的状态（attachments.md §8）。 */
function isExpired(at: string, now: string): boolean {
  return Date.parse(at) <= Date.parse(now)
}

// ---- body 校验 ---------------------------------------------------------------

/**
 * 四条方法的正文字段集是**闭的**，所以照群方法那样查未知字段。
 *
 * `commit_object` 是规范自己把这条说死的那一个：§10.3.2 的规则 3、4 明写
 * **MUST NOT** 传输 `object_key_b64u` 与 `nonce_b64u`——一条 MUST NOT 只有在字段集封闭时
 * 才有内容，"不认识就忽略"会让它变成一句空话。另外三条跟着一起做，是为了这一族有一致的
 * 边界；它们的字段表同样是 MUST / SHOULD / MAY 三档列尽的。
 */
function rejectUnknown(body: Record<string, unknown>, allowed: readonly string[]): void {
  const extra = Object.keys(body).filter((key) => !allowed.includes(key))
  if (extra.length > 0) throw refusal(shapeProblem(`unknown body field(s): ${extra.join(', ')}`))
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** 十进制字符串（§10.2.2 L861 给 `expected_size` 定的形状）。返回数值，形状不对时
 *  `undefined`。 */
function decimalSize(value: unknown): number | undefined {
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return undefined
  const size = Number(value)
  return Number.isSafeInteger(size) ? size : undefined
}

function requireText(body: Record<string, unknown>, field: string): string {
  const value = body[field]
  if (typeof value !== 'string' || value === '') {
    throw refusal(shapeProblem(`body.${field} MUST be a non-empty string`))
  }
  return value
}

/** §7.4 L466–474：`{alg, value_b64u}`，`alg` 在 v1 固定为 `sha-256`。 */
function digestOf(value: unknown, field: string): { alg: string; value_b64u: string } {
  if (!isPlainObject(value)) throw refusal(shapeProblem(`body.${field} MUST be an object`))
  if (value.alg !== 'sha-256') {
    throw refusal(shapeProblem(`body.${field}.alg MUST be sha-256 in v1`))
  }
  if (typeof value.value_b64u !== 'string' || value.value_b64u === '') {
    throw refusal(shapeProblem(`body.${field}.value_b64u MUST be a non-empty string`))
  }
  return { alg: 'sha-256', value_b64u: value.value_b64u }
}

const CREATE_SLOT_FIELDS = [
  'attachment_id',
  'intended_message_security_profile',
  'object_encryption_mode',
  'expected_size',
  'mime_type',
  'filename',
  'expected_digest',
  'intended_target',
] as const

/** §10.2.2 L836–877。 */
export function validateCreateSlotBody(body: Record<string, unknown>): AnpRejection | undefined {
  rejectUnknown(body, CREATE_SLOT_FIELDS)
  requireText(body, 'attachment_id')

  const profile = body.intended_message_security_profile
  if (typeof profile !== 'string' || !(MESSAGE_SECURITY_PROFILES as readonly string[]).includes(profile)) {
    return shapeProblem(
      `body.intended_message_security_profile MUST be one of ${MESSAGE_SECURITY_PROFILES.join(', ')}`,
    )
  }
  const mode = body.object_encryption_mode
  if (typeof mode !== 'string' || !(ENCRYPTION_MODES as readonly string[]).includes(mode)) {
    return shapeProblem(`body.object_encryption_mode MUST be one of ${ENCRYPTION_MODES.join(', ')}`)
  }

  // §10.2.2 L875 约束 1，也就是 §3.4 L140 那句"明文承载下对象也必须明文"的落点。回 6013
  // 而不是 1003：§12 L1100 给 6013 的定义正是"对象加密模式与消息安全模式组合不合法"。
  if (profile === 'transport-protected' && mode !== 'none') {
    return attachmentError(
      'encryptionPolicyViolation',
      'a transport-protected message MUST carry a plaintext object (object_encryption_mode = none)',
    )
  }

  if (body.expected_size !== undefined && decimalSize(body.expected_size) === undefined) {
    return shapeProblem('body.expected_size MUST be a decimal string')
  }
  if (body.expected_digest !== undefined) {
    const bad = checkIgnoringShape(() => digestOf(body.expected_digest, 'expected_digest'))
    if (bad !== undefined) return bad
  }
  for (const field of ['mime_type', 'filename'] as const) {
    if (body[field] !== undefined && typeof body[field] !== 'string') {
      return shapeProblem(`body.${field} MUST be a string`)
    }
  }
  if (body.intended_target !== undefined) {
    const target = body.intended_target
    if (!isPlainObject(target)) return shapeProblem('body.intended_target MUST be an object')
    if (target.kind !== 'agent' && target.kind !== 'group') {
      return shapeProblem('body.intended_target.kind MUST be agent or group')
    }
    if (typeof target.did !== 'string' || target.did === '') {
      return shapeProblem('body.intended_target.did MUST be a non-empty string')
    }
  }
  return undefined
}

const COMMIT_FIELDS = [
  'attachment_id',
  'slot_id',
  'commit_token',
  'size',
  'digest',
  'object_encryption_mode',
  'plaintext_size',
  'media_info',
] as const

/** §10.3.2 L905–930。 */
export function validateCommitBody(body: Record<string, unknown>): AnpRejection | undefined {
  rejectUnknown(body, COMMIT_FIELDS)
  requireText(body, 'attachment_id')
  requireText(body, 'slot_id')
  requireText(body, 'commit_token')

  if (decimalSize(body.size) === undefined) return shapeProblem('body.size MUST be a decimal string')
  const bad = checkIgnoringShape(() => digestOf(body.digest, 'digest'))
  if (bad !== undefined) return bad

  const mode = body.object_encryption_mode
  if (typeof mode !== 'string' || !(ENCRYPTION_MODES as readonly string[]).includes(mode)) {
    return shapeProblem(`body.object_encryption_mode MUST be one of ${ENCRYPTION_MODES.join(', ')}`)
  }

  // §10.3.2 L926 规则 2：密文模式必须报出明文长度，否则接收方无法在解密后校验（§11.3）。
  if (mode === 'object-e2ee' && decimalSize(body.plaintext_size) === undefined) {
    return shapeProblem('body.plaintext_size MUST exist and be a decimal string when object_encryption_mode is object-e2ee')
  }
  if (body.plaintext_size !== undefined && decimalSize(body.plaintext_size) === undefined) {
    return shapeProblem('body.plaintext_size MUST be a decimal string')
  }
  if (body.media_info !== undefined && !isPlainObject(body.media_info)) {
    return shapeProblem('body.media_info MUST be an object')
  }
  return undefined
}

const ABORT_FIELDS = ['attachment_id', 'slot_id'] as const

/** §10.4.2 L953–960。正文只有两个字段，两个都必须有。 */
export function validateAbortBody(body: Record<string, unknown>): AnpRejection | undefined {
  rejectUnknown(body, ABORT_FIELDS)
  requireText(body, 'attachment_id')
  requireText(body, 'slot_id')
  return undefined
}

const TICKET_FIELDS = [
  'attachment_id',
  'object_uri',
  'requester_did',
  'message_security_profile',
  'message_id',
  'message_target_did',
  'group_did',
  'one_time',
] as const

/** §10.5.2 L983–1011。 */
export function validateTicketBody(body: Record<string, unknown>, meta: AnpMeta): AnpRejection | undefined {
  rejectUnknown(body, TICKET_FIELDS)
  requireText(body, 'attachment_id')
  requireText(body, 'object_uri')
  requireText(body, 'message_security_profile')
  requireText(body, 'message_id')
  const requesterDid = requireText(body, 'requester_did')

  // §10.5.2 L1008：`requester_did` **MUST** 等于 `meta.sender_did`。这一条是正文与 `meta`
  // 的关系，所以只能在这一层判（`validateBody` 拿得到两者，见 `MethodSpec`）。
  if (requesterDid !== meta.sender_did) {
    return shapeProblem('body.requester_did MUST equal meta.sender_did')
  }

  // 上下文"补充其一"：两个都缺就没有上下文可判，两个都给则不知按哪一个判（§9.6 第 6、7
  // 条是两条不同的路径）。两种都拒。
  const hasDirect = body.message_target_did !== undefined
  const hasGroup = body.group_did !== undefined
  if (hasDirect === hasGroup) {
    return shapeProblem('body MUST carry exactly one of message_target_did (direct) or group_did (group)')
  }
  for (const field of ['message_target_did', 'group_did'] as const) {
    if (body[field] !== undefined && (typeof body[field] !== 'string' || body[field] === '')) {
      return shapeProblem(`body.${field} MUST be a non-empty string`)
    }
  }
  if (body.one_time !== undefined && typeof body.one_time !== 'boolean') {
    return shapeProblem('body.one_time MUST be a boolean')
  }
  return undefined
}

/** 把一个"抛拒绝"的小过程收成"返回拒绝"，好让校验函数保持"返回 `AnpRejection | undefined`"
 *  这一个形状。只有本文件里那几个 `require*` 小工具会抛。 */
function checkIgnoringShape(run: () => void): AnpRejection | undefined {
  try {
    run()
    return undefined
  } catch (err) {
    if (err instanceof Error && 'rejection' in err) return (err as { rejection: AnpRejection }).rejection
    throw err
  }
}

// ---- 处理器 ------------------------------------------------------------------

function createSlot(ctx: AttachmentContext): Record<string, unknown> {
  requireServiceTarget(ctx)
  const ownerDid = actorOf(ctx.meta)
  const attachmentId = requireText(ctx.body, 'attachment_id')

  const slotId = newId()
  const uploadToken = newToken()
  const objectId = newId()

  ctx.storage.insertAttachmentSlot({
    attachmentId,
    slotId,
    ownerDid,
    uploadToken,
    commitToken: newToken(),
    objectEncryptionMode: String(ctx.body.object_encryption_mode),
    messageSecurityProfile: String(ctx.body.intended_message_security_profile),
    state: 'pending',
    expiresAt: expiresAt(ctx.acceptedAt, SLOT_TTL_MS),
    objectUri: objectUriFor(ctx.publicUrl, objectId),
  })

  return {
    attachment_id: attachmentId,
    slot_id: slotId,
    upload_uri: uploadUriFor(ctx.publicUrl, uploadToken),
    object_uri: objectUriFor(ctx.publicUrl, objectId),
    commit_token: ctx.storage.attachmentSlot(attachmentId, slotId)?.commitToken ?? '',
    expires_at: expiresAt(ctx.acceptedAt, SLOT_TTL_MS),
    // §10.2.3 L892 的 MAY。上传路由不查这个头，它只是把"该怎么发"写清楚——省得每个客户端
    // 自己猜一个。
    upload_headers: { 'content-type': 'application/octet-stream' },
  }
}

function commitObject(ctx: AttachmentContext): Record<string, unknown> {
  requireServiceTarget(ctx)
  const attachmentId = requireText(ctx.body, 'attachment_id')
  const slotId = requireText(ctx.body, 'slot_id')
  const commitToken = requireText(ctx.body, 'commit_token')

  const slot = ctx.storage.attachmentSlot(attachmentId, slotId)
  if (slot === undefined) throw refusal(attachmentError('slotNotFound', `no upload slot ${attachmentId}/${slotId}`))
  if (isExpired(slot.expiresAt, ctx.acceptedAt)) {
    throw refusal(attachmentError('slotExpired', `slot ${slotId} expired at ${slot.expiresAt}`))
  }
  // §10.1 L808–824 那张状态机里 Aborted 是终态：一个被废弃的槽不再"可用"，所以回 6000
  // （§12 L1084 的原话就是"未找到**可用** Upload Slot"），而不是给它一个更细的码。
  if (slot.state === 'aborted') {
    throw refusal(attachmentError('slotNotFound', `slot ${slotId} was aborted`))
  }
  // 令牌先于状态判：它是这次调用的凭据，一个令牌不对的请求不该从状态下猜出任何东西。
  if (slot.commitToken !== commitToken) {
    throw refusal(
      attachmentError('commitTokenInvalid', 'commit_token does not match the slot'),
      // §12 L1100 末段那句话也适用于这里：6013 的语义是"与当前对象上下文不匹配"的一种。
    )
  }
  if (slot.objectEncryptionMode !== ctx.body.object_encryption_mode) {
    throw refusal(
      attachmentError(
        'encryptionPolicyViolation',
        `slot was created for object_encryption_mode ${slot.objectEncryptionMode}`,
      ),
    )
  }

  // 同一个槽的第二次提交：§10.1 的状态机里 Committed 同样是终态，没有回边的箭头。幂等台账
  // 只认得同一次 `operation_id`，所以另一个 `operation_id` 指着同一个已提交的槽会走到这里
  // ——报回当初那份，与 `direct.send` 的重复消息识别同一个策略。
  if (slot.state === 'committed') {
    return {
      committed: true,
      attachment_id: attachmentId,
      ...(slot.objectUri !== undefined ? { object_uri: slot.objectUri } : {}),
      ...(slot.committedAt !== undefined ? { committed_at: slot.committedAt } : {}),
    }
  }
  // `pending` 意味着 PUT 一次都没完成。§12 L1099 给 6012 的定义正是"对象未完成提交"。
  if (slot.state !== 'uploaded' || slot.digest === undefined || slot.size === undefined) {
    throw refusal(attachmentError('objectUnavailable', `slot ${slotId} has no completed upload`))
  }

  const declaredSize = decimalSize(ctx.body.size)
  const declared = digestOf(ctx.body.digest, 'digest')
  // §12 L1098 的 6010 是"上传或下载后的对象摘要与期望摘要不一致"。长度对不上时没有任何更
  // 贴切的码——规范不为长度单配一个——而"你声明的和实际收到的不是同一个"正是同一个意思。
  if (declaredSize !== slot.size) {
    throw refusal(
      attachmentError('digestMismatch', `uploaded ${slot.size} bytes, commit declares ${String(ctx.body.size)}`),
    )
  }
  if (declared.value_b64u !== slot.digest) {
    throw refusal(attachmentError('digestMismatch', 'digest does not match the uploaded bytes'))
  }

  // 落库与搬文件都在事务里。搬是本地 `rename`（原子），不是网络往返，所以不会让并发受理在
  // 锁上等；顺序上先写索引再搬，搬成功而事务回滚只会留下一个没有行指向的文件——它按摘要
  // 命名、永远不可达，重试时 `commit` 会因为目标已存在而直接成功。
  ctx.storage.insertAttachmentObject({ digest: slot.digest, size: slot.size, committedAt: ctx.acceptedAt })
  ctx.objects.commit(slotId, slot.digest)
  ctx.storage.setAttachmentSlotState(attachmentId, slotId, 'committed', ctx.acceptedAt)

  return {
    committed: true,
    attachment_id: attachmentId,
    ...(slot.objectUri !== undefined ? { object_uri: slot.objectUri } : {}),
    committed_at: ctx.acceptedAt,
  }
}

function abortObject(ctx: AttachmentContext): Record<string, unknown> {
  requireServiceTarget(ctx)
  const attachmentId = requireText(ctx.body, 'attachment_id')
  const slotId = requireText(ctx.body, 'slot_id')

  const slot = ctx.storage.attachmentSlot(attachmentId, slotId)
  if (slot === undefined) throw refusal(attachmentError('slotNotFound', `no upload slot ${attachmentId}/${slotId}`))
  if (isExpired(slot.expiresAt, ctx.acceptedAt)) {
    throw refusal(attachmentError('slotExpired', `slot ${slotId} expired at ${slot.expiresAt}`))
  }
  if (slot.state === 'aborted') {
    return {
      aborted: true,
      attachment_id: attachmentId,
      ...(slot.committedAt !== undefined ? { aborted_at: slot.committedAt } : {}),
    }
  }
  // Committed 在状态机里是终态，没有指向 Aborted 的边：对象已经可以被消息引用，这时删掉
  // 字节等于让一条已受理的消息指向不存在的对象。
  if (slot.state === 'committed') {
    throw refusal(attachmentError('slotNotFound', `slot ${slotId} is already committed`))
  }

  // §10.4.2 L957–960 只要求两个字段，没有令牌——**照做**。槽位 id 与两个令牌一样是 128 位
  // 随机串，所以"知道这个槽"本身就是凭据；这一族方法又都要求 `origin_proof`，调用方不是
  // 匿名的。多要一个令牌会把一条规范允许的请求拒掉。
  ctx.objects.discard(slotId)
  ctx.storage.setAttachmentSlotState(attachmentId, slotId, 'aborted', ctx.acceptedAt)
  return { aborted: true, attachment_id: attachmentId, aborted_at: ctx.acceptedAt }
}

function getDownloadTicket(ctx: AttachmentContext): Record<string, unknown> {
  requireServiceTarget(ctx)
  const requesterDid = actorOf(ctx.meta)
  const attachmentId = requireText(ctx.body, 'attachment_id')
  const objectUri = requireText(ctx.body, 'object_uri')
  const messageId = requireText(ctx.body, 'message_id')
  const messageSecurityProfile = requireText(ctx.body, 'message_security_profile')

  // §9.6 L713 第 4 条：三元组对应的 Access Grant 必须存在。这里的查找键就是 §7.2 L434 要求
  // 的那三元组——`attachment_id` 单列只在一条 Attachment Message 内唯一。
  const grant = ctx.storage.attachmentGrant(messageId, attachmentId, objectUri)
  if (grant === undefined) {
    throw refusal(
      attachmentError('grantNotFound', 'no access grant for this message and attachment', {
        attachment_id: attachmentId,
        object_uri: objectUri,
        message_id: messageId,
      }),
    )
  }

  // §9.6 L714 第 5 条。
  if (grant.messageSecurityProfile !== messageSecurityProfile) {
    throw refusal(
      attachmentError('unauthorizedRequester', 'message_security_profile does not match the grant'),
    )
  }

  // §9.6 L715–716 第 6、7 条。两条互斥，由 Grant 当初绑的是哪一个决定，而不是由请求里写了
  // 哪一个决定——请求里那一个只是**主张**。
  if (grant.messageTargetDid !== undefined) {
    if (ctx.body.message_target_did !== grant.messageTargetDid) {
      throw refusal(attachmentError('unauthorizedRequester', 'message_target_did does not match the grant'))
    }
    // §9.2 L666 原话："Access Grant 授权目标 DID 或群上下文"。私聊的授权对象就是那条消息
    // 的目标 agent，所以请求者必须是它——只对得上字段而对不上人不构成授权。
    if (requesterDid !== grant.messageTargetDid) {
      throw refusal(
        attachmentError('unauthorizedRequester', `the grant authorizes ${grant.messageTargetDid}, not ${requesterDid}`),
      )
    }
  } else if (grant.groupDid !== undefined) {
    if (ctx.body.group_did !== grant.groupDid) {
      throw refusal(attachmentError('unauthorizedRequester', 'group_did does not match the grant'))
    }
    // **实时**判定，不是消息时刻的快照：§9.8 L734 说已移出的成员 SHOULD 拿不到新票，而
    // 它此前拿到过的字节不追回（L730–735）——两句要一起读。
    const member = ctx.storage.groupMember(grant.groupDid, requesterDid)
    if (member === undefined || member.membershipStatus !== 'active') {
      throw refusal(
        attachmentError('unauthorizedRequester', `${requesterDid} is not an active member of ${grant.groupDid}`),
      )
    }
  } else {
    // Grant 两侧都没绑，那是写坏了的行，不是请求的问题；但拒绝的答案是一样的。
    throw refusal(attachmentError('unauthorizedRequester', 'the grant carries no message context'))
  }

  const token = newToken()
  const expires = expiresAt(ctx.acceptedAt, TICKET_TTL_MS)
  const oneTime = ctx.body.one_time === true
  ctx.storage.insertDownloadTicket({
    tokenHash: sha256b64u(token),
    attachmentId,
    objectUri,
    requesterDid,
    messageId,
    messageSecurityProfile,
    ...(grant.messageTargetDid !== undefined ? { messageTargetDid: grant.messageTargetDid } : {}),
    ...(grant.groupDid !== undefined ? { groupDid: grant.groupDid } : {}),
    oneTime,
    issuedAt: ctx.acceptedAt,
    expiresAt: expires,
  })

  return {
    download_ticket_b64u: token,
    expires_at: expires,
    // §9.4 L691 与 §10.5.3 L1035：绑定里 **MUST NOT** 有设备 selector，所以这里逐字段列出
    // 而不是把某个更大的对象摊开。
    ticket_binding: {
      attachment_id: attachmentId,
      object_uri: objectUri,
      requester_did: requesterDid,
      message_id: messageId,
      message_security_profile: messageSecurityProfile,
      ...(grant.messageTargetDid !== undefined ? { message_target_did: grant.messageTargetDid } : {}),
      ...(grant.groupDid !== undefined ? { group_did: grant.groupDid } : {}),
    },
  }
}

export const ATTACHMENT_HANDLERS: Readonly<Record<string, AttachmentHandler>> = {
  [ATTACHMENT_CREATE_SLOT]: createSlot,
  [ATTACHMENT_COMMIT_OBJECT]: commitObject,
  [ATTACHMENT_ABORT_OBJECT]: abortObject,
  [ATTACHMENT_GET_DOWNLOAD_TICKET]: getDownloadTicket,
}

// ---- 授权链：Grant 在哪一刻长出来 --------------------------------------------

/** 一条 Attachment Message 里读出来的一项：只有建立 Grant 与做组合检查要用的三个字段。
 *  它**不是** `StoredAttachmentGrant`——那个还带着消息上下文，由 {@link attachmentGrantsFor}
 *  在读完整个清单之后补上。 */
export interface ManifestAttachment {
  attachmentId: string
  objectUri: string
  /** §7.3 的 `encryption_info.mode`。 */
  mode: string
}

/**
 * 一条 Attachment Message 里每个附件各自的 `object_uri`（§7.3 L452–459）。
 *
 * `body.payload` 由**对端**给，所以这里逐字段判：§6.1 L349–350 与 §6.2 L360–361 要求
 * `body.payload` **MUST** 是 Attachment Message，而 §7.3 的字段表是 MUST。判不过就是 1003
 * ——收下一条形状不对的清单，等于把一个我们自己都读不懂的东西当成授权依据。
 */
export function manifestAttachments(payload: unknown): ManifestAttachment[] {
  if (!isPlainObject(payload)) throw refusal(shapeProblem('body.payload MUST be an Attachment Message'))
  const attachments = payload.attachments
  // §7.1 L423：`attachments` **MUST** 存在且非空。
  if (!Array.isArray(attachments) || attachments.length === 0) {
    throw refusal(shapeProblem('body.payload.attachments MUST be a non-empty array'))
  }
  return attachments.map((entry, index) => {
    if (!isPlainObject(entry)) throw refusal(shapeProblem(`body.payload.attachments[${String(index)}] MUST be an object`))
    const attachmentId = entry.attachment_id
    if (typeof attachmentId !== 'string' || attachmentId === '') {
      throw refusal(shapeProblem(`body.payload.attachments[${String(index)}].attachment_id MUST be a non-empty string`))
    }
    const accessInfo = entry.access_info
    if (!isPlainObject(accessInfo) || typeof accessInfo.object_uri !== 'string' || accessInfo.object_uri === '') {
      throw refusal(shapeProblem(`body.payload.attachments[${String(index)}].access_info.object_uri MUST be a non-empty string`))
    }
    const encryptionInfo = entry.encryption_info
    if (!isPlainObject(encryptionInfo)) {
      throw refusal(shapeProblem(`body.payload.attachments[${String(index)}].encryption_info MUST be an object`))
    }
    const mode = encryptionInfo.mode
    if (typeof mode !== 'string' || !(ENCRYPTION_MODES as readonly string[]).includes(mode)) {
      throw refusal(
        shapeProblem(`body.payload.attachments[${String(index)}].encryption_info.mode MUST be one of ${ENCRYPTION_MODES.join(', ')}`),
      )
    }
    return { attachmentId, objectUri: accessInfo.object_uri, mode }
  })
}

export interface GrantInput {
  /** `meta.content_type`。不是清单类型就一个 Grant 都不建（§6.3 / §6.4 说那种情况下列表
   *  在密文里，本服务看不见它）。 */
  contentType: string
  /** `meta.security_profile`：写进 Grant 的那一项。 */
  securityProfile: string
  body: Record<string, unknown>
  messageId: string
  /** 私聊上下文：那条消息的目标 agent。群聊给 `groupDid`，两者互斥。 */
  targetDid?: string
  groupDid?: string
  createdAt: string
}

/**
 * 一条承载附件清单的消息被受理时，它为每个附件各自长出一条 Grant（§9.2 L656）。
 *
 * **必须在这个事务里调用**：Grant 落到事务外面就会出现"消息收下了、附件还不能下载"的中间
 * 态，而那个中间态是客户端判断不出来的——它只知道消息成功了（attachments.md §5）。
 *
 * 每个附件都建，**不管 `object_uri` 指向的是不是本服务**。§9.2 L656 的原话是"发送方侧系统
 * **MUST** 为每个附件创建一条 Access Grant"，没有"若对象在本域"。指向别处的那些 Grant 在
 * 本服务里永远换不出能用的票（下载路由按 `object_uri` 反查本地槽位，查不到就是 404），所以
 * 多建一条不会开出一个口子，少建一条却违了一条 MUST。
 */
export function attachmentGrantsFor(input: GrantInput): StoredAttachmentGrant[] {
  if (input.contentType !== ATTACHMENT_MANIFEST_CONTENT_TYPE) return []
  const entries = manifestAttachments(input.body.payload)

  return entries.map((entry) => {
    // §6.1 L352 / §6.2 L364：`transport-protected` 承载时每条 `encryption_info.mode`
    // **MUST** 为 `none`。§12 L1100 给 6013 的定义正是"对象加密模式与消息安全模式组合不
    // 合法"，所以这里回 6013 而不是 1003。
    if (input.securityProfile === 'transport-protected' && entry.mode !== 'none') {
      throw refusal(
        attachmentError(
          'encryptionPolicyViolation',
          `a transport-protected message MUST carry a plaintext object (${entry.attachmentId} declares ${entry.mode})`,
        ),
      )
    }
    return {
      messageId: input.messageId,
      attachmentId: entry.attachmentId,
      objectUri: entry.objectUri,
      messageSecurityProfile: input.securityProfile,
      ...(input.targetDid !== undefined ? { messageTargetDid: input.targetDid } : {}),
      ...(input.groupDid !== undefined ? { groupDid: input.groupDid } : {}),
      createdAt: input.createdAt,
    }
  })
}

/** 把 {@link attachmentGrantsFor} 的结果写下去。两个承载方各写一次循环，不如一个函数。 */
export function insertAttachmentGrants(storage: Storage, grants: readonly StoredAttachmentGrant[]): void {
  for (const grant of grants) storage.insertAttachmentGrant(grant)
}

/** 方法表算幂等键的第二段。四条方法各自只针对一个资源，所以"是哪一个资源"就是作用域：
 *  `create_slot` / `commit_object` / `abort_object` 是那个槽位所属的 `attachment_id`，
 *  `get_download_ticket` 是 §7.2 L434 要求的三元组——票据绑定与授权记录用的是同一个
 *  键，两者没有理由各取一套。 */
export function attachmentScope(_meta: AnpMeta, body: Record<string, unknown>): string {
  return typeof body.attachment_id === 'string' ? body.attachment_id : ''
}

export function ticketScope(_meta: AnpMeta, body: Record<string, unknown>): string {
  return `${String(body.message_id)}/${String(body.attachment_id)}/${String(body.object_uri)}`
}
