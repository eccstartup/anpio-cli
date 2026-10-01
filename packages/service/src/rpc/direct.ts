// P3 私聊：`direct.send` 的body 校验与落库。
//
// 分两层看：`validateDirectBody` 是"这条消息能不能收"，`storeDirectMessage` 是"收下之后
// 写什么"。两者都不看信封、不验签——那些是 §3 与 §5 的事，这里拿到的已经是解析过、
// 认证过的东西。
//
// 写库发生在 `acceptOperation` 的 `perform` 里，所以这里**不得**自己开事务、
// 也不得在写之前做任何可能失败的 I/O（一次网络往返会让并发写在锁里等）。

import { anpRejection, type AnpAuth, type AnpMeta, type AnpRejection } from '@agentx/core'
import type { Storage } from '../storage/types'

/** P3 §6.3 L281–285 里的三个负载字段。 */
const PAYLOAD_FIELDS = ['text', 'payload', 'payload_b64u'] as const

/** 每个字段对应的内容类型（P3 §6.2.4 L262 / §6.2.5 L268）。`payload_b64u` 是二进制或
 *  私有扩展（§6.2.6 L274），Profile 没有给它定内容类型，所以不在这张表里。 */
const CONTENT_TYPE_OF = {
  text: 'text/plain',
  payload: 'application/json',
} as const

function isUnpaddedBase64Url(value: string): boolean {
  // P3 §6.2.6 L276：无填充 base64url。`=` 出现在这里就是填充；长度模 4 余 1 是任何
  // base64 都不可能产生的形态。
  return /^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1
}

/**
 * `direct.send` 的 `body` 是否合规（P3 §6.3 L281–285）。
 *
 * 三选一的规则是 MUST-reject，且要**恰好**一个：多一个少一个都拒。§6.2.4 L262 与
 * §6.2.5 L268 再要求负载字段与 `content_type` 对上——`content_type` 说 json 却给了
 * `text`，错的是 body 不是内容类型，所以这里也用 1003。
 *
 * 回 1003（`anp.invalid_params_shape`）是**本实现的选择**：§7.1.4 L386–387 把"内容类型
 * 不被支持"与"请求体不符合互斥规则"列成两条拒绝理由，却没给后者配码，而 1003 是公共段
 * 里唯一说"params 结构不符合要求"的那个。1009 留给真正不认识的内容类型。
 */
export function validateDirectBody(body: Record<string, unknown>, contentType: string): AnpRejection | undefined {
  const present = PAYLOAD_FIELDS.filter((field) => body[field] !== undefined)
  if (present.length !== 1) {
    return anpRejection(
      'anp.invalid_params_shape',
      `body must carry exactly one of ${PAYLOAD_FIELDS.join(', ')} (got ${present.length})`,
    )
  }

  const field = present[0]
  if (field === undefined) return undefined
  const expected = CONTENT_TYPE_OF[field as keyof typeof CONTENT_TYPE_OF]
  if (expected !== undefined && contentType !== expected) {
    return anpRejection('anp.invalid_params_shape', `body.${field} requires content_type ${expected}`)
  }
  if (field === 'payload_b64u') {
    const value = body.payload_b64u
    if (typeof value !== 'string' || !isUnpaddedBase64Url(value)) {
      return anpRejection('anp.invalid_params_shape', 'body.payload_b64u must be unpadded base64url')
    }
  }
  if (field === 'text' && typeof body.text !== 'string') {
    return anpRejection('anp.invalid_params_shape', 'body.text must be a string')
  }
  if (field === 'payload' && (typeof body.payload !== 'object' || body.payload === null || Array.isArray(body.payload))) {
    return anpRejection('anp.invalid_params_shape', 'body.payload must be a JSON object')
  }
  return undefined
}

/**
 * `direct.incoming` 的 `params`（P3 §7.2.3 L409–422）。
 *
 * 落库时就构造好，而不是推送时再拼：推送失败要重试，重试时原始请求早已不在手上，
 * 而这些字段**必须**与原消息一致。存下来还能让取件面（`sync.delta`）直接把它当载荷，
 * 不必重建。
 *
 * `auth` 原样带走（L420）：中间服务**不得**重签，重签会把业务原发者的证明换成
 * 这个服务的，跨域链条上"谁发的"就变了。
 */
export function incomingParams(input: {
  meta: AnpMeta
  body: Record<string, unknown>
  auth?: AnpAuth
}): Record<string, unknown> {
  const { meta } = input
  const params: Record<string, unknown> = {
    meta: {
      profile: meta.profile,
      security_profile: meta.security_profile,
      sender_did: meta.sender_did,
      target: { kind: 'agent', did: meta.target?.did },
      operation_id: meta.operation_id,
      message_id: meta.message_id,
      content_type: meta.content_type,
    },
    body: input.body,
  }
  // 没有 `auth` 就不放这个键：一个 `undefined` 进去，JSON 序列化后整键消失、但内存里
  // 形状不同，取件面读出来的东西会随序列化时机变。
  if (input.auth !== undefined) params.auth = input.auth
  return params
}

export interface StoreDirectInput {
  meta: AnpMeta
  body: Record<string, unknown>
  auth?: AnpAuth
  /** RFC 3339。由调用方给，测试才好钉住这个值。 */
  acceptedAt: string
}

/**
 * 写下一条私聊消息与收件人的投递记录，返回 §7.1.3 L366–372 的成功 `result`。
 *
 * 结果**以 DID 为范围**（L378）：不含设备 selector、不含逐设备结果，所以这里只有一份
 * 投递记录，收件人是 `meta.target.did`。
 */
export function storeDirectMessage(storage: Storage, input: StoreDirectInput): Record<string, unknown> {
  const { meta } = input
  const targetDid = meta.target?.did ?? ''
  const messageId = meta.message_id ?? ''
  const senderDid = meta.sender_did ?? ''
  const conversationId = input.body.conversation_id

  // §8.2 L444–450 的消息级重复识别，也就是流程图里 M1 →「按重复消息策略处理」那一格。
  // 本实现的策略跟 §9.1 L630 给操作级的那个一样：把已经在那儿的消息**报回去**，不再存
  // 第二份、也不再排第二条投递——重放一条通知与重放一个响应，对收件人是同一件事。
  //
  // 只有操作级未命中时才会走到这里（C4 的 `perform` 只在未命中时被调用），所以这正是
  // §9.2 L650 排在第二位的那种情形：另一个 `operation_id` 指着一个已收下的消息。照
  // §8.4 L465–466 走的调用方（重试时 `operation_id` 与 `message_id` 都不变）根本到不了
  // 这一行——它命中的是操作级。
  const existing = storage.message(senderDid, targetDid, messageId)
  if (existing !== undefined) {
    return {
      accepted: true,
      message_id: existing.messageId,
      // 回的是**这次**操作的 id：应答的对象是这次调用。§9.1 L630 要的是"等价结果"而不是
      // 逐字节相同，而必须跨重放稳定的是 `message_id` / `target_did` / `accepted_at`
      // ——它们都取自落库那一行。
      operation_id: meta.operation_id,
      target_did: existing.targetDid,
      accepted_at: existing.acceptedAt,
      ...(existing.conversationId !== undefined ? { conversation_id: existing.conversationId } : {}),
    }
  }

  const acceptedAt = input.acceptedAt
  storage.insertMessage({
    messageId,
    senderDid,
    targetDid,
    profile: meta.profile,
    securityProfile: meta.security_profile,
    contentType: meta.content_type ?? '',
    bodyJson: JSON.stringify(input.body),
    ...(typeof conversationId === 'string' ? { conversationId } : {}),
    acceptedAt,
  })

  storage.appendDelivery({
    ownerDid: targetDid,
    messageId,
    method: 'direct.incoming',
    paramsJson: JSON.stringify(incomingParams({ meta, body: input.body, ...(input.auth ? { auth: input.auth } : {}) })),
    acceptedAt,
  })

  return {
    accepted: true,
    message_id: messageId,
    operation_id: meta.operation_id,
    target_did: targetDid,
    accepted_at: acceptedAt,
    // §7.1.3 L374–376：`conversation_id` 是 MAY，有就原样回。
    ...(typeof conversationId === 'string' ? { conversation_id: conversationId } : {}),
  }
}
