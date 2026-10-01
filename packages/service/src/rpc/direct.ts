// P3 私聊：`direct.send` 的body 校验与落库。
//
// 分两层看：`validateDirectBody` 是"这条消息能不能收"，`storeDirectMessage` 是"收下之后
// 写什么"。两者都不看信封、不验签——那些是 §3 与 §5 的事，这里拿到的已经是解析过、
// 认证过的东西。
//
// 写库发生在 `acceptOperation` 的 `perform` 里，所以这里**不得**自己开事务、
// 也不得在写之前做任何可能失败的 I/O（一次网络往返会让并发写在锁里等）。

import { anpRejection, buildMessageNotification, type AnpAuth, type AnpMeta, type AnpParams, type AnpRejection } from '@agentx/core'
import type { DeliveryRecord, Storage } from '../storage/types'

/** P3 §6.3 L281–285 里的三个负载字段。 */
const PAYLOAD_FIELDS = ['text', 'payload', 'payload_b64u'] as const

/** 每个字段对应的内容类型（P3 §6.2.4 L262 / §6.2.5 L268）。`payload_b64u` 是二进制或
 *  私有扩展（§6.2.6 L274），Profile 没有给它定内容类型，所以不在这张表里。 */
const CONTENT_TYPE_OF = {
  text: 'text/plain',
  payload: 'application/json',
} as const

/**
 * 本服务接受的内容类型，供 `anp.get_capabilities` 的 `supported_content_types` 自报
 * （P1 §8.2.2 L574，那里说这个字段 SHOULD 尽量给）。
 *
 * 从上面那张表**推**出来，而不是另写一份清单：那张表就是"哪些内容类型会被接受"的判据
 * （`validateDirectBody` 按它拒），另写一份迟早与它对不上，而对不上的方向是"报了却不认"
 * ——客户端照着自己看到的清单发，收到一个 1003。
 *
 * `payload_b64u` 的私有扩展对象用的是发送方自定义的内容类型（§6.2.6 L274），枚举不出来，
 * 所以不在这里；它们照样能被受理，只是没法提前声明。
 */
export const ACCEPTED_CONTENT_TYPES: readonly string[] = [...new Set(Object.values(CONTENT_TYPE_OF))]

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
 * `direct.incoming` 是**这一个方法名**：它是通知，不是请求，表不在方法表里（本服务
 * 收它、不服务它）。放在这里是因为它承载的是"这条 `direct.send` 被投递时是什么样"，
 * 与这个文件里其余的私聊语义是同一件事。
 */
export const DIRECT_INCOMING = 'direct.incoming'

export interface IncomingParamsInput {
  meta: AnpMeta
  /** 收件人。就是 `meta.target.did`（P3 §7.2.3 L414），但单独传进来：`meta.target` 的
   *  类型是可选的，而 §7.2.3 要这一项 MUST 在。调用方刚查过目标绑定，让它把那个已经
   *  非空的值交过来，比在这里再写一次 `?? ''` 更诚实。 */
  targetDid: string
  body: Record<string, unknown>
  auth?: AnpAuth
}

/**
 * 落库时就构造好，而不是推送时再拼：推送失败要重试，重试时原始请求早已不在手上，
 * 而这些字段**必须**与原消息一致。存下来还能让取件面（`sync.delta`）直接把它当载荷，
 * 不必重建。
 *
 * `auth` 原样带走（L420）：中间服务**不得**重签，重签会把业务原发者的证明换成
 * 这个服务的，跨域链条上"谁发的"就变了。
 *
 * 这个函数只写 §7.2.3 L411–418 点名的七个字段——`sender_device_id` /
 * `recipient_device_id` 不在其中，L421 还专门要求它们 MUST NOT 出现（设备 selector
 * 只属于 P5 的 Overlay，而 Base 的 `direct.send` 连收都不收它们）。
 */
export function incomingParams(input: IncomingParamsInput): AnpParams {
  const { meta } = input
  return {
    meta: {
      profile: meta.profile,
      security_profile: meta.security_profile,
      sender_did: meta.sender_did,
      target: { kind: 'agent', did: input.targetDid },
      operation_id: meta.operation_id,
      message_id: meta.message_id,
      content_type: meta.content_type,
    },
    // 没有 `auth` 就不放这个键：一个 `undefined` 进去，JSON 序列化后整键消失、但内存里
    // 形状不同，取件面读出来的东西会随序列化时机变。
    ...(input.auth !== undefined ? { auth: input.auth } : {}),
    body: input.body,
  }
}

export interface StoreDirectInput {
  meta: AnpMeta
  body: Record<string, unknown>
  auth?: AnpAuth
  /** RFC 3339。由调用方给，测试才好钉住这个值。 */
  acceptedAt: string
  /**
   * The delivery this call appended, once there is one.
   *
   * A callback rather than a return value because the caller is inside a transaction and
   * must not use it yet: the subscription push (realtime.md §8.1) happens **after** the
   * commit, and this is how the record gets out there. Nothing may be published from here —
   * a message the transaction then rolls back would have been pushed to a live client.
   *
   * Not called on the duplicate path: §8.2 L444–450's second send of one message appends no
   * delivery, so there is no new sequence and nothing to push.
   */
  onDelivery?: (record: DeliveryRecord) => void
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

  // §7.2.3 的字段表只写一遍：投递行与出站通知用的是**同一份** `params`，两处各拼一次
  // 就是将来某次改动只改了一边的入口。
  const params = incomingParams({
    meta,
    targetDid,
    body: input.body,
    ...(input.auth !== undefined ? { auth: input.auth } : {}),
  })

  const delivered = storage.appendDelivery({
    ownerDid: targetDid,
    messageId,
    method: DIRECT_INCOMING,
    paramsJson: JSON.stringify(params),
    acceptedAt,
  })
  input.onDelivery?.(delivered)

  // 出站推送排进 outbox。载荷存**整个通知信封**：worker 到那时手上只有这一行，任何
  // "到时候再拼"都要它知道方法名与 §7.2.3 的字段搬运规则，而那正是上面刚刚做过的事。
  //
  // `nextAttemptAt` 取受理时刻：受理成功之后马上尝试一次是常态，退避只在失败之后开始。
  // 这一步仍然是纯写——真正解析对端与发 HTTP 的是 delivery worker，不在这里。事务里
  // 不得有网络往返，否则一次慢连接会让所有并发受理在锁上等。
  storage.enqueueOutbox({
    recipientDid: targetDid,
    payloadJson: JSON.stringify(
      buildMessageNotification({
        method: DIRECT_INCOMING,
        meta: params.meta,
        body: params.body,
        ...(params.auth !== undefined ? { auth: params.auth } : {}),
      }),
    ),
    nextAttemptAt: acceptedAt,
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
