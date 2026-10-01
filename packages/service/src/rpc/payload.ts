// 负载字段与 `content_type` 的那条规则。
//
// P3 §6.2.4–§6.2.6 与 P4 §7.6 说的是**同一件事**，所以只有这一份：`direct.send` 与
// `group.send` 的正文互斥规则逐字相同，各写一遍就等着某次只改了其中一边。

import { anpRejection, type AnpRejection } from '@agentx/core'

/** P3 §6.3 L281–285 / P4 §7.6 L438–442：三个负载字段，**恰好**出现一个。 */
export const PAYLOAD_FIELDS = ['text', 'payload', 'payload_b64u'] as const

/**
 * 内容类型 → 它**要求**出现的那个负载字段。
 *
 * **方向是单向的**：规范说的是"当 `content_type = "text/plain"` 时 `text` **MUST**"
 * （P3 §6.2.4 L262）、"当 `content_type = "application/json"` 时 `payload` **MUST**"
 * （§6.2.5 L268），不是"`payload` 出现时必须配 `application/json`"。读成等号会拒掉
 * `application/anp-attachment-manifest+json` 这类内容类型——它们的 `body.payload`
 * **MUST** 是 Attachment Message（P7 §6.1 L349–350），P4 §7.6 L432–436 又点名 MUST
 * 支持它。
 *
 * `+json` 按后缀收而不是逐条列举：P7 那一类是"JSON 媒体类型用 `payload` 承载自己的
 * 对象"，同族的其它类型没有理由不一样。
 *
 * 表里没有的内容类型**不施加**任何约束。负载是不透明字节，本服务不解释它，于是发送方
 * 自定义的内容类型（P3 §6.2.6 L274）照样能被受理。
 */
function payloadFieldRequiredBy(contentType: string): string | undefined {
  if (contentType === 'text/plain') return 'text'
  if (contentType === 'application/json' || contentType.endsWith('+json')) return 'payload'
  return undefined
}

/**
 * 本服务对外自报的内容类型（P1 §8.2.2 L574）。
 *
 * 这份清单**不是**准入白名单，见上面那段：任何 `content_type` 都能被转发。这里列的是
 * 规范点名要求支持的那几个——P3 的两个，加上 P4 §7.6 L432–436 MUST 支持的三个里多出来的
 * 附件清单类型。
 */
export const ACCEPTED_CONTENT_TYPES: readonly string[] = [
  'text/plain',
  'application/json',
  'application/anp-attachment-manifest+json',
]

function isUnpaddedBase64Url(value: string): boolean {
  // P3 §6.2.6 L276：无填充 base64url。`=` 出现在这里就是填充；长度模 4 余 1 是任何
  // base64 都不可能产生的形态。
  return /^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1
}

/**
 * 负载字段是否合规（P3 §6.3 L281–285、§6.2.4 L262、§6.2.5 L268；P4 §7.6 同）。
 *
 * 三选一的规则是 MUST-reject，且要**恰好**一个：多一个少一个都拒。
 *
 * 回 1003（`anp.invalid_params_shape`）是**本实现的选择**：P3 §7.1.4 L386–387 把"内容
 * 类型不被支持"与"请求体不符合互斥规则"列成两条拒绝理由，却没给后者配码，而 1003 是公共
 * 段里唯一说"params 结构不符合要求"的那个。1009 留给真正不认识的内容类型。
 */
export function validatePayloadBody(body: Record<string, unknown>, contentType: string): AnpRejection | undefined {
  const present = PAYLOAD_FIELDS.filter((field) => body[field] !== undefined)
  if (present.length !== 1) {
    return anpRejection(
      'anp.invalid_params_shape',
      `body must carry exactly one of ${PAYLOAD_FIELDS.join(', ')} (got ${present.length})`,
    )
  }

  const field = present[0]
  if (field === undefined) return undefined
  const required = payloadFieldRequiredBy(contentType)
  if (required !== undefined && field !== required) {
    return anpRejection('anp.invalid_params_shape', `content_type ${contentType} requires body.${required}`)
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
