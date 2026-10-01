// C7 —— 流上的两个传输方法（realtime.md §4、§6）。
//
// 这两个方法与 §9 那条取件面**不在同一个 Profile 下**：取件面是 `x_agentx.inbox.v1`，
// 握手与投递确认是 `x_agentx.stream.v1`（realtime.md §9 把这条分界写清了——业务方法与
// 传输握手各有各的 Profile，都挂在 `x_` 扩展命名空间里）。
//
// 它们**不进 `METHODS`**：那张表是 `POST /anp-im/rpc` 的方法面，而这两个方法离开了流就
// 没有意义。`stream.auth` 在 HTTP 上没有订阅可注册，`stream.ack` 在 HTTP 上不知道是哪台
// 设备（游标按 `(owner_did, device_id)` 分片，§5.4）。所以它们由 `stream/session.ts` 在
// 连接上直接接，走的是**同一条** `checkMethod` + `authenticate` 路径，不是另一套。

import type { AnpRejection } from '@agentx/core'
import { anpRejection } from '@agentx/core'
import { isCount, isNonEmptyString, unknownField } from './body'

/** 传输握手的 Profile（realtime.md §9）。 */
export const STREAM_PROFILE = 'x_agentx.stream.v1'

export const STREAM_AUTH = 'stream.auth'
export const STREAM_ACK = 'stream.ack'

/** `stream.hello` 是服务端推的 Notification，客户端不发它；常量在这里是为了让它与
 *  `stream.auth` 相邻——`hello` 报的能力里就有本 Profile 的值。 */
export const STREAM_HELLO = 'stream.hello'

const AUTH_FIELDS = ['device_id', 'cursor'] as const
const ACK_FIELDS = ['seq'] as const

/** `stream.auth {device_id, cursor?}`（realtime.md §4）。
 *
 *  `cursor` 是 `--since` 那条排查用的覆盖（§5.4）：给的是**这次补齐的起点**，不是要写进
 *  存储的游标——写存储的只有 `stream.ack`。所以这里只校验形状，不回写。 */
export function validateStreamAuthBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, AUTH_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isNonEmptyString(body.device_id)) {
    return anpRejection('anp.invalid_params_shape', 'body.device_id must be a non-empty string')
  }
  if (body.cursor !== undefined && !isCount(body.cursor)) {
    return anpRejection('anp.invalid_params_shape', 'body.cursor must be a non-negative integer')
  }
  return undefined
}

/** `stream.ack {seq}`（realtime.md §6）。
 *
 *  它推进的是**本服务的交付游标**，不是发回给对方的已读回执——规范不定义后者
 *  （P5 §10.7、P6、P8 §35），§6 那段⚠写的就是这件事。 */
export function validateStreamAckBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, ACK_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isCount(body.seq) || body.seq === 0) {
    return anpRejection('anp.invalid_params_shape', 'body.seq must be a positive integer')
  }
  return undefined
}

/** 握手帧里的 `device_id`。校验过之后取用，所以这里能直接当字符串。 */
export function deviceIdOf(body: Record<string, unknown>): string {
  return typeof body.device_id === 'string' ? body.device_id : ''
}

/** 握手帧里可选的 `cursor`，没给就是 `undefined`（调用方据此回落到存储里的游标）。 */
export function cursorOf(body: Record<string, unknown>): number | undefined {
  return typeof body.cursor === 'number' && Number.isInteger(body.cursor) ? body.cursor : undefined
}

/** 投递确认帧里的 `seq`。 */
export function seqOf(body: Record<string, unknown>): number {
  return typeof body.seq === 'number' && Number.isInteger(body.seq) ? body.seq : 0
}
