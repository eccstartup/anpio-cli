// 正文校验里反复出现的那几个判断。
//
// 提出来是因为 §9 那条扩展面和它上面的传输握手掌的是同一套规矩（`rpc/stream.ts`）：方法自己
// 的正文里出现了不认识的字段就拒。两处各写一遍的话，"不认识的字段"这件事会有两个定义，而
// 它们的分歧只会表现为某个方法多收或少收了一个键。

import { anpRejection, type AnpRejection } from '@anpio-cli/core'

/** 不认识就拒。
 *
 *  这是本实现的选择，理由是这一族方法的参数**全部**由我们自己的客户端给：一个拼错的
 *  `include-read` 被静默忽略，结果就是"少看到一些消息"而没有任何地方说得出为什么。
 *  P1 对 `meta` 用的是同一条规矩（§6.2.1 的未知字段 MUST NOT 出现），这里只是把它
 *  照搬到方法自己的 `body` 上。 */
export function unknownField(body: Record<string, unknown>, allowed: readonly string[]): AnpRejection | undefined {
  const extra = Object.keys(body).filter((key) => !allowed.includes(key))
  if (extra.length === 0) return undefined
  return anpRejection('anp.invalid_params_shape', `unknown body field(s): ${extra.join(', ')}`)
}

export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== ''
}

/** 非负整数。`skip` / `since` 用这个：0 是合法值，所以不能拿"假值"当缺失。 */
export function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
}

/** 正整数，且不超过 `max`。 */
export function isPage(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= max
}
