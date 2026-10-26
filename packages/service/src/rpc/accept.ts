// C4 —— 受理一次状态改变型操作：幂等查表 → 干活 → 记结果，全过程一个事务。
//
// 这一层只做"同一操作来过没有"，不判断"这次调用该不该由它发起"（那是 §5.1 的
// `authenticate`），也不判断"这个方法的 `target_scope` 是什么"（那是方法表的事，C5）。
// 传进来的 `key` 由调用方用 core 的 `idempotencyKey()` 从**请求自己写的**字段算好。
//
// P1 §9.1 L630–631 的两条分支在这里落地：语义等价 → 回原结果；语义冲突 → 1008。
// 判定本身是 core 的 `idempotencyVerdict()`，本模块负责的是它周围那圈**顺序与事务**。

import { anpRejection, idempotencyVerdict, type AnpRejection } from '@anpio-cli/core'
import type { Storage } from '../storage/types'

/**
 * 一次受理的结果。
 *
 * `new` 与 `replay` 都携带**操作的结果对象**（不是 JSON-RPC 信封）——重试是另一次请求、
 * 带自己的 `id`，回放一个存下来的信封会把首个请求的 `id` 答给重试。信封由调用方拿这次
 * 请求的 `id` 重新包一层。§9.1 L630 说"返回同一结果或等价结果"，说的是结果。
 */
export type Acceptance<T> =
  | { kind: 'new'; response: T }
  | { kind: 'replay'; response: T }
  /** 同键不同语义：P1 §10.3 L709 的 1008。 */
  | { kind: 'conflict'; error: AnpRejection }

export interface AcceptInput<T> {
  storage: Storage
  /**
   * core `idempotencyKey()` 的输出。
   *
   * 必须按**请求里写的** `sender_did` 算，不得先替换成后继 DID 再算——§9.1 L641
   * 要求"以 DID 已被替代为由拒绝之前，先查旧 DID 下的精确记录"。键换成后继 DID，
   * 那次查找就永远落空，一条早就处理过的重试会被当成新消息重做一遍。
   */
  key: string
  /** 请求的语义指纹（调用方用 `contentDigestOf(signedRequestObject)` 算），等价即相同。 */
  fingerprint: string
  /** 首次受理时执行的状态改变；返回值就是这次操作的结果。所有写都必须经由
   *  `input.storage`，它们都在同一个事务里。 */
  perform: () => T
  /** 记录 `created_at` 用的时钟。注入是为了测试不必等真实时间。 */
  now?: () => string
}

/**
 * 受理一次操作。
 *
 * `perform` 只在**没有记录**时被调用。这一条比它看起来重要：调用方把"这不对，拒掉"
 * （比如 `anp.did_superseded`）写在 `perform` 里抛出来，就自动满足了 §9.1 L641 的顺序
 * 要求——拒绝发生在查表**之后**。反过来说，任何在调用本函数**之前**就返回错误的写法，
 * 都会让这条规则失效。
 *
 * 事务边界也在这一层：`perform` 写下的行与随后写入的幂等记录同生共死。规范没要求这一步
 * （§9.1 只说重复请求 MUST 得到同一结果），但不这么做就没有任何东西能保证它——一半落库
 * 一半没有的中间态，会让"重试得到同一结果"变成一句空话。
 */
export function acceptOperation<T extends Record<string, unknown>>(
  input: AcceptInput<T>,
): Acceptance<T> {
  const now = input.now ?? (() => new Date().toISOString())
  return input.storage.transaction(() => {
    const row = input.storage.idempotentRow(input.key)
    const verdict = idempotencyVerdict(
      row === undefined
        ? undefined
        : {
            key: row.key,
            fingerprint: row.fingerprint,
            response: JSON.parse(row.responseJson) as Record<string, unknown>,
            createdAt: row.createdAt,
          },
      input.fingerprint,
    )

    if (verdict.kind === 'replay') return { kind: 'replay' as const, response: verdict.response as T }
    if (verdict.kind === 'conflict') {
      return {
        kind: 'conflict' as const,
        error: anpRejection(
          'anp.idempotency_conflict',
          'this operation_id was already used for a semantically different request',
        ),
      }
    }

    const response = input.perform()
    input.storage.rememberIdempotent({
      key: input.key,
      fingerprint: input.fingerprint,
      responseJson: JSON.stringify(response),
      createdAt: now(),
    })
    return { kind: 'new' as const, response }
  })
}
