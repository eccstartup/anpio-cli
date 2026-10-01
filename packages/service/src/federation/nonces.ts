// C11 —— 外层签名的重放缓存（federation.md §2.2）。
//
// ANP-02 L437 要求服务端**必须**实现重放防护，L143 把它放在验证流程的第 8 步。core 的
// `verifyHttpMessageSignature` 已经把这个接缝留好了（`nonceStore`），这里只补存储：
// 一行 `(keyid, nonce)`，过期即无意义。
//
// **为什么不用 core 里那个现成的 `createNonceStore()`**：它是一张进程内的 Map。这个服务
// 的 `Storage` 已经是一个跨重启的事实来源，而重放防护最不经用的失败恰好是"重启一下"——
// 攻击者不需要攻破什么，等一次发版就行。表本身很小（一行一个签名，两小时就出清了）。
//
// 键必须是 `(keyid, nonce)` 这一**对**，不能是裸 nonce。ANP-02 §3.2.1 第 8 步与 core 的
// `NonceStore` 都写明了：nonce 只保证签者自己内部唯一，按裸 nonce 建缓存会让一个 DID 的
// 重放烧掉另一个 DID 的挑战——那是一个受害者从没选过的值上的拒绝服务。

import type { NonceStore } from '@agentx/core'
import type { Storage } from '../storage/types'

/**
 * 一个 nonce 被记住多久。
 *
 * core 的 `verifyHttpMessageSignature` 给签名本身划的上限是 `created` 之后 600 秒、TTL
 * 3600 秒，所以一个 nonce 最多只可能在约 66 分钟的窗口里被重放。2 小时比那个窗口宽，
 * 是 core 的参考实现用的同一个数（`NonceStoreOptions.ttlMs` 的默认值），跟它对齐是为了
 * 两个实现不会给出两个答案。
 */
const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000

export interface HttpNonceStoreOptions {
  /** 见 {@link DEFAULT_TTL_MS}。 */
  ttlMs?: number
  /** 注入是为了让"过期之后可以再用"能被测试钉住，不是为了放宽策略。 */
  now?: () => Date
}

/**
 * `Storage` 上的 `http_nonces` 表，作为 core 的 {@link NonceStore}。
 *
 * 判定与写入都在 SQL 里（`consumeHttpNonce`），所以这里**没有**"先查再写"——那是这个
 * 接口唯一可能实现错的地方。
 */
export function createHttpNonceStore(storage: Storage, options: HttpNonceStoreOptions = {}): NonceStore {
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const now = options.now ?? ((): Date => new Date())

  return {
    consume(keyid: string, nonce: string): boolean {
      const at = now()
      const expiresAt = new Date(at.getTime() + ttlMs).toISOString()
      return storage.consumeHttpNonce(keyid, nonce, expiresAt, at.toISOString())
    },
  }
}
