// Profile 处理器在**事务内部**拒绝一次调用时用的那个异常。
//
// 为什么是异常而不是返回值：拒绝点分布在 handler 的任意深度，而它们的调用方是
// `acceptOperation()` 的 `perform`——那个函数的返回值是**操作的结果**，不是"结果或拒绝"。
// 把两者塞进同一个返回值，每一层都要多写一个解包分支。
//
// 另一条更重要的理由在顺序上：P1 §9.1 L641 要求"以 DID 已被替代为由拒绝之前，先返回旧
// DID 下的精确幂等重放结果"，C4 把这个顺序实现成"幂等命中就不调用 `perform`"。所以凡是
// 需要查库才能判的拒绝（权限、成员状态、群在不在），都**必须**在 `perform` 里抛出，而不
// 能在进入事务之前就地回一个响应——后者会让一次早已受理的重试被重新判一遍，而那次判定
// 此刻的答案可能与当初不同。

import type { AnpRejection } from '@agentx/core'

/** 一次调用被 Profile 层拒绝。抛出它，让分发层用**这次请求自己的** `id` 包成响应。 */
export class AnpRefusal extends Error {
  readonly rejection: AnpRejection

  constructor(rejection: AnpRejection) {
    super(rejection.message)
    this.name = 'AnpRefusal'
    this.rejection = rejection
  }
}

/** 判不了就抛。`throw refusal(...)` 比 `if (...) throw new AnpRefusal(x)` 少一层括号。 */
export function refusal(rejection: AnpRejection): AnpRefusal {
  return new AnpRefusal(rejection)
}
