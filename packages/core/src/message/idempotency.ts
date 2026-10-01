// ANP-09 P1 §9 —— 幂等键与判定。
//
// 只做**纯函数**那一半：算键、判"重放还是冲突"。存与事务是服务端的事
// （`packages/service` 的 `Storage`），因为"先落库再应答"要用上同一个事务，
// 那不是 core 能替它做的。
//
// 放 core 是因为键的两侧在不同进程里：发方要靠同一个 `operation_id` 重试（§9.2
// L647–648），收方要靠同一个键认出重试。两边各算一遍，就会出现"重试看起来像新消息"。

import { ConnectxError } from '../errors'
import type { AnpMeta } from './envelope'

/**
 * §9.1 L628：`(sender_did, target_scope, method, operation_id)`。
 *
 * `target_scope` 的具体取值**由 Profile 定义**（§9.1 L635）：Direct 类通常是
 * `target.did`，Group 类通常是 `group_did`。所以它在这里是一个**调用方填好的值**，
 * 而不是从 `meta` 里现取的字段——Group 的群 id 在 `body.group_did` 上，不在
 * `meta.target.did` 上，由本模块去猜哪一个是猜不对的。
 */
export interface IdempotencyScope {
  senderDid: string
  /** Profile 定义的 `target_scope`。 */
  targetScope: string
  method: string
  operationId: string
  /**
   * **仅**设备定址的 E2EE Overlay 使用（§9.1 L639）。
   *
   * Base 操作**必须留空**——"对 DID 定址的 Base 操作，设备标识不属于幂等作用域"。
   * 把设备 selector 无差别塞进来，会让同一个逻辑操作从两台设备发出时被当成两件事，
   * 而它们本该共享一个幂等记录。
   */
  deviceSelectors?: string[]
}

/**
 * 键的字符串形式：每段长度前缀 + `:`，段间用 `|`。
 *
 * 长度前缀不是装饰。`operation_id` / `target_scope` 都是对端可控的字符串，用分隔符
 * 拼接时 `("a|b", "c")` 与 `("a", "b|c")` 会撞成同一个键——前者是重放，后者是新请求，
 * 撞上就意味着**把一个新请求当成重放、回给它上一次的响应**。DID 里今天不会出现 `|`，
 * 但"今天不会出现"不是正确性依据。
 */
export function idempotencyKey(scope: IdempotencyScope): string {
  if (scope.operationId === '') {
    // §6.2.6 L388：所有会改变状态的操作 MUST 带 operation_id。没有它就没有幂等
    // 可言——每次重试都会被当成新操作，而这正是幂等要防的那件事。
    // （§9.1 L628 把 operation_id 列为幂等键的四段之一，前提就是它存在。）
    throw new ConnectxError('message_invalid', 'operation_id is required for state-changing operations')
  }
  const parts = [scope.senderDid, scope.targetScope, scope.method, scope.operationId]
  // 设备 selector 排序后入键，这样"同一组设备、不同书写顺序"算同一个键。
  if (scope.deviceSelectors && scope.deviceSelectors.length > 0) {
    parts.push([...scope.deviceSelectors].sort().join(','))
  }
  return parts.map((p) => `${p.length}:${p}`).join('|')
}

/** 一条已接受的幂等记录。`response` 是原样回放的那次结果（§9.1 L630）。 */
export interface IdempotencyRecord {
  key: string
  /** 请求的语义指纹；等价即相同。 */
  fingerprint: string
  response: Record<string, unknown>
  createdAt: string
}

export type IdempotencyVerdict =
  /** 没记录：这是第一次，正常处理。 */
  | { kind: 'new' }
  /** 同键同语义：**回原结果**，不要重复投递（§9.1 L630）。 */
  | { kind: 'replay'; response: Record<string, unknown> }
  /** 同键不同语义：`anp.idempotency_conflict`（§9.1 L631）。 */
  | { kind: 'conflict'; code: 'anp.idempotency_conflict' }

/**
 * §9.1 L630–631 的判定。
 *
 * "语义等价"在这里落在**指纹相等**上。指纹由调用方给出，用请求自己的
 * `contentDigestOf(signedRequestObject)` 最省事也最不容易走偏：它已经覆盖
 * method / meta / body 的全部内容，且与签名绑的是同一个对象（P1 附录 A.3）。
 * 自己另算一份摘要就会有两种"等价"。
 */
export function idempotencyVerdict(
  record: IdempotencyRecord | undefined,
  fingerprint: string,
): IdempotencyVerdict {
  if (record === undefined) return { kind: 'new' }
  if (record.fingerprint === fingerprint) return { kind: 'replay', response: record.response }
  return { kind: 'conflict', code: 'anp.idempotency_conflict' }
}

// §9.2 L650：服务端**先**查操作级幂等记录，再谈消息级。
//
// 这条落在**查找顺序**上，不是键的形状——所以它没有对应的函数，只有这条注释。
// 消息级去重的键（是否含 `message_id`）由各消息 Profile 定义（§9.2 L651），
// 本模块只固定操作级这一层。
//
// 另：DID 已被替代时，§9.1 L641 要求在**以"DID 已被替代"拒掉之前**，用**旧 DID** 查一次
// 精确幂等记录，命中就回原结果。
// 那也落在同一件事上——键必须按请求里写的 `sender_did` 算，**不得**先替换成后继 DID
// 再算。换了就等于把一条早就处理过的重试，重新当成新消息处理一遍，而那正是这条规则
// 要防的情形。同一行还划了另一半边界：后继 DID 签的请求**不是**旧 DID 请求的精确重放，
// 跨 DID 去重要由 Profile 另行定义，本模块不替它做。

/** 从 `meta` 取一次幂等作用域所需的三个字段，把缺失值就地拒掉。 */
export function idempotencyScopeFromMeta(input: {
  meta: AnpMeta
  /** Profile 定义的 `target_scope`（Direct 是 `target.did`，Group 是 `group_did`）。 */
  targetScope: string
  method: string
  deviceSelectors?: string[]
}): IdempotencyScope {
  const { meta } = input
  if (typeof meta.sender_did !== 'string' || meta.sender_did === '') {
    throw new ConnectxError('message_invalid', 'meta.sender_did is required to compute an idempotency key')
  }
  if (typeof meta.operation_id !== 'string' || meta.operation_id === '') {
    throw new ConnectxError('message_invalid', 'meta.operation_id is required to compute an idempotency key')
  }
  const scope: IdempotencyScope = {
    senderDid: meta.sender_did,
    targetScope: input.targetScope,
    method: input.method,
    operationId: meta.operation_id,
  }
  if (input.deviceSelectors && input.deviceSelectors.length > 0) {
    scope.deviceSelectors = input.deviceSelectors
  }
  return scope
}
