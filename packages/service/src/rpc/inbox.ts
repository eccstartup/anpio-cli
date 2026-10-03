// C6 —— 取件扩展面（message-service.md §9）。
//
// 规范在取件侧是空白的，而且是刻意的：P3 §1 把历史拉取 / 已读状态 / 内部同步整个排除在外，
// P5 §10.7、P6、P8 §35 同样排除，规范里**不存在** `inbox.get`。所以这一族方法没有可援引的
// 规范条款，它们的权威就是 §9 那张表。
//
// ## 只剩一条方法了（2026-10-03，用户裁定）
//
// §9.3 那张表原本四条：`inbox.get` / `inbox.mark_read` / `message.get_batch` / `sync.delta`。
// 读搬到客户端本地之后（[client-messages.md](../../../../docs/design/client-messages.md) §8），
// 前三条**没有调用者了**，于是它们连同服务端这一侧的读状态一起退场——`inbox.get` 与
// `message.get_batch` 由本地查询取代，`inbox.mark_read` 由本地那次写取代（§8.5）。
//
// **留下 `sync.delta` 不是"留一条看看"**：它是补齐，而补齐这件事只有服务端做得了——本地库
// 是记录之源，但"服务端手上还有哪些客户端没搬走的投递"这个问题，答案不在客户端手里。
// `msg fetch` 与 `msg listen` 的回填都走它，所以它是这一族里唯一一个**必须**存在的成员。
//
// 删掉那三条不是把功能丢掉：方法表（`methods.ts` 的 `METHODS`）同时驱动分发与对外的能力面，
// 所以删掉它们的 spec，`/.well-known` 与 `anp.get_capabilities` 就不再宣告它们——客户端不会
// 看到一条答不了的方法，这是"别让读=本地与服务端还在答 inbox.get 同时为真"那条要求的落点。

import type { AnpMeta, AnpRejection } from '@agentx/core'
import { anpRejection } from '@agentx/core'
import type { Storage } from '../storage/types'
import { isCount, isNonEmptyString, isPage, unknownField } from './body'

/** §9.1：这条扩展面自己的 Profile。`x_` 前缀是 P1 §12 给扩展留的命名空间，取值不是
 *  任何一个规范 Profile——那才是对客户端撒谎（P1 §6.2.2 L277 说 `profile` 是"唯一解释"）。 */
export const EXTENSION_PROFILE = 'x_agentx.inbox.v1'

/** §9.3 那张表里**还在**的那一条。 */
export const SYNC_DELTA = 'sync.delta'

/** 一页的上限。`limit` 由调用方给，所以它也是一个要设界的外部输入：不限就等于让
 *  一个请求决定服务端读多少行、分配多少内存。 */
const MAX_PAGE = 200
const DEFAULT_DELTA_PAGE = 100

const DELTA_FIELDS = ['since', 'limit', 'device_id'] as const

// ---- body 校验 ---------------------------------------------------------------

/** §9.3 加的那一项：`body.device_id`，**选填**。
 *
 *  取件面是在 P5 之后才有设备概念的。P5 §10.7.1 L1407 把"只投给
 *  `meta.recipient_device_id`"写成 MUST，而订阅路已经照着做了（`stream/registry.ts` 的
 *  `reaches`）——那么同一条信箱的另一半（拉取）不照做，密文就会从这一侧漏给同账号的另一台
 *  设备。字段名沿用订阅握手那个 `device_id`，因为它们是同一台信箱的两半，而 `sync.delta`
 *  补的正是订阅会推的那些帧。
 *
 *  **缺席不是"没有限制"**，是"调用方没有声明自己代表哪台设备"——那样就只看账号级的行。
 *  这个方向（fail-closed）是刻意的：默认放行等于默认泄漏，而漏出去的密文收不回来。 */
function deviceFieldRefusal(body: Record<string, unknown>): AnpRejection | undefined {
  if (body.device_id !== undefined && !isNonEmptyString(body.device_id)) {
    return anpRejection('anp.invalid_params_shape', 'body.device_id must be a non-empty string')
  }
  return undefined
}

/** 校验过之后取用；没声明就是 `''`，与 `delivery_cursor.device_id` 同一个约定。 */
function deviceOf(body: Record<string, unknown>): string {
  return isNonEmptyString(body.device_id) ? body.device_id : ''
}

export function validateDeltaBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, DELTA_FIELDS)
  if (unknown !== undefined) return unknown
  const device = deviceFieldRefusal(body)
  if (device !== undefined) return device
  if (!isCount(body.since)) {
    return anpRejection('anp.invalid_params_shape', 'body.since must be a non-negative integer')
  }
  if (body.limit !== undefined && !isPage(body.limit, MAX_PAGE)) {
    return anpRejection('anp.invalid_params_shape', `body.limit must be an integer in 1..${MAX_PAGE}`)
  }
  return undefined
}

// ---- 处理 --------------------------------------------------------------------

function ownerOf(meta: AnpMeta): string {
  // `checkMethod` 已经保证 `meta.target.did === meta.sender_did`（§9.1.1），所以这里
  // 只是把那个结论拿出来用；真正被授权读的信箱永远是签名绑定的那个身份。
  return meta.sender_did ?? ''
}

/**
 * 取件面的**可读窗口**（2026-10-03 用户裁定，TODO7 §3）：`deliveries` 一条都不删，但
 * `sync.delta` 只答最近这么久的行。窗口下界由**这次请求自己的**时刻算，不是 `Date.now()`——
 * 同一批 assert 里两次调用必须落在同一个瞬间，否则一条投递会不会被答出来取决于两次之间
 * 服务端有没有跨过那个毫秒（`acceptedAt` 本来就是这么一路传下来的：`dispatch` 一次请求一个）。
 *
 * `windowMs` 是正数（配置层 `parsePositive` 保证），但真到了 `<= 0` 也只是把窗口收成
 * "只能看见未来"，不会算出 `Invalid Date`——`parsePositive` 之外没有人能给出这个值。
 */
function readWindowStart(acceptedAt: string, windowMs: number): string {
  return new Date(Date.parse(acceptedAt) - windowMs).toISOString()
}

export function readDelta(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
  readWindowMs: number,
  acceptedAt: string,
): Record<string, unknown> {
  const since = isCount(body.since) ? body.since : 0
  const limit = isPage(body.limit, MAX_PAGE) ? body.limit : DEFAULT_DELTA_PAGE
  const floor = readWindowStart(acceptedAt, readWindowMs)
  // 多要一行只为回答 `has_more`，多出来的那一行不进结果。窗口下界与 `limit` 一起进 SQL：
  // 先取页再筛会把页切错——筛掉几行之后"这一页满没满"说的就不是服务端手上的那一段了。
  const records = storage.deliveriesSince(ownerOf(meta), deviceOf(body), since, limit + 1, floor)
  const page = records.slice(0, limit)
  const last = page[page.length - 1]
  return {
    // 每一项就是订阅路会推的那一帧，原样，外加交付序号（§9.3）：这样补齐与实时两条路
    // 在客户端汇成同一个渲染器。
    messages: page.map((record) => ({
      seq: record.seq,
      method: record.method,
      params: JSON.parse(record.paramsJson) as unknown,
    })),
    // 空页回 `since` 本身：一个"没有新东西"的答案是"你还在原位"，不是"回到 0"。
    //
    // 窗口**不会**让这一条把游标推过看不见的那一段：窗口是序列的一个前缀（见
    // `types.ts` 的 {@link Storage.deliveriesSince}），所以看不见的行只在**比看见的行更早**
    // 的位置上。整条信箱都过期时这一页是空的、`next_since` 停在 `since`，客户端于是每次
    // 都重问一遍——那是对的答案("我这儿没有你能拿的")，只是问得有点勤；反过来把 `next_since`
    // 推到 `headSeq` 才是真的错：那等于替客户端宣告"这一段你看过了"。
    next_since: last === undefined ? since : last.seq,
    has_more: records.length > limit,
    // 「窗外还有多少」（TODO7 §3）：这一页够不着、游标也还没跨过的行数。少了它，
    // `brought in: 0` 分不出"真的没有了"与"有，但全在窗口外"——而窗口是**永不裁剪 + 限时
    // 可见**，所以后者是常态。它是诊断，不参与分页：`messages` / `next_since` / `has_more`
    // 一个都不因它改。只在第一页可能非零（后一页的 `since` 已经越过那段）。
    aged_out: storage.deliveriesAgedOut(ownerOf(meta), deviceOf(body), since, floor),
  }
}
