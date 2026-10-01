// C6 —— 取件扩展面（message-service.md §9）。
//
// 规范在取件侧是空白的，而且是刻意的：P3 §1 把历史拉取 / 已读状态 / 内部同步整个排除在外，
// P5 §10.7、P6、P8 §35 同样排除，规范里**不存在** `inbox.get`。所以这一族方法没有可援引的
// 规范条款，它们的权威就是 §9 那张表；本文件是那张表在服务端的唯一实现，两边（服务与 CLI）
// 的字段名与形状要对上，靠的是同一个 §9.3。
//
// 两种东西分开写在这里：`validateXxxBody` 是"这个请求能不能答"，`readXxx` 是"答什么"。
// 认证、信封、目标绑定都在上面几层，这里拿到的已经是验过签、查过 `target.did == sender_did`
// 的 params。

import type { AnpMeta, AnpRejection } from '@agentx/core'
import { anpRejection } from '@agentx/core'
import type { InboxRow, Storage } from '../storage/types'
import { isCount, isNonEmptyString, isPage, unknownField } from './body'

/** §9.1：这条扩展面自己的 Profile。`x_` 前缀是 P1 §12 给扩展留的命名空间，取值不是
 *  任何一个规范 Profile——那才是对客户端撒谎（P1 §6.2.2 L277 说 `profile` 是"唯一解释"）。 */
export const EXTENSION_PROFILE = 'x_agentx.inbox.v1'

/** §9.3 那张表的四个方法。`direct.get_history` 不在其中，理由见设计文档 §9.3。 */
export const INBOX_GET = 'inbox.get'
export const INBOX_MARK_READ = 'inbox.mark_read'
export const MESSAGE_GET_BATCH = 'message.get_batch'
export const SYNC_DELTA = 'sync.delta'

/** §9.3：`message.get_batch` 一次最多收这么多 id。 */
const MAX_BATCH = 100
/** 一页的上限。`limit` 由调用方给，所以它也是一个要设界的外部输入：不限就等于让
 *  一个请求决定服务端读多少行、分配多少内存。 */
const MAX_PAGE = 200
const DEFAULT_PAGE = 20
const DEFAULT_DELTA_PAGE = 100

const INBOX_GET_FIELDS = ['limit', 'skip', 'include_read'] as const
const MARK_READ_FIELDS = ['message_ids'] as const
const GET_BATCH_FIELDS = ['message_ids'] as const
const DELTA_FIELDS = ['since', 'limit'] as const

// ---- body 校验 ---------------------------------------------------------------

function idsOf(value: unknown, field: string, max?: number): { ids: string[] } | { error: AnpRejection } {
  if (!Array.isArray(value) || value.length === 0) {
    return { error: anpRejection('anp.invalid_params_shape', `body.${field} must be a non-empty array of message ids`) }
  }
  if (max !== undefined && value.length > max) {
    return {
      error: anpRejection('anp.invalid_params_shape', `body.${field} holds at most ${max} ids (got ${value.length})`),
    }
  }
  if (!value.every(isNonEmptyString)) {
    return { error: anpRejection('anp.invalid_params_shape', `body.${field} must hold non-empty strings`) }
  }
  // 重复的 id 不拒：调用方把同一个东西列了两遍，没有任何一种状态下拒绝它对它更有用。
  // 去重后按首次出现的顺序查，结果里也按这个顺序给。
  return { ids: [...new Set(value)] }
}

/** The id list of a request whose body has already passed its validator. Kept separate
 *  from {@link idsOf} so the handlers do not have to re-unwrap a rejection that cannot
 *  be there any more. */
function idsFrom(body: Record<string, unknown>): string[] {
  const value = Array.isArray(body.message_ids) ? body.message_ids : []
  return [...new Set(value.filter(isNonEmptyString))]
}

export function validateInboxGetBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, INBOX_GET_FIELDS)
  if (unknown !== undefined) return unknown
  if (body.limit !== undefined && !isPage(body.limit, MAX_PAGE)) {
    return anpRejection('anp.invalid_params_shape', `body.limit must be an integer in 1..${MAX_PAGE}`)
  }
  if (body.skip !== undefined && !isCount(body.skip)) {
    return anpRejection('anp.invalid_params_shape', 'body.skip must be a non-negative integer')
  }
  if (body.include_read !== undefined && typeof body.include_read !== 'boolean') {
    return anpRejection('anp.invalid_params_shape', 'body.include_read must be a boolean')
  }
  return undefined
}

export function validateMarkReadBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, MARK_READ_FIELDS)
  if (unknown !== undefined) return unknown
  const parsed = idsOf(body.message_ids, 'message_ids')
  return 'error' in parsed ? parsed.error : undefined
}

export function validateGetBatchBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, GET_BATCH_FIELDS)
  if (unknown !== undefined) return unknown
  const parsed = idsOf(body.message_ids, 'message_ids', MAX_BATCH)
  return 'error' in parsed ? parsed.error : undefined
}

export function validateDeltaBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, DELTA_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isCount(body.since)) {
    return anpRejection('anp.invalid_params_shape', 'body.since must be a non-negative integer')
  }
  if (body.limit !== undefined && !isPage(body.limit, MAX_PAGE)) {
    return anpRejection('anp.invalid_params_shape', `body.limit must be an integer in 1..${MAX_PAGE}`)
  }
  return undefined
}

// ---- 结果 --------------------------------------------------------------------

/** §9.3 的那七项，外加 `body`。
 *
 *  `read_at` 对 `direction: "outgoing"` 一直是 `null`：那是发件人自己的一份，不存在
 *  "读没读"这回事。判"未读"的那一侧必须把方向一起看，光看 `read_at` 会把每一条自己
 *  发出去的消息都算成未读。 */
function rowJson(row: InboxRow): Record<string, unknown> {
  return {
    message_id: row.messageId,
    sender_did: row.senderDid,
    recipient_did: row.recipientDid,
    content_type: row.contentType,
    direction: row.direction,
    created_at: row.createdAt,
    read_at: row.readAt,
    body: JSON.parse(row.bodyJson) as unknown,
  }
}

function ownerOf(meta: AnpMeta): string {
  // `checkMethod` 已经保证 `meta.target.did === meta.sender_did`（§9.1.1），所以这里
  // 只是把那个结论拿出来用；真正被授权读的信箱永远是签名绑定的那个身份。
  return meta.sender_did ?? ''
}

// ---- 处理 --------------------------------------------------------------------

export function readInbox(storage: Storage, meta: AnpMeta, body: Record<string, unknown>): Record<string, unknown> {
  const owner = ownerOf(meta)
  const limit = isPage(body.limit, MAX_PAGE) ? body.limit : DEFAULT_PAGE
  const skip = isCount(body.skip) ? body.skip : 0
  // §9.3 的 `include_read` 缺省为假，与 CLI 的默认一致：`msg inbox` 先给未读，
  // 要看全部得显式要求。
  const includeRead = body.include_read === true
  const rows = storage.inboxPage(owner, { limit, skip, includeRead })
  const total = storage.inboxSize(owner, includeRead)
  return {
    messages: rows.map(rowJson),
    total,
    // 由 `total` 算而不是"这一页满没满"：最后一页正好填满时，前者是 false，后者会说还有。
    has_more: skip + rows.length < total,
  }
}

export function readBatch(storage: Storage, meta: AnpMeta, body: Record<string, unknown>): Record<string, unknown> {
  const ids = idsFrom(body)
  const found = new Map(storage.inboxRows(ownerOf(meta), ids).map((row) => [row.messageId, row]))
  return {
    items: ids.flatMap((id) => {
      const row = found.get(id)
      return row === undefined ? [] : [{ message_id: id, message: rowJson(row) }]
    }),
    // 查不到与查得到分开报：`msg show <id>` 拿一个不属于这个信箱的 id，得到的必须是
    // "没有这条"，而不是一条空消息。
    unavailable: ids.filter((id) => !found.has(id)),
  }
}

export function readDelta(storage: Storage, meta: AnpMeta, body: Record<string, unknown>): Record<string, unknown> {
  const since = isCount(body.since) ? body.since : 0
  const limit = isPage(body.limit, MAX_PAGE) ? body.limit : DEFAULT_DELTA_PAGE
  // 多要一行只为回答 `has_more`，多出来的那一行不进结果。
  const records = storage.deliveriesSince(ownerOf(meta), since, limit + 1)
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
    next_since: last === undefined ? since : last.seq,
    has_more: records.length > limit,
  }
}

export function markRead(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
  readAt: string,
): Record<string, unknown> {
  const ids = idsFrom(body)
  const marked = storage.markRead(ownerOf(meta), ids, readAt)
  return {
    updated_count: marked.length,
    // 回的是**真的被标上的**那些，不是请求里列的：里面有别人的消息、有本来就已读的，
    // 把它们一起报成"已更新"会让 `updated_count` 变成一个不说明任何事的数。
    message_ids: marked,
    read_at: marked.length > 0 ? readAt : null,
  }
}
