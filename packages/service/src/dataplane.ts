// C10 —— P7 的数据面：上传与下载这两条字节路。
//
// 它们**不是** JSON-RPC（§11.1 L1050 / §11.2 L1057）：客户端是普通 HTTP 客户端（curl、
// 浏览器、`fetch`），所以这里没有信封、没有 `id`，用的是**真的 HTTP 状态码**加一个 JSON
// 体里的 `anp_code`，两种客户端都能用。`attachments.md` §3.1 说明了为什么不跟着 §2.1 的
// "一律 200"：那条规矩的理由是 `core` 的 `postMessage` 对非 2xx 直接抛错、会丢掉
// `anp_code`，而在数据面上没有那个客户端。
//
// 与 HTTP 层的关系和 `dispatch.ts` 一样：本模块返回一个值，绝不碰 `ServerResponse`。
// 唯一的区别是那个值可以带一个 `Readable`——对象是几 MiB，不能先读进内存。

import type { IncomingMessage } from 'node:http'
import type { Readable } from 'node:stream'
import type { ObjectStore } from './objects'
import { ObjectTooLargeError } from './objects'
import type { Storage } from './storage/types'
import { attachmentError, objectUriFor, sha256b64u, type AttachmentErrorName } from './rpc/attachments'

export interface DataPlaneDeps {
  storage: Storage
  objects: ObjectStore
  /** `object_uri` 的基址。拼法与 `attachments.ts` 里铸它的时候是同一个函数。 */
  publicUrl: string
  /** 一次请求一个时刻，测试才好钉住它。 */
  now?: () => Date
}

export interface DataPlaneRequest {
  /** 路由那一段参数，已经 `decodeURIComponent`：上传路由是 URL 里的令牌，下载路由是
   *  对象 id。 */
  resource: string
  headers: IncomingMessage['headers']
  /** 请求体。只有 PUT 会去读它；GET 上它是一个空的异步可迭代。 */
  body: AsyncIterable<Uint8Array>
}

export interface DataPlaneResponse {
  status: number
  /** 小体（错误就是这样）。与 `stream` 二选一。 */
  body?: string
  /** 对象字节。`length` 写进 `content-length`。 */
  stream?: { read: Readable; length: number }
  contentType?: string
  headers?: Record<string, string>
}

export type DataPlaneHandler = (request: DataPlaneRequest) => Promise<DataPlaneResponse> | DataPlaneResponse

/** 一条拒绝的响应体。`anp_code` **MUST** 存在（§12 L1082），另外带上码值与消息——
 *  没有 JSON-RPC 信封，这是客户端唯一能据以分支的东西。 */
function problem(
  status: number,
  name: AttachmentErrorName,
  message: string,
  details?: Record<string, unknown>,
): DataPlaneResponse {
  const rejection = attachmentError(name, message, details)
  return {
    status,
    contentType: 'application/json',
    body: JSON.stringify({
      error: rejection.message,
      code: rejection.code,
      anp_code: rejection.anpCode,
      ...(rejection.details !== undefined ? { data: rejection.details } : {}),
    }),
    headers: status === 401 ? { 'www-authenticate': 'Bearer' } : {},
  }
}

/** §9.5 L704–705：票据**MUST** 通过 `Authorization` 头传输，**MUST NOT** 通过 URL 查询
 *  参数承载。所以这里只看头——`?ticket=` 一类的东西连读都不读。 */
function bearerToken(header: string | undefined): string | undefined {
  if (header === undefined) return undefined
  const matched = /^Bearer[ \t]+(\S+)$/i.exec(header.trim())
  return matched?.[1]
}

export function createDataPlane(deps: DataPlaneDeps): {
  handleUpload: DataPlaneHandler
  handleObject: DataPlaneHandler
} {
  const now = deps.now ?? ((): Date => new Date())

  /**
   * `PUT {upload_uri}`（§11.1 L1045–1052）。
   *
   * 这一次请求**没有** `origin_proof`，也不能有：它是普通 HTTP 客户端发的，`upload_headers`
   * 指的是 HTTP 头。它全部的凭据就是 URL 里那段只在 `create_slot` 响应里出现过一次的
   * 令牌，所以这里的鉴权就是拿它查一行。
   */
  const handleUpload: DataPlaneHandler = async (request) => {
    const slot = deps.storage.attachmentSlotByUploadToken(request.resource)
    if (slot === undefined) {
      return problem(404, 'slotNotFound', 'unknown upload token', { slot_id: request.resource })
    }
    const at = now().toISOString()
    if (Date.parse(slot.expiresAt) <= Date.parse(at)) {
      return problem(410, 'slotExpired', `upload slot expired at ${slot.expiresAt}`, {
        attachment_id: slot.attachmentId,
        slot_id: slot.slotId,
      })
    }
    // §10.1 L808–824 的状态机里 Aborted 是终态。6000 的原话是"未找到**可用** Upload
    // Slot"，一个已废弃的槽位不再可用。
    if (slot.state === 'aborted') {
      return problem(404, 'slotNotFound', 'upload slot was aborted', {
        attachment_id: slot.attachmentId,
        slot_id: slot.slotId,
      })
    }
    // 已经收完一次的对象不接受第二次 PUT：状态机上没有 Uploaded → Uploading 这条边。
    // 让它重传会得到一个新摘要，而 `commit_object` 声明的摘要必须对得上**那一次**收到的
    // 字节——重传把"声明的"与"在暂存区里的"之间的关系变成了谁最后说话谁算。要重来就
    // `abort_object` 之后再 `create_slot`。
    if (slot.state !== 'pending') {
      return problem(404, 'slotNotFound', `upload slot is ${slot.state}, not accepting an upload`, {
        attachment_id: slot.attachmentId,
        slot_id: slot.slotId,
      })
    }

    let staged
    try {
      staged = await deps.objects.accept(slot.slotId, request.body)
    } catch (err) {
      // 6003（§12 L1091）。上限与消息体的上限是两个数：信封是几 KiB 量级，对象是几 MiB
      // 量级（`config.ts` 的 `DEFAULT_MAX_OBJECT_BYTES`）。
      if (err instanceof ObjectTooLargeError) {
        return problem(413, 'objectTooLarge', `object exceeds the ${String(err.limit)} byte limit`, {
          attachment_id: slot.attachmentId,
          slot_id: slot.slotId,
        })
      }
      throw err
    }
    // 记下收到的字节数与摘要，同时推进到 `uploaded`。`commit_object` 之后就拿这一行判
    // 声明对不对得上（§10.3.2 L925）。
    deps.storage.recordAttachmentUpload(slot.attachmentId, slot.slotId, staged.size, staged.digest)
    return { status: 200 }
  }

  /**
   * `GET {object_uri}`（§11.2 L1053–1062）。
   *
   * 顺序是先票据、再对象：票据是凭据，先判它，一个没有凭据的请求不该从对象的状态里读出
   * 任何东西——哪怕只是"这个对象在不在"。
   */
  const handleObject: DataPlaneHandler = (request) => {
    const token = bearerToken(request.headers.authorization)
    if (token === undefined) {
      return { status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'missing bearer ticket' }), headers: { 'www-authenticate': 'Bearer' } }
    }
    // 按令牌的 SHA-256 查行。台账里没有明文，所以这里也只能按摘要查（`attachments.md` §7）。
    const ticket = deps.storage.downloadTicket(sha256b64u(token))
    // 不认识的令牌、已被作废的令牌，都是 §12 L1095 那句"缺失、非法、无法解析，或已被作废"
    // ——这一族在本服务里**只有数据面**会发，控制面那一侧是签发，此时还没有令牌可判。
    if (ticket === undefined) {
      return problem(401, 'downloadTicketInvalid', 'unknown download ticket')
    }
    const at = now().toISOString()
    if (Date.parse(ticket.expiresAt) <= Date.parse(at)) {
      return problem(410, 'ticketExpired', `download ticket expired at ${ticket.expiresAt}`, {
        attachment_id: ticket.attachmentId,
        object_uri: ticket.objectUri,
        message_id: ticket.messageId,
      })
    }

    // 票据绑的是哪一个对象，由**我们**拼出来的那个字符串说了算：路由段只是它的一段，
    // 拼法与 `create_slot` 铸它的时候是同一个函数。
    const objectUri = objectUriFor(deps.publicUrl, request.resource)
    if (ticket.objectUri !== objectUri) {
      return problem(403, 'ticketBindingMismatch', 'the ticket is not bound to this object', {
        attachment_id: ticket.attachmentId,
        object_uri: ticket.objectUri,
        message_id: ticket.messageId,
      })
    }

    // 一次性的票据：**用一次原子操作**把它划掉，"查过没被用"与"标记为已用"之间不能有缝，
    // 否则两个并发请求都会从那条缝里过去。`consumeDownloadTicket` 的 `changes` 就是答案。
    if (ticket.oneTime && !deps.storage.consumeDownloadTicket(ticket.tokenHash, at)) {
      return problem(401, 'downloadTicketInvalid', 'the one-time ticket has already been redeemed')
    }

    // §10.1 L826：拿到 `object_uri` 不等于对象可用。只有提交过的槽位才有对象，而槽位可能
    // 早就过期、被废弃，或者根本没上传完。
    const slot = deps.storage.attachmentSlotByObjectUri(objectUri)
    if (slot === undefined || slot.state !== 'committed' || slot.digest === undefined) {
      return problem(404, 'objectUnavailable', 'no committed object at this uri', {
        attachment_id: ticket.attachmentId,
        object_uri: objectUri,
        message_id: ticket.messageId,
      })
    }
    const object = deps.storage.attachmentObject(slot.digest)
    const read = deps.objects.open(slot.digest)
    if (object === undefined || read === undefined) {
      return problem(404, 'objectUnavailable', 'the object bytes are not available', {
        attachment_id: ticket.attachmentId,
        object_uri: objectUri,
        message_id: ticket.messageId,
      })
    }

    return {
      status: 200,
      // §7.3 L455 的 `mime_type` 是**对端**给的。按它原样回 `Content-Type` 就等于让对端在
      // 我们这个域名下挑渲染上下文——一个 `text/html` 的对象就是同源下的一个页面。规范没说
      // 数据面该回什么头，这是本服务的选择（`attachments.md` §3.2）。
      contentType: 'application/octet-stream',
      headers: {
        'content-disposition': 'attachment',
        'x-content-type-options': 'nosniff',
      },
      stream: { read, length: object.size },
    }
  }

  return { handleUpload, handleObject }
}
