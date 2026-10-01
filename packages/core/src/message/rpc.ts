// ANP-09 P1 §5–§6 —— JSON-RPC over HTTP 的**客户端**半边。
//
// 服务端那一半（校验入站信封、发响应）在 `packages/service`；这里只做三件事：
//
//   1. 把请求 POST 到 `serviceEndpoint`；
//   2. 走**同一份** SSRF 网络策略——`fetchControlledJson` 的带请求体形态。消息的服务
//      端点是从对端 DID 文档里读出来的，主机由对端选定，所以它比 DID 文档那一跳更
//      需要那层逐跳校验，而不是更不需要；
//   3. 判定回来的东西是不是一个合规的 JSON-RPC 响应（§5.6）。
//
// 它与 `envelope.ts` 的分工：那边知道信封**长什么样**，这边知道信封**怎么走**。
// 把两者分开，是为了让服务端能只 import 前者。

import { ConnectxError } from '../errors'
import { fetchControlledJson } from '../crypto/resolveDid'
import type { FetchErrorCodes, ResolveDidOptions } from '../crypto/resolveDid'
import type { AnpErrorResponse, AnpRequest, AnpResponse, AnpSuccessResponse } from './envelope'
import { JSONRPC_VERSION } from './envelope'

/**
 * 一次消息交换失败时用的错误码。
 *
 * 前五项都落到 `message_send_failed`，因为对调用方而言它们是同一件事：**这次 HTTP
 * 交换没有完成**。对端真正的拒绝不走这里（那是一个 2xx 里带 `error` 成员的响
 * 应，见 {@link postMessage} 的返回值），它自己的 `anp_code` 才是可分支的信号。
 * 唯一分开的是体积：那是一个关于数据的事实，不是关于交换的。
 */
export const MESSAGE_FETCH_CODES: FetchErrorCodes = {
  subject: 'ANP message service',
  blocked: 'message_send_failed',
  failed: 'message_send_failed',
  timeout: 'message_send_failed',
  tooLarge: 'response_too_large',
  tooManyRedirects: 'message_send_failed',
  invalidDocument: 'message_invalid',
}

const JSON_RPC_HEADERS = {
  'content-type': 'application/json',
  accept: 'application/json',
}

/**
 * POST 一个请求给 ANP Endpoint，回它的响应对象。
 *
 * **对端的拒绝不抛异常**：§5.6 L202–203 规定失败响应是一个带 `error` 的 2xx 体，
 * 那是协议正常跑通的一部分，而不是传输故障。把它抛掉，`anp.did_superseded` 这类
 * 需要按 `anp_code` 分派的答复就只剩下一句人话。真正抛的是三件事：网络/策略层失败、
 * 回来的东西不是 JSON-RPC 响应、或者响应的 `id` 与请求不一致（§5.6 L204）。
 *
 * 不做鉴权、不签 `auth`、不重试——那些是调用方的事，而且重试要复用同一个
 * `operation_id`，只有调用方知道那是什么。
 */
export async function postMessage(
  endpoint: string,
  request: AnpRequest,
  options: ResolveDidOptions = {},
): Promise<AnpResponse> {
  const raw = await fetchControlledJson(endpoint, options, MESSAGE_FETCH_CODES, {
    method: 'POST',
    headers: JSON_RPC_HEADERS,
    body: JSON.stringify(request),
  })

  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConnectxError(
      'message_invalid',
      `ANP message service at ${endpoint} did not answer with a JSON-RPC response object`,
    )
  }
  const response = raw as Record<string, unknown>
  if (response.jsonrpc !== JSONRPC_VERSION) {
    throw new ConnectxError(
      'message_invalid',
      `ANP message service at ${endpoint} answered with jsonrpc ${JSON.stringify(response.jsonrpc)}; it MUST be exactly "2.0" (P1 §4.1 L127)`,
    )
  }
  // §5.6 L204：响应 id MUST 与请求 id 完全一致。这条把"回的是不是我这一个请求"钉住，
  // 否则一个中间层的缓存或串答会把别人的结果当成自己的。
  if (response.id !== request.id) {
    throw new ConnectxError(
      'message_invalid',
      `ANP message service at ${endpoint} answered id ${JSON.stringify(response.id)} for request id ${JSON.stringify(request.id)}; they MUST match (P1 §5.6 L204)`,
    )
  }

  const hasError = Object.prototype.hasOwnProperty.call(response, 'error')
  const hasResult = Object.prototype.hasOwnProperty.call(response, 'result')
  // §5.6 L202–203：成功 MUST 有 result 且 MUST NOT 有 error；失败反之。两个都有或
  // 都没有，都是"这不是一个我们能解释的响应"。
  if (hasError === hasResult) {
    throw new ConnectxError(
      'message_invalid',
      `ANP message service at ${endpoint} answered with ${hasError ? 'both' : 'neither'} of result and error (P1 §5.6 L202)`,
    )
  }

  if (!hasError) return raw as AnpSuccessResponse

  const error = response.error
  if (typeof error !== 'object' || error === null || Array.isArray(error)) {
    throw new ConnectxError('message_invalid', `ANP message service at ${endpoint} answered with a non-object error`)
  }
  const obj = error as Record<string, unknown>
  if (typeof obj.code !== 'number' || typeof obj.message !== 'string') {
    throw new ConnectxError(
      'message_invalid',
      `ANP message service at ${endpoint} answered with an error object missing code or message (P1 §10.2)`,
    )
  }
  return raw as AnpErrorResponse
}

/**
 * 一个失败响应里的 `anp_code`（§10.2 L687–695：只在 `code` 落在 ANP 自定义段时才有）。
 *
 * 单独一个读出器，是为了让调用方不必知道它藏在 `error.data` 下、也不必每次重写那段
 * `typeof` 判断。它**不**把标准码（-32xxx）翻译成 ANP 码：那一段本来就靠 `message`
 * 区分，硬塞一个等价的 `anp_code` 等于发明规范里没有的对应关系。
 */
export function anpCodeOf(response: AnpErrorResponse): string | undefined {
  const data = response.error.data
  return typeof data?.anp_code === 'string' ? data.anp_code : undefined
}
