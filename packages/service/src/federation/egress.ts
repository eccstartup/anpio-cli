// C11 —— 出站那一跳：把一次跨域调用交给对端的入口服务，并把它的**答复**带回来。
//
// 与 `delivery/worker.ts` 的两处不同，都是 P8 定的：
//
//   1. **任何状态码都是答复**（§2.4）。ANP-02 §3.2.4.1 把外层认证的失败放在 HTTP 状态
//      与 `WWW-Authenticate` 上，不是放进 JSON-RPC 的 `error` 里，所以 401 是一次跑通的
//      交换而不是传输故障。core 的 `postMessage` 对非 2xx 直接抛，正是这一点上不能用
//      ——它会把"我被拒了"和"网络不通"并成同一句话。
//   2. **外层签名**挂在请求上（`federation/signing.ts`）。没有配钥就不签，对端按 §2.3
//      把它当本地调用处理，业务层的 `origin_proof` 照旧是唯一的授权依据。
//
// 网络策略与解析 DID 文档**共用一套闸门**（`LocateOptions`）：目标地址来自对端的文档，
// 是对端选的，不是调用方选的——这一点上它和 DID 文档一样需要白名单与逐跳校验。
// 复用 core 的受控 fetch 而不是自己写一遍，理由在 `resolveDid.ts` 里写着：逐跳校验出现
// 第二份拷贝的地方，就是 SSRF 漏洞最终会出现的地方。

import { randomUUID } from 'node:crypto'
import { fetchControlledResponse, type AnpNotification, type AnpRequest, type FetchErrorCodes, type LocateOptions } from '@anpio-cli/core'
import type { Config } from '../config'
import type { HttpSigner } from './signing'

/** 失败码的措辞沿用消息发送那一套（core 的 `MESSAGE_FETCH_CODES`）：对这些调用方来说，
 *  一次跨域调用发不出去与一次同域推送发不出去是同一件事。 */
const EGRESS_FETCH_CODES: FetchErrorCodes = {
  subject: 'ANP message service',
  blocked: 'message_send_failed',
  failed: 'message_send_failed',
  timeout: 'message_send_failed',
  tooLarge: 'response_too_large',
  tooManyRedirects: 'message_send_failed',
  invalidDocument: 'message_invalid',
}

export interface EgressAnswer {
  status: number
  /** 对端回的头，小写键。挑战头就在这一张里，而它是 401 上唯一有内容的部分。 */
  headers: Record<string, string>
  /** 解析出来的 JSON 正文；对端回的不是 JSON（或没有正文）时是 `undefined`。
   *  **不是异常**：§5.6 允许一个 200 带空 body。 */
  body: unknown
}

export interface Egress {
  /** 一次交换。**不重试**：重试要复用同一个 `operation_id`，那只有调用方知道（§9.1），
   *  而重复发送在这里也不是免费的动作。 */
  post(endpoint: string, request: AnpRequest | AnpNotification): Promise<EgressAnswer>
}

export interface EgressOptions {
  config: Config
  /** 缺省表示这次部署不签外层身份。**不是错误**：§2.3 让不带外层身份的调用方失去的是
   *  域级归属，不是受理资格。 */
  signer?: HttpSigner
  /** 与解析 DID 文档共用的网络策略。默认取 `config.didResolution`。 */
  locateOptions?: LocateOptions
  /** 签名里的 `created`。注入是为了让测试钉住签名的底。 */
  now?: () => number
  /** 每个请求一个的一次性 nonce。 */
  nonce?: () => string
}

function lowercaseHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  headers.forEach((value, name) => {
    out[name.toLowerCase()] = value
  })
  return out
}

export function createEgress(options: EgressOptions): Egress {
  const locateOptions = options.locateOptions ?? options.config.didResolution
  const now = options.now ?? ((): number => Math.floor(Date.now() / 1000))
  const nonce = options.nonce ?? ((): string => randomUUID())

  async function post(endpoint: string, request: AnpRequest | AnpNotification): Promise<EgressAnswer> {
    // 序列化一次、两处用：签名覆盖的就是这些字节，重发一遍 `JSON.stringify` 就有两份
    // 可能不一致的正文。
    const body = JSON.stringify(request)
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
    }
    if (options.signer !== undefined) {
      Object.assign(
        headers,
        await options.signer.headers({ method: 'POST', url: endpoint, body, nonce: nonce(), now: now() }),
      )
    }

    const answer = await fetchControlledResponse(
      endpoint,
      locateOptions,
      EGRESS_FETCH_CODES,
      { method: 'POST', headers, body },
    )
    return {
      status: answer.status,
      headers: lowercaseHeaders(answer.headers),
      body: parseJson(answer.text),
    }
  }

  return { post }
}

/** 空 body 与读不懂的 body 都是 `undefined`——对端回 200 加空 body 是正常的（§5.6），
 *  而一个不是 JSON 的正文在调用方那里与"没有正文"是同一件事：没有可解释的答复。 */
function parseJson(text: string): unknown {
  if (text === '') return undefined
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
