// C11 —— 跨域请求的**同步**出站（P8 §3.2）。请求有人在等答复，所以它不走 outbox。
//
// 为什么必须同步，一句话：§6.7 L464 要求联邦服务**原样保留**最终服务返回的 DID 迁移错误
// （`anp.did_superseded` + `current_did`），而"原始调用方负责验证迁移、重建字段、重新签名
// 并重试"——重签名要私钥，私钥在 agent 手里，不在域名服务手里（§7.2 L492）。异步 outbox 在
// 受理那一刻就已经答复过调用方了，之后再没有通道能把那个错误送回去，而 §6.7 是 MTI 第 14 项。
//
// 于是顺序是（§3.2）：**事务外转发 → 对端接受 → 事务内受理落库 → 答复**。对端拒绝时
// **不落库**，调用方拿同一个 `operation_id` 重试就是干净的一次。
//
// 这个文件只回答三个问题：目标服务是不是自己、对端那段字节是什么、把它翻译成本服务对
// 调用方的答复。它不知道 `direct.send` 的正文规则，也不知道怎么落库。

import {
  ANP_ERRORS,
  discoverMessageService,
  DidServiceLocator,
  type AnpErrorObject,
  type AnpRejection,
  type AnpRequest,
  type LocateOptions,
  type ServiceLocator,
} from '@agentx/core'
import type { Config } from '../config'
import { isOurOwnIngress } from '../http/server'
import type { Egress, EgressAnswer } from './egress'

/** 一次出站路由的结果。三分，因为调用方对这三件事的处理各不相同。 */
export type ForwardOutcome =
  /** 目标就是本服务：按本地办完，一个 HTTP 都不用发（§3.3）。 */
  | { kind: 'local' }
  /** 对端收下了。`result` 是它那一份 §7.1.3 的结果，**原样**交回调用方。 */
  | { kind: 'answered'; result: Record<string, unknown> }
  /** 这次调用没有被受理。要么对端拒了（它自己的错误对象，原样），要么这一趟根本没走通。 */
  | { kind: 'refused'; rejection: AnpRejection }

export interface Relay {
  /** 把一次已经通过本地认证与正文校验的请求送到 `targetDid` 的入口服务。 */
  forward(request: AnpRequest, targetDid: string): Promise<ForwardOutcome>
}

export interface RelayOptions {
  config: Config
  egress: Egress
  /** 默认 core 的 `DidServiceLocator`。与 `delivery/worker.ts` 同一个口子：测试拿它回答
   *  "对端的入口在哪"，不必上网。 */
  locator?: ServiceLocator
  /** 与解析文档、推送通知共用的网络策略。默认取 `config.didResolution`。 */
  locateOptions?: LocateOptions
  log?: (line: string) => void
}

/**
 * "这一趟没走通"要说成什么。
 *
 * 用 1012 `anp.temporarily_unavailable`，**不另造名字**：§2.4 已经因为同样的理由拒绝过
 * 自己编 `anp_code`（另造一套没有出处的名字），而这里也确实符合 1012 的语义——目标可能
 * 存在，只是我们这一刻够不着（对端文档解析不出来、外层被拒、网络不通）。
 *
 * 也**不**折叠成成功：§6.6 L456–458 禁止任何形式的静默降级。对端的错误对象（下面那条
 * 分支）走的是另一条路，它原样穿过。
 */
function unavailable(message: string, details?: Record<string, unknown>): AnpRejection {
  return {
    code: ANP_ERRORS['anp.temporarily_unavailable'],
    anpCode: 'anp.temporarily_unavailable',
    retryable: true,
    message,
    ...(details !== undefined ? { details } : {}),
  }
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** 对端回的**响应**：一个有 `result` 或 `error` 的 JSON-RPC 对象。 */
interface RelayedResponse {
  error?: AnpErrorObject
  result?: unknown
}

/** 只认形状，不认 `jsonrpc` 字段：§5.4 L181 那个版本号是出站信封的属性，而对端回什么
 *  是它的事。缺了 `jsonrpc` 不改变"这是一个响应"这件事。 */
function asResponse(body: unknown): RelayedResponse | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined
  const candidate = body as Record<string, unknown>
  if (typeof candidate.error === 'object' && candidate.error !== null) {
    return { error: candidate.error as AnpErrorObject }
  }
  if ('result' in candidate) return { result: candidate.result }
  return undefined
}

/**
 * 把对端的错误对象装回本服务的拒形。
 *
 * 重建而不是透传原始 JSON，是为了让"线上的错误对象长什么样"始终只有一个定义
 * （core 的 `toErrorObject`）。§10.2 把 `data` 定成恰好那三个键，所以重建是无损的：
 * 多出来的键本来就不合规。`retryable` 取对端说的那一个——那是它的判断，比我们的准。
 */
function relayed(rejection: AnpErrorObject): AnpRejection {
  const data = (rejection.data ?? {}) as Record<string, unknown>
  const anpCode = typeof data.anp_code === 'string' ? data.anp_code : undefined
  const details = typeof data.details === 'object' && data.details !== null
    ? (data.details as Record<string, unknown>)
    : undefined
  return {
    code: rejection.code,
    ...(anpCode !== undefined ? { anpCode } : {}),
    retryable: typeof data.retryable === 'boolean' ? data.retryable : false,
    message: rejection.message,
    ...(details !== undefined ? { details } : {}),
  }
}

export function createRelay(options: RelayOptions): Relay {
  const { config, egress } = options
  const locator = options.locator ?? new DidServiceLocator()
  const locateOptions = options.locateOptions ?? config.didResolution
  const log = options.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))

  return {
    async forward(request: AnpRequest, targetDid: string): Promise<ForwardOutcome> {
      let endpoint: string
      try {
        const target = await discoverMessageService(targetDid, { locator, ...locateOptions })
        endpoint = target.endpoint
      } catch (err) {
        // 解析不出目标的入口服务：可能没有那条 service 条目，也可能它在我们够不着的
        // 域里（`AGENTX_ALLOWED_DID_HOSTS` 是空的时候，任何远程解析都到不了这里）。
        log(`anp: cannot locate an ANPMessageService for ${targetDid}: ${describe(err)}`)
        return {
          kind: 'refused',
          rejection: unavailable(`no reachable ANPMessageService for the target (${describe(err)})`),
        }
      }

      // 端点解不出来时 `isOurOwnIngress` 会抛（对端的文档把 `serviceEndpoint` 写坏了）。
      // 那是**对端**的问题，不是本服务的内部错误：接住它，说成 1012，别让它冒到最外面
      // 被当成 -32603 报出去——那样调用方会以为是我们坏了，而重试是对的。
      let own: boolean
      try {
        own = isOurOwnIngress(config, endpoint)
      } catch (err) {
        log(`anp: the ANPMessageService entry for ${targetDid} has an unusable serviceEndpoint: ${describe(err)}`)
        return {
          kind: 'refused',
          rejection: unavailable(`the target service entry has an unusable serviceEndpoint (${describe(err)})`),
        }
      }
      if (own) return { kind: 'local' }

      let answer: EgressAnswer
      try {
        answer = await egress.post(endpoint, request)
      } catch (err) {
        // 传输出错（连不上、超时、字节超限）。这**不是**对端的答复，所以这里没有对端的
        // 错误对象可保留——只有我们自己的观察。§2.4 分的就是这两件事。
        log(`anp: forwarding ${request.method} to ${endpoint} failed: ${describe(err)}`)
        return {
          kind: 'refused',
          rejection: unavailable(`could not reach ${endpoint} (${describe(err)})`),
        }
      }

      // §2.4：非 2xx **是答复**，它说的是"我不收这一次"。按 §6.6 不能静默降级成成功，
      // 而这一层也没有别的状态对象可以用——把状态原样写进 details，日志里写全。
      if (answer.status < 200 || answer.status >= 300) {
        log(`anp: forwarding ${request.method} to ${endpoint} refused with HTTP ${answer.status}`)
        return {
          kind: 'refused',
          rejection: unavailable(`the target service answered HTTP ${answer.status}`, {
            status: answer.status,
          }),
        }
      }

      const response = asResponse(answer.body)
      if (response === undefined) {
        log(`anp: forwarding ${request.method} to ${endpoint} got a body that is not a JSON-RPC response`)
        return {
          kind: 'refused',
          rejection: unavailable('the target service answered with something that is not a JSON-RPC response'),
        }
      }
      // 对端自己的拒绝——包括 §6.7 那个 `anp.did_superseded`——原样走回调用方。这里是
      // 整个联邦层最不能"顺手翻译一下"的一处：`current_did` 与 `retryable` 是原始调用方
      // 重建请求所必需的，而重建只能由持有私钥的那一方做。
      if (response.error !== undefined) return { kind: 'refused', rejection: relayed(response.error) }

      const result = response.result
      if (typeof result !== 'object' || result === null || Array.isArray(result)) {
        log(`anp: forwarding ${request.method} to ${endpoint} returned a non-object result`)
        return {
          kind: 'refused',
          rejection: unavailable('the target service returned a result that is not an object'),
        }
      }
      return { kind: 'answered', result: result as Record<string, unknown> }
    },
  }
}
