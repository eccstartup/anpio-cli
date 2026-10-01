// C5 —— 受理一条 `direct.send`。
//
// 这一步是把前面几块串起来的地方，别处都不做顺序判断：信封（§3）、方法自己的 MUST（§3
// 剩的两行）、认证（§5）、正文（P3 §6）、幂等（§9）。顺序写在下面 `handle` 的一个直线
// 流程里，因为**顺序本身是规范要求的一部分**——§9.2 L650 要求先查操作级幂等记录，而
// C4 的 `perform` 只在未命中时被调用，两件事必须一起看才成立。
//
// 与 HTTP 层的关系：`http/server.ts` 只管路由和读体，拿到文本就交给这里；这里负责把
// 每一种结局都变成一份带正确 `id` 的 JSON-RPC 响应。所以本模块里不该出现 `req` / `res`。

import {
  contentDigestOf,
  DidKeyResolver,
  idempotencyKey,
  idempotencyScopeFromMeta,
  JSON_RPC_ERROR,
  rpcRejection,
  signedRequestObject,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
  type KeyResolver,
  type LocateOptions,
} from '@agentx/core'
import type { Config } from '../config'
import type { RpcHandler, RpcResponse } from '../http/server'
import type { Storage } from '../storage/types'
import { acceptOperation } from './accept'
import { authenticate, callerAnchor } from './auth'
import { DIRECT_SEND, lookupMethod, checkMethod, type MethodSpec } from './methods'
import { storeDirectMessage } from './direct'
import { INBOX_GET, INBOX_MARK_READ, MESSAGE_GET_BATCH, SYNC_DELTA, markRead, readBatch, readDelta, readInbox } from './inbox'
import { errorResponse, failureId, noResponse, parseRequestText, successResponse } from './envelope'

export interface DispatchDeps {
  /** Read for the service's own DID and for {@link DidResolution}, which becomes the
   *  outbound resolver policy. */
  config: Config
  storage: Storage
  /** Defaults to core's `DidKeyResolver`. A test substitutes one that answers from an
   *  inline document, which is what keeps the accept path testable without a network. */
  resolver?: KeyResolver
  /** Passed to the resolver on every verification. Defaults to the config's
   *  `didResolution`, which is the operator's SSRF allowlist. */
  resolverOptions?: LocateOptions
  /** Authentication failures are logged with their reason, which is deliberately NOT
   *  put on the wire (`auth.ts` explains why: answering "was this keyid authorized"
   *  per request is an oracle). */
  log?: (line: string) => void
  /** One instant per request, in two coatings: ISO 8601 for what gets stored, epoch
   *  seconds for the proof's time window (that is the unit `expires` / `created` are
   *  written in, P1 附录 A). Injected in tests so a stored `accepted_at` is a literal. */
  now?: () => Date
}

export function createDispatch(deps: DispatchDeps): RpcHandler {
  const resolver = deps.resolver ?? new DidKeyResolver()
  const resolverOptions = deps.resolverOptions ?? deps.config.didResolution
  const now = deps.now ?? (() => new Date())
  const log = deps.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))

  /**
   * 这个方法收下这次调用的**状态改变**，返回 §7.1.3 的 `result`。
   *
   * 只在幂等未命中时被调用（C4），所以这里不能有无谓的失败面：一次网络往返会让并发写在
   * 事务里等，而写之前任何一步抛错都会把整个操作回滚掉。
   */
  function perform(spec: MethodSpec, params: AnpParams, acceptedAt: string): Record<string, unknown> {
    const { meta, body, auth } = params
    switch (spec.name) {
      case DIRECT_SEND:
        return storeDirectMessage(deps.storage, {
          meta,
          body,
          ...(auth !== undefined ? { auth } : {}),
          acceptedAt,
        })
      case INBOX_GET:
        return readInbox(deps.storage, meta, body)
      case MESSAGE_GET_BATCH:
        return readBatch(deps.storage, meta, body)
      case SYNC_DELTA:
        return readDelta(deps.storage, meta, body)
      case INBOX_MARK_READ:
        return markRead(deps.storage, meta, body, acceptedAt)
      default:
        // 方法表里有它、这里没分支：两张表不一致，是代码错，不是请求错。
        throw new Error(`no handler for ${spec.name}`)
    }
  }

  /**
   * 走完整条受理路径。
   *
   * 每一层的失败都就地回一份响应，不是叠一个异常再在最外面翻译——响应要带上它自己那层
   * 才知道的 `id`，而"哪一层拒的"决定了回哪个码。
   */
  const handle: RpcHandler = async (request) => {
    const text = request.body
    const parsed = parseRequestText(text)
    if (!parsed.ok) return errorResponse(failureId(text, parsed.error), parsed.error)

    const envelope = parsed.value
    // 通知不答（§5.3 L162、§5.6 L201）。用 `'id' in` 而不是 core 的 `isNotification`：
    // 理由写在 `envelope.ts` 里（联合会被守卫收成 `never`）。
    if (!('id' in envelope)) return noResponse()

    const spec = lookupMethod(envelope.method)
    if (spec === undefined) {
      return errorResponse(
        envelope.id,
        rpcRejection(JSON_RPC_ERROR.METHOD_NOT_FOUND, `Method not found: ${envelope.method}`),
      )
    }

    const { meta, body } = envelope.params
    const refused = checkMethod(spec, meta)
    if (refused !== undefined) return errorResponse(envelope.id, refused)

    const at = now()

    // 认证在正文之前：正文校验会读 `content_type` 并据此判断，那个字段是请求方写的，
    // 先让它通过签名再据它判，才不至于拿一个未认证的字段做决定。
    if (spec.requiresOriginProof(meta)) {
      const outcome = await authenticate({
        envelope,
        expectedAnchor: callerAnchor(spec.name, envelope.params),
        resolver,
        resolverOptions,
        codes: spec.authCodes,
        now: Math.floor(at.getTime() / 1000),
      })
      if (!outcome.ok) {
        // 只记方法与原因。`sender_did` 此刻还没被验证过，是一条请求方自己写的话，把它
        // 原样写进日志等于让人往日志里塞任意文本（换行也算）。
        log(`anp: ${spec.name} not authenticated (${outcome.reason})`)
        return errorResponse(envelope.id, outcome.error)
      }
    }

    try {
      const bodyRefusal = bodyRefusalFor(spec, body, meta)
      if (bodyRefusal !== undefined) return errorResponse(envelope.id, bodyRefusal)

      const acceptedAt = at.toISOString()
      const run = (): Record<string, unknown> => perform(spec, envelope.params, acceptedAt)

      // 这个方法不改状态：没有幂等作用域，也就没有要记的操作，直接跑（P1 §9.1 L628 的
      // 四段键里 operation_id 的语义是"重试同一次操作"，无状态调用没有这个东西）。
      if (spec.targetScope === undefined) return successResponse(envelope.id, run())

      const outcome = acceptOperation({
        storage: deps.storage,
        // 键按**请求里写的** `sender_did` 算（§9.1 L641 的另一半：DID 被替代时，重试要用
        // 旧 DID 才查得到；`idempotency.ts` 里有完整的说明）。
        key: idempotencyKey(idempotencyScopeFromMeta({ meta, targetScope: spec.targetScope(meta, body), method: spec.name })),
        // 指纹取 Signed Request Object 的摘要：A.3 L1044–1050 让它只含 method / meta / body，
        // 所以重新签过一次、`auth` 换了、`id` 换了的重试，指纹仍与原请求相同——那正是
        // §9.1 L630 要的"语义等价"。
        fingerprint: await contentDigestOf(signedRequestObject({ method: spec.name, meta, body })),
        perform: run,
      })

      // §10.3 L709：同键不同语义。
      if (outcome.kind === 'conflict') return errorResponse(envelope.id, outcome.error)
      return successResponse(envelope.id, outcome.response)
    } catch (err) {
      // 到这里还没有回应的，只剩"代码错了"这一种：每个已知的拒绝理由都在上面就地回了。
      // 回 -32603（§10.1 L669–675：这类形状 SHOULD 用 JSON-RPC 标准码）而不是把栈发给
      // 对端；栈进日志。
      log(`anp: ${spec.name} failed internally: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`)
      return errorResponse(envelope.id, rpcRejection(JSON_RPC_ERROR.INTERNAL_ERROR, 'Internal error'))
    }
  }

  return handle
}

/**
 * Profile 层对 `body` 的校验，**由方法表自己声明**。
 *
 * 之前这里是按方法名的分支，注释写着"第二个方法的正文规则出现时，那个字段该长什么样
 * 就清楚了"——C6 的取件面就是那第二个（第四、第五个）方法，于是它成了 `MethodSpec` 上
 * 的一个字段。这样"这个方法有哪些正文规则"和"它要哪些 meta 字段"在同一处，不会有一边
 * 改了另一边没改。
 */
function bodyRefusalFor(
  spec: MethodSpec,
  body: Record<string, unknown>,
  meta: AnpMeta,
): AnpRejection | undefined {
  return spec.validateBody?.(body, meta)
}
