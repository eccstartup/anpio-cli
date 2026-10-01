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
  anpRejection,
  contentDigestOf,
  DidDeviceResolver,
  DidKeyResolver,
  DidServiceLocator,
  idempotencyKey,
  idempotencyScopeFromMeta,
  JSON_RPC_ERROR,
  rpcRejection,
  signedRequestObject,
  type AnpLoginFailure,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
  type AnpRequest,
  type DeviceResolver,
  type KeyResolver,
  type LocateOptions,
  type NonceStore,
  type ServiceLocator,
} from '@agentx/core'
import type { Config } from '../config'
import { capabilitiesResult } from '../capabilities'
import type { ForwardOutcome, Relay } from '../federation/forward'
import { createHttpNonceStore } from '../federation/nonces'
import { challengeHeader, verifyOuterIdentity } from '../federation/outer'
import type { RpcHandler, RpcResponse } from '../http/server'
import type { DeliveryRecord, Storage } from '../storage/types'
import { acceptOperation } from './accept'
import { authenticate, callerAnchor } from './auth'
import { DIRECT_SEND, GET_CAPABILITIES, lookupMethod, checkMethod, type MethodSpec } from './methods'
import { storeDirectMessage } from './direct'
import type { DeviceAddressed, EligibleDevice } from './eligibility'
import { checkDevice, deviceSelector, isRejection } from './eligibility'
import {
  GET_PREKEY_BUNDLE,
  PUBLISH_PREKEY_BUNDLE,
  getPrekeyBundle,
  publishPrekeyBundle,
  type KeyContext,
} from './keys'
import { callerKeyOf, createRateLimiter } from './rateLimit'
import { GROUP_HANDLERS } from './groups'
import { ATTACHMENT_HANDLERS } from './attachments'
import type { ObjectStore } from '../objects'
import { AnpRefusal } from './refusal'
import { INBOX_GET, INBOX_MARK_READ, MESSAGE_GET_BATCH, SYNC_DELTA, markRead, readBatch, readDelta, readInbox } from './inbox'
import { errorResponse, failureId, noResponse, parseRequestText, successResponse } from './envelope'

/** 目标就是本服务（§3.3）。一个共享的常量：它没有内容，没必要每次现造一个。 */
const LOCAL: ForwardOutcome = { kind: 'local' }

export interface DispatchDeps {
  /** Read for the service's own DID and for {@link DidResolution}, which becomes the
   *  outbound resolver policy. */
  config: Config
  storage: Storage
  /**
   * 附件对象的字节（P7，C10）。
   *
   * **必填而不是可选**：`attachment.create_slot` 一进方法表，`anp.attachment.v1` 就出现在
   * `.well-known` 与 `anp.get_capabilities` 里（能力是从方法表推出来的）。一个宣告实现了
   * 这个 Profile、却在 `commit_object` 上无处落字节的服务，比一个不宣告它的服务坏得多。
   * 所以要么给，要么那四条方法不该在表里。
   */
  objects: ObjectStore
  /** Defaults to core's `DidKeyResolver`. A test substitutes one that answers from an
   *  inline document, which is what keeps the accept path testable without a network. */
  resolver?: KeyResolver
  /** Passed to the resolver on every verification. Defaults to the config's
   *  `didResolution`, which is the operator's SSRF allowlist. */
  resolverOptions?: LocateOptions
  /** Resolves a caller anchor's DID document to its service entries — P8 §6.2.2 steps 2–3.
   *  Defaults to core's `DidServiceLocator`; a test substitutes one that answers from an
   *  inline document, which is what keeps the cross-domain path testable without a network. */
  locator?: ServiceLocator
  /** Reads a DID's `deviceManifest` to answer "is this device eligible right now"
   *  (P5 §4.1.1). Defaults to core's `DidDeviceResolver`; a test substitutes one that
   *  answers from an inline document, same reason as `resolver` and `locator`. */
  deviceResolver?: DeviceResolver
  /** 跨域外层签名的重放缓存（P8 §6.2.2 第 8 步、federation.md §2.2）。默认为本服务自己
   *  `Storage` 上的 `http_nonces` 表。 */
  nonceStore?: NonceStore
  /**
   * 跨域请求的同步出站（P8 §3.2）。
   *
   * 缺席时 `direct.send` 一律当成同域受理——这是**测试的缝**，不是部署的档位：`main.ts`
   * 总是把它接上，因为"收件人不在本服务上而我们当本地收下了"是一种会静默走错域的行为，
   * 不该有一个开关能把它打开。与 `locator` / `nonceStore` 同一个理由：不让每个用例都
   * 起一个出站 HTTP。
   */
  relay?: Relay
  /** Authentication failures are logged with their reason, which is deliberately NOT
   *  put on the wire (`auth.ts` explains why: answering "was this keyid authorized"
   *  per request is an oracle). */
  log?: (line: string) => void
  /** One instant per request, in two coatings: ISO 8601 for what gets stored, epoch
   *  seconds for the proof's time window (that is the unit `expires` / `created` are
   *  written in, P1 附录 A). Injected in tests so a stored `accepted_at` is a literal. */
  now?: () => Date
  /**
   * A delivery to hand to the subscription path (realtime.md §8.1). Called **after** the
   * transaction that wrote it has committed, and only for the request that created it — a
   * replay appends nothing new and therefore publishes nothing.
   *
   * `main.ts` points this at the subscriber registry. It arrives as a plain callback
   * rather than as the registry itself so the accept path keeps no reference to the
   * transport, which is what lets `dispatch.test.ts` run without a socket.
   */
  onDelivered?: (record: DeliveryRecord) => void
}

export function createDispatch(deps: DispatchDeps): RpcHandler {
  const resolver = deps.resolver ?? new DidKeyResolver()
  const relay = deps.relay
  const resolverOptions = deps.resolverOptions ?? deps.config.didResolution
  const locator = deps.locator ?? new DidServiceLocator()
  const deviceResolver = deps.deviceResolver ?? new DidDeviceResolver()
  const nonceStore = deps.nonceStore ?? createHttpNonceStore(deps.storage)
  const now = deps.now ?? (() => new Date())
  const log = deps.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  // `config.publicUrl` 已经过 `normalizeUrl`，保证是一个绝对的 http(s) URL（配置层拒过别的）。
  // 外层签名覆盖的是 `@target-uri`，而那是一个绝对 URI——scheme 只能来自部署声明：本服务
  // 自己是明文监听，落在 TLS 终止后面时客户端签的是 `https`，从 socket 上看不出来。
  const publicUrl = new URL(deps.config.publicUrl)
  // P5 §7.3 L598 的落点。记分板只有一块，两条 Key 方法共用——§7.3 那一节讲的是"发放
  // PreKey 材料"这一件事，把两条分开计数会让"发布完立刻领取"吃两份额度，而对服务端来说
  // 那是同一个调用方在干同一件事。见 `rateLimit.ts` 的文件头。
  const prekeyLimiter = createRateLimiter(deps.config.prekeyRate)

  /**
   * 一次 `perform` 需要的、在事务**外**就已经拿到的东西。
   *
   * 收成一个对象而不是六个位置参数：`devices` 是这一块新加的，而位置参数每加一个都要改
   * 所有调用点，且两个 `string` 挨在一起时传反了编译器不会说话。
   */
  interface PerformInput {
    params: AnpParams
    acceptedAt: string
    pending: DeliveryRecord[]
    requestDigest: string
    relayed?: Record<string, unknown>
    /**
     * 这次调用点名的设备，顺序同 `DeviceAddressed.pairs`，且都已判过 §4.1.1 资格。
     *
     * 不是设备定址的调用（以及跨域）这里是空的。重放也到不了这里——`acceptOperation` 命中
     * 同键时根本不调 `perform`，所以两条 Key 方法的处理器可以当它一定填满。
     */
    devices: readonly EligibleDevice[]
  }

  /**
   * 这个方法收下这次调用的**状态改变**，返回 §7.1.3 的 `result`。
   *
   * 只在幂等未命中时被调用（C4），所以这里不能有无谓的失败面：一次网络往返会让并发写在
   * 事务里等，而写之前任何一步抛错都会把整个操作回滚掉。
   */
  function perform(spec: MethodSpec, input: PerformInput): Record<string, unknown> {
    const { meta, body, auth } = input.params
    switch (spec.name) {
      case GET_CAPABILITIES:
        // 只读、且是匿名可达的：答复里没有一处与调用方身份相关，所以这就是全部。
        return capabilitiesResult(deps.config)
      case DIRECT_SEND:
        return storeDirectMessage(deps.storage, {
          meta,
          body,
          ...(auth !== undefined ? { auth } : {}),
          acceptedAt: input.acceptedAt,
          ...(input.relayed !== undefined ? { relayed: input.relayed } : {}),
          // Collected, not published: this runs inside the transaction, and a delivery
          // pushed from here would have been seen by a live client before a rollback could
          // undo it. The caller publishes once `acceptOperation` has returned.
          onDelivery: (record) => input.pending.push(record),
        })
      // P5 §7 那两条。它们与上面几个不同：要的是**事务外**解析出来的设备（文档 + 条目），
      // 因为 Bundle 的 Object Proof 只能拿 issuer 文档验，而那个解析不能在事务里做。
      case PUBLISH_PREKEY_BUNDLE:
        return publishPrekeyBundle(keyContext(input))
      case GET_PREKEY_BUNDLE:
        return getPrekeyBundle(keyContext(input))
      case INBOX_GET:
        return readInbox(deps.storage, meta, body)
      case MESSAGE_GET_BATCH:
        return readBatch(deps.storage, meta, body)
      case SYNC_DELTA:
        return readDelta(deps.storage, meta, body)
      case INBOX_MARK_READ:
        return markRead(deps.storage, meta, body, input.acceptedAt)
      default: {
        // `group.*` 与 `attachment.*` 两族都不在这里逐个枚举：它们的处理器按方法名查
        // （`groups.ts` / `attachments.ts`），因为同族的方法在这一层完全同形，逐个写一个
        // `case` 只是把同一段构造抄若干遍，而漏抄一个的表现是"某个方法莫名 500"。查不到
        // 才是不一致——方法表里有它，处理器表里没有。
        const group = GROUP_HANDLERS[spec.name]
        if (group !== undefined) {
          return group({
            storage: deps.storage,
            serviceDid: deps.config.serviceDid,
            meta,
            body,
            ...(auth !== undefined ? { auth } : {}),
            acceptedAt: input.acceptedAt,
            // 与幂等指纹是**同一个**摘要：`group_receipt.payload_digest` 要证明的就是
            // "这次被受理的请求是这一份"，而 §9.1 的指纹要判的也是同一件事。各算一次除了
            // 多一趟哈希，还留下两处会各自漂移的定义。
            requestDigest: input.requestDigest,
            onDelivery: (record) => input.pending.push(record),
          })
        }
        const attachment = ATTACHMENT_HANDLERS[spec.name]
        if (attachment !== undefined) {
          return attachment({
            storage: deps.storage,
            serviceDid: deps.config.serviceDid,
            publicUrl: deps.config.publicUrl,
            objects: deps.objects,
            meta,
            body,
            acceptedAt: input.acceptedAt,
          })
        }
        // 方法表里有它、这里两处都没有分支：两张表不一致，是代码错，不是请求错。
        throw new Error(`no handler for ${spec.name}`)
      }
    }
  }

  /**
   * 一次 Key 调用要的上下文。`devices` 是事务外解析出来的，**不重解析**：同一次请求里解析
   * 两遍会得到两份可能不同的文档，而 Bundle 的 proof 只能对着**其中一份**验。
   *
   * 空数组是到不了的：`checkMethod` 保证 `sender_did` / `sender_device_id` / `target` 在场，
   * 于是 `addressed` 一定不是 `undefined`，资格那一步也就一定跑过。真空了是代码错——让
   * `keys.ts` 的 `device()` 抛出来，比在这里静默降级成"没有设备"好。
   */
  function keyContext(input: PerformInput): KeyContext {
    return {
      storage: deps.storage,
      serviceDid: deps.config.serviceDid,
      meta: input.params.meta,
      body: input.params.body,
      acceptedAt: input.acceptedAt,
      devices: input.devices,
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
    // 一次请求一个时刻。取在最前面而不是临用临取：限流、证明的时间窗、`accepted_at` 三处
    // 都读它，各读一次会得到三个时刻，而"这一次调用是什么时候"必须只有一个答案。
    const at = now()

    // P8 §6.2.2 的八步跑在 JSON-RPC **之前**（federation.md §2.4），所以它排在方法表、
    // 排在这个通知短路之前：一份跨域通知被拒时，对端要拿到的是 401，而不是"没有响应"。
    // 没带外层身份的请求在这里原样放过——那是本地调用，业务动作仍由 `origin_proof` 授权
    // （§2.3，代价写在 federation.md 里）。
    //
    // 顺手接出**认证过的**调用方身份（见下面限流那一段）。只有 `verified` 那一档算数：
    // `absent` 是"同域明文，没有任何外层身份"，`refused` 已经在这里回掉了。
    let authenticatedCaller: string | undefined
    if (request.method !== undefined) {
      const outer = await verifyOuterIdentity({
        method: envelope.method,
        params: envelope.params,
        http: {
          method: request.method,
          path: request.url.pathname,
          search: request.url.search,
          // 客户端寻址的是哪个 authority，它签的就是哪个：`host` 头，不是本服务的监听地址。
          authority: request.headers.host ?? '',
          headers: request.headers,
          body: text,
        },
        scheme: publicUrl.protocol,
        resolver,
        locator,
        locateOptions: resolverOptions,
        nonceStore,
      })
      if (outer.kind === 'refused') {
        // `reason` 只进日志。逐条答出去等于给对端一个"哪一步没过"的探针，而 ANP-02
        // §3.2.4.1 已经把这件事用一个 `error` 值表示完了。
        log(`anp: ${envelope.method} refused at the outer layer (${outer.error}: ${outer.reason})`)
        return outerRefusal(publicUrl.hostname, outer.error)
      }
      if (outer.kind === 'verified') authenticatedCaller = outer.serviceDid
    }

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
    const refused = checkMethod(spec, envelope.params)
    if (refused !== undefined) return errorResponse(envelope.id, refused)

    // P5 §7.3 L598：密钥控制面的限流。位置在方法表之后、正文校验之前——`meta.sender_did`
    // 到这里才被 `requiredMeta` 保证在场（`rateLimit.ts` 的 `callerKeyOf` 要用它），而
    // 放在正文校验之前是因为正文里那批 OPK 可能很大，不该先解析再拒绝。
    //
    // **排在幂等之前**：一次被限流的调用不写台账、不占 `operation_id`。这与 §9.1 不冲突
    // ——那不是一次"被受理的操作"，调用方拿着同一个 `operation_id` 稍后重试，走的正是
    // 同一条路。
    const limited = rateLimitFor(spec, meta, authenticatedCaller, at)
    if (limited !== undefined) return errorResponse(envelope.id, limited)

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

      // §9.3 L823–824 / §9.1 L639：这次调用按不按设备定址，是这个方法自己的判断。问一次、
      // 两处用——幂等键的两段设备，以及下面那次资格检查。
      //
      // **位置在正文校验之后**，因为 `get_prekey_bundle` 点名的第二台设备写在正文里
      // （§7.2 L563 的 `target_device_id`）。早一步算，`body.target_device_id` 还没有被
      // 判过是不是一个非空字符串，`deviceSelector()` 会把一个 `undefined` 拼进幂等键。
      const addressed = spec.deviceAddressed?.(meta, body)
      // 这次请求点名的设备，由下面的资格判定填。空数组是常态（取件面、群、附件都不定址）。
      const devices: EligibleDevice[] = []

      const acceptedAt = at.toISOString()

      // A.3 L1044–1050：SRO 只含 method / meta / body，所以重新签过一次、`auth` 换了、
      // `id` 换了的重试，摘要仍与原请求相同——那正是 §9.1 L630 要的"语义等价"。
      //
      // 算一次、两处用：幂等与冲突判定的指纹，以及 `group_receipt.payload_digest`。无状态
      // 方法（取件面、`group.get_info`）用不上它，代价是多算一趟哈希——换来的是"被受理的
      // 是哪一份请求"只有一个定义。
      const requestDigest = await contentDigestOf(signedRequestObject({ method: spec.name, meta, body }))
      // §8.1: what this request delivered. Filled by `perform`, and empty on every path
      // that did not create one (a replay, and every method but `direct.send`).
      const pending: DeliveryRecord[] = []

      // 这个方法不改状态：没有幂等作用域，也就没有要记的操作，直接跑（P1 §9.1 L628 的
      // 四段键里 operation_id 的语义是"重试同一次操作"，无状态调用没有这个东西）。
      if (spec.targetScope === undefined) {
        return successResponse(
          envelope.id,
          perform(spec, { params: envelope.params, acceptedAt, pending, requestDigest, devices }),
        )
      }

      // 四段键按**请求里写的** `sender_did` 算（§9.1 L641 的另一半：DID 被替代时，重试要用
      // 旧 DID 才查得到；`idempotency.ts` 里有完整的说明）。转发之前要拿它查一次记录，
      // 所以在这里算出来，而不是留在 `acceptOperation` 的参数里当内联表达式。
      const key = idempotencyKey(
        idempotencyScopeFromMeta({
          meta,
          targetScope: spec.targetScope(meta, body),
          method: spec.name,
          // §9.1 L639：只有设备定址的 Overlay 才把设备段放进键。Base 那些调用这里拿到
          // `undefined`，于是键里没有设备——"同一个逻辑操作从两台设备发出"仍是一件事。
          ...(addressed !== undefined ? { deviceSelectors: addressed.pairs.map(deviceSelector) } : {}),
        }),
      )

      // §9.1 L630：这条键上已经有过一条**被受理**的记录，这次就是重放。读一次，两处用：
      // 出站要跳过（`relayFor`），设备资格也要跳过（见下面那一段）。
      const replayed = deps.storage.idempotentRow(key) !== undefined

      // P8 §3.2：请求在**事务外**同步转发——对端接受了才落库（§3.3 的"是不是本服务"
      // 由 relay 一并判掉，是本服务时它返回 `local`，一个字节都不发）。
      //
      // 位置在这里而不是更早，理由与 C5b 那条"事务里不得有网络往返"是同一个：认证与
      // 正文校验都已经过了，此刻转发的是**已经认证过的**请求；再往前走一步就是
      // `acceptOperation` 的事务，网络往返进不去。对端拒绝时我们什么都不写，调用方拿
      // 同一个 `operation_id` 重试即是一次干净的再来。
      const relayed = await relayFor(spec, envelope, key, replayed)
      if (relayed.kind === 'refused') return errorResponse(envelope.id, relayed.rejection)
      const forwarded = relayed.kind === 'answered' ? relayed.result : undefined

      // P5 §4.1.1 / §10.7 L1388：本地收下这颗密文之前，先确认点名的设备此刻都算数。
      // 重放要不要重判由方法自己定（见 `DeviceAddressed.recheckOnReplay`）。
      if (addressed !== undefined && (!replayed || addressed.recheckOnReplay === true) && forwarded === undefined) {
        const ineligible = await eligibilityFor(addressed, devices)
        if (ineligible !== undefined) return errorResponse(envelope.id, ineligible)
      }

      const outcome = acceptOperation({
        storage: deps.storage,
        key,
        fingerprint: requestDigest,
        perform: () =>
          perform(spec, {
            params: envelope.params,
            acceptedAt,
            pending,
            requestDigest,
            ...(forwarded !== undefined ? { relayed: forwarded } : {}),
            devices,
          }),
      })

      // §10.3 L709：同键不同语义。
      if (outcome.kind === 'conflict') return errorResponse(envelope.id, outcome.error)
      // 事务已经提交，投递行是真的了，这时候才推。
      publish(pending)
      return successResponse(envelope.id, outcome.response)
    } catch (err) {
      // Profile 处理器在事务里拒绝一次调用（权限、成员状态、群在不在）。事务已经回滚，
      // 该回的是它自己那个码，不是 500。
      if (err instanceof AnpRefusal) return errorResponse(envelope.id, err.rejection)
      // 到这里还没有回应的，只剩"代码错了"这一种：每个已知的拒绝理由都在上面就地回了。
      // 回 -32603（§10.1 L669–675：这类形状 SHOULD 用 JSON-RPC 标准码）而不是把栈发给
      // 对端；栈进日志。
      log(`anp: ${spec.name} failed internally: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`)
      return errorResponse(envelope.id, rpcRejection(JSON_RPC_ERROR.INTERNAL_ERROR, 'Internal error'))
    }
  }

  /**
   * 这次调用该不该出站，以及出站的结果（P8 §3.3）。
   *
   * **只接 `direct.send` 一条**。P8 §3.2 点的那一族是 `direct.send` / `group.*` /
   * `attachment.*`，但另外两族今天还接不上：
   *
   *   - `group.*` 的锚点是 `group_did`，而"是不是本服务"要先解析它的文档才判得了
   *     （[federation.md](docs/design/federation.md) §5.1）。群 DID 文档**还没有人发布**
   *     ——所以接上它只会让**自家**的群也解析失败。这是那条已记录的 v1 缺口，不是这里
   *     能补的：等 Host 侧发布文档之后，这里的 `spec.name` 判断换成"这个方法的目标 DID"
   *     即可，机制本身不用改。
   *   - `attachment.*` 的锚点是**原始附件消息的发送者 DID**（§9.1 L565、§5.3 L249），
   *     而不是 `meta.target.did`。C10 的 `attachment.get_download_ticket` 是域内实现，
   *     跨域代理模式还没接。
   *
   * 两族今天都落在本地受理上，且都是**响亮的失败**（群不存在、授权不在）而不是静默走错
   * 域——C13 / 后续那一块接上时改的只是这一行判断。
   *
   * `replayed` 是这次调用在幂等台账上已经有过记录——**已经记过账的操作不再出站**。那份
   * 记录里的结果就是对端的答复，重试要的是它。不查这一下，每次重试都会再打扰对端一遍
   * ——而对端若正好不可达，那句 1012 会让调用方以为这颗消息没被受理，事实上它早就被受理
   * 过了。§9.1 L630 说的"重试得到同一结果"包括不重做网络那一跳。判定在 `acceptOperation`
   * 里，两处看的都是同一行，所以"重放"与"同键不同语义"仍然由后者说了算。
   */
  async function relayFor(
    spec: MethodSpec,
    envelope: AnpRequest,
    key: string,
    replayed: boolean,
  ): Promise<ForwardOutcome> {
    if (relay === undefined || spec.name !== DIRECT_SEND) return LOCAL
    if (replayed) return LOCAL
    const targetDid = envelope.params.meta.target?.did
    if (targetDid === undefined || targetDid === '') return LOCAL
    return relay.forward(envelope, targetDid)
  }

  /**
   * P5 §4.1.1：这次调用点名的设备，此刻算不算数。合格的条目**按 `pairs` 的顺序**填进
   * 调用方给的那个数组——两条 Key 方法的处理器要靠这个顺序认人（发布方是 `[0]`，领取的
   * 目标设备是 `[1]`），所以它不能在下面被换成 `Map` 或者被排序。
   *
   * 位置与 `relayFor` 并列——都在 `acceptOperation` 之前，因为它是若干次网络往返（要解析
   * 每台设备所属的 DID 文档），而那个事务里不许有 I/O。
   *
   * 调用点替这里挡掉了三种不该查的情形，每一种都有硬理由：
   *
   *   - **不是设备定址的调用**（`addressed === undefined`）：Base 没有设备可言。
   *   - **跨域**（`forwarded !== undefined`）：§10.7 L1388 把"验两台设备"写成**目标服务**
   *     的 MUST。收到那颗密文的是对端，它的清单归它解释；我们在这里再查一遍，等于拿一份
   *     我们无权解释的清单替对端做主——那份清单里没有那台设备时，我们回的那个码是在说
   *     对端的用户不合法，而它可能只是换了一台设备。
   *   - **重放**（`replayed` 且方法没要求重判）：资格是**当下**的事实（§4.1.1 L171 说它是
   *     每次操作的前置），而 §9.1 L630 要重放得到**同一个**结果。`direct.send` 于是跳过
   *     ——一次早就受理过的重试，不该因为发送方后来把设备摘了而变成错误。但
   *     `get_prekey_bundle` 是另一回事：它交回的是**密钥材料**，§7.2 L578 与 §12.4 L1515
   *     要求每一次返回之前都重验，所以那一档自己把 `recheckOnReplay` 打开。
   *
   * 按 `pairs` 的顺序查，于是先查的是调用方自己那台——它才是这次调用的主张，也是调用方
   * 能自己改的那一半。`get_prekey_bundle` 的第二项不在它的控制下，说"你的设备不合格"比
   * 说"对方的设备不合格"更接近它要做的事。
   */
  async function eligibilityFor(addressed: DeviceAddressed, devices: EligibleDevice[]): Promise<AnpRejection | undefined> {
    for (const pair of addressed.pairs) {
      const outcome = await checkDevice({
        resolver: deviceResolver,
        requirement: addressed.requirement,
        identity: pair.identity,
        deviceId: pair.deviceId,
        opts: resolverOptions,
      })
      if (isRejection(outcome)) return outcome
      devices.push(outcome)
    }
    return undefined
  }

  /**
   * P5 §7.3 L598 的限流，只罩着两条 Key 方法。
   *
   * 键取**认证过的**身份（跨域时是外层签名验出来的 `serviceDid`），同域明文调用没有这一层
   * 认证，只能退回自报的 `meta.sender_did`——`rateLimit.ts` 的文件头把那半的性质写清楚了：
   * 它挡的是"一个身份发得太快"，不是"有人冒充这个身份"。`docs/design/e2ee-direct.md` §9
   * 记着这条缺口。
   *
   * 返回 `undefined` 就是放行（包括"这个方法不限流"）。**不是** `AnpRejection | undefined`
   * 的另一种写法——那个类型的 `undefined` 在别处都表示"没问题"，这里也一样。
   */
  function rateLimitFor(
    spec: MethodSpec,
    meta: AnpMeta,
    authenticatedCaller: string | undefined,
    at: Date,
  ): AnpRejection | undefined {
    if (spec.name !== PUBLISH_PREKEY_BUNDLE && spec.name !== GET_PREKEY_BUNDLE) return undefined
    const decision = prekeyLimiter.take(callerKeyOf(authenticatedCaller, meta.sender_did), at.getTime())
    if (decision.allowed) return undefined
    return anpRejection('anp.rate_limited', `${spec.name} is rate limited for this caller`, {
      retryable: true,
      details: { retry_after: decision.retryAfterSeconds },
    })
  }

  /**
   * 把这次请求产生的投递交给订阅路。
   *
   * 每一条各自兜住异常，且**吞掉**它：走到这里消息已经落库、响应即将发出，`direct.send`
   * 的成功语义与推送无关（realtime.md §1：推送是尽力而为，存储才是事实）。让一个推送
   * 失败把一次已经受理的发送变成错误响应，等于告诉发送方"没收到"，而它其实收到了。
   */
  function publish(records: readonly DeliveryRecord[]): void {
    const sink = deps.onDelivered
    if (sink === undefined) return
    for (const record of records) {
      try {
        sink(record)
      } catch (err) {
        log(
          `anp: publishing delivery ${record.ownerDid}#${String(record.seq)} failed: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
    }
  }

  return handle
}

/**
 * 外层认证失败时回什么。
 *
 * 401 的形态是 ANP-02 §3.2.4.1：`WWW-Authenticate` 带 `DIDWba realm=…, error=…`，正文
 * 按 §4.2.2 L377–383 的示例镜像同一组字段。**没有 `id`**：这一步跑在 JSON-RPC 之前，
 * 那时信封还没被判为可答复的东西，所以正文里只有 §4.2.2 那三个字段，不是一份 JSON-RPC 响应。
 *
 * `unverifiable` 是例外，它回 503 且**不进挑战头**：那个词的语义是"我们（本服务）得不出
 * 结论"（core 把 `VerifyFailure.store_failed` 收在这里），回 401 会把对端送去重签一份本来
 * 没问题的请求。ANP-02 §3.2.4.1 的九个 `error` 值里也没有它——把它塞进头里等于自造词汇。
 */
function outerRefusal(realm: string, error: AnpLoginFailure): RpcResponse {
  if (error === 'unverifiable') {
    // 正文里连 `unverifiable` 都不写：那是本服务的内部词，对端能做的是稍后重试，而不是
    // 根据我们的诊断去改什么。
    return { status: 503, contentType: 'application/json', body: JSON.stringify({ code: 503 }) }
  }
  return {
    status: 401,
    contentType: 'application/json',
    body: JSON.stringify({ code: 401, error }),
    headers: { 'www-authenticate': challengeHeader(realm, error) },
  }
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
