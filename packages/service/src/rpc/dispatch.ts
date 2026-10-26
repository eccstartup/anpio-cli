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
  profileRejection,
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
} from '@anpio-cli/core'
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
import { GET_KEY_PACKAGE, PUBLISH_KEY_PACKAGE, getKeyPackage, publishKeyPackage } from './groupE2ee'
import {
  GROUP_E2EE_ADD,
  GROUP_E2EE_CREATE,
  GROUP_E2EE_REMOVE,
  GROUP_E2EE_SEND,
  addE2eeMember,
  createE2eeGroup,
  removeE2eeMember,
  sendE2eeMessage,
  type GroupControlContext,
} from './groupControl'
import { callerKeyOf, createRateLimiter } from './rateLimit'
import {
  GROUP_ADD,
  GROUP_CREATE,
  GROUP_GET_INFO,
  GROUP_HANDLERS,
  GROUP_JOIN,
  GROUP_LEAVE,
  GROUP_REMOVE,
  GROUP_SEND,
  GROUP_UPDATE_POLICY,
  GROUP_UPDATE_PROFILE,
  isOwnGroupDid,
} from './groups'
import { adoptMemberDidForRequest, requestTriggersDidUpdate, type DidChainResolver } from './memberDidUpdate'
import { adoptOwnerDidForRequest, isSelfAddressed } from './ownerDidUpdate'
import {
  ATTACHMENT_ABORT_OBJECT,
  ATTACHMENT_COMMIT_OBJECT,
  ATTACHMENT_CREATE_SLOT,
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  ATTACHMENT_HANDLERS,
} from './attachments'
import type { ObjectStore } from '../objects'
import { AnpRefusal, refusal } from './refusal'
import { SYNC_DELTA, readDelta } from './inbox'
import {
  CONTACTS_LIST,
  CONTACTS_PUT,
  CONTACTS_REMOVE,
  putContact,
  readContacts,
  removeContact,
} from './contacts'
import {
  GROUP_REMARKS_LIST,
  GROUP_REMARKS_PUT,
  GROUP_REMARKS_REMOVE,
  putGroupRemark,
  readGroupRemarks,
  removeGroupRemark,
} from './groupRemarks'
import { errorResponse, failureId, noResponse, parseRequestText, successResponse } from './envelope'

/** 目标就是本服务（§3.3）。一个共享的常量：它没有内容，没必要每次现造一个。 */
const LOCAL: ForwardOutcome = { kind: 'local' }

/**
 * 会出站转发的三族（P8 §5.1、§5.3、§5.4）。
 *
 * 表放在这里是为了让"哪些方法会出站"是一个**可数的事实**：方法表将来加一条
 * service-scoped 的控制面方法，漏了这里就是"它静默落在本地、再响亮地失败"，而不是转发。
 * 判断在 {@link relayFor}。
 *
 * `group.*` 分两批进来（B1b-A4），因为它们的 `meta.target` 不是一回事：
 *
 *   - `group.create` / `group.e2ee.create` 是 `kind: "service"`，`did` = 某个
 *     `serviceDid`（§8.1.2 L624–625）——建群之前还没有群可指。**与附件完全同形**，连
 *     "目标写着 `config.serviceDid` 就本地办"那次短路都复用。
 *   - 其余十一条是 `kind: "group"`，`did` = `group_did`（§8.2.2 L648–649、§8.9.2
 *     L833–834）。它们以前接不上，是因为"是不是本服务"要先解析群文档，而群文档此前没有
 *     托管方；B1b-A2/A3 让它有了（groups.md §2.2/§2.3）。
 */
const RELAYED_METHODS: ReadonlySet<string> = new Set([
  DIRECT_SEND,
  ATTACHMENT_CREATE_SLOT,
  ATTACHMENT_COMMIT_OBJECT,
  ATTACHMENT_ABORT_OBJECT,
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  // 目标是服务的那两条：建群与建 MLS 组。
  GROUP_CREATE,
  GROUP_E2EE_CREATE,
  // 目标是群的那十一条：读、成员增删、资料与策略、群消息，以及 MLS 的增删发。
  GROUP_GET_INFO,
  GROUP_JOIN,
  GROUP_ADD,
  GROUP_REMOVE,
  GROUP_LEAVE,
  GROUP_UPDATE_PROFILE,
  GROUP_UPDATE_POLICY,
  GROUP_SEND,
  GROUP_E2EE_ADD,
  GROUP_E2EE_REMOVE,
  GROUP_E2EE_SEND,
])

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
  /** 走一次 DID 转移链（P4 §8.12 的请求触发）。默认为 core 的 `resolveDidChain`，选项就是
   *  `config.didResolution`；与 `resolver` / `locator` / `deviceResolver` 同一个理由可换：
   *  换 DID 这条路要读对端的文档，测试不该为此上网。 */
  chainResolver?: DidChainResolver
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
    /**
     * proof 里声明的 keyid（A.2 L1018）。只有要求 `origin_proof` 的方法有值。
     *
     * 与 `devices` 并列而不是塞进 `meta`：它是**外层认证的产物**，不是请求方写的字段——
     * 请求方写的那个是一整串 `signatureInput`，解析它归 core 的验签。
     */
    proofKeyId?: string
    /**
     * proof 里声明的 `nonce`（A.2 L1018）。只有要求 `origin_proof` 的方法有值，且证明里
     * 没写这个参数时它就是 `undefined`。
     *
     * 与 `proofKeyId` 同一个来路，但**用途不同**：它不进任何 handler，只由
     * `consumeProofNonce()` 兑掉一次。见那个函数与 `auth.ts` 的 `AuthResult`。
     */
    proofNonce?: string
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
      // P6 §8 那两条（C13）。与上面一对共用 `keyContext`：上下文要的四件（`storage` /
      // `serviceDid` / `meta` / `body` / `acceptedAt` / `devices`）恰好一样，而 `devices`
      // 的**顺序**读法也相同（[0] 是调用方，领取时的 [1] 是正文点名的目标设备）。
      case PUBLISH_KEY_PACKAGE:
        return publishKeyPackage(keyContext(input))
      case GET_KEY_PACKAGE:
        return getKeyPackage(keyContext(input))
      // P6 §9 的四条控制面方法（C13）。与上面那一对是**两条不同的路**：这几条要
      // `auth.origin_proof`（§9.2.3 等逐字），所以上下文里多两样东西——proof 的 `keyid`
      // 与 `nonce`，都是 `authenticate()` 的产物。`devices[0]` 同样是调用方自己。
      case GROUP_E2EE_CREATE:
        return createE2eeGroup(controlContext(spec, input))
      case GROUP_E2EE_ADD:
        return addE2eeMember(controlContext(spec, input))
      case GROUP_E2EE_REMOVE:
        return removeE2eeMember(controlContext(spec, input))
      case GROUP_E2EE_SEND:
        return sendE2eeMessage(controlContext(spec, input))
      // 取件扩展面只剩这一条（`inbox.ts` 抬头记了另外三条为什么退场）：补齐是唯一一件
      // 服务端才做得了的事，所以它不走"本地读"那条路，也**不**改状态。
      case SYNC_DELTA:
        return readDelta(deps.storage, meta, body, deps.config.deliveryReadWindowMs, input.acceptedAt)
      // TODO6 §3 的通讯录。三条与取件面同形——`self-addressed` 那层绑定保证 `owner_did`
      // 是验过签的 sender，所以这里不需要（也拿不到）第二个身份。
      case CONTACTS_LIST:
        return readContacts(deps.storage, meta)
      case CONTACTS_PUT:
        return putContact(deps.storage, meta, body, input.acceptedAt)
      case CONTACTS_REMOVE:
        return removeContact(deps.storage, meta, body)
      // TODO6 §4.2 的群备注：通讯录那半的另一半，三条同样同形。
      case GROUP_REMARKS_LIST:
        return readGroupRemarks(deps.storage, meta)
      case GROUP_REMARKS_PUT:
        return putGroupRemark(deps.storage, meta, body, input.acceptedAt)
      case GROUP_REMARKS_REMOVE:
        return removeGroupRemark(deps.storage, meta, body)
      default: {
        // `group.*` 与 `attachment.*` 两族都不在这里逐个枚举：它们的处理器按方法名查
        // （`groups.ts` / `attachments.ts`），因为同族的方法在这一层完全同形，逐个写一个
        // `case` 只是把同一段构造抄若干遍，而漏抄一个的表现是"某个方法莫名 500"。查不到
        // 才是不一致——方法表里有它，处理器表里没有。
        const group = GROUP_HANDLERS[spec.name]
        if (group !== undefined) {
          // 跨域那一档到此为止（P8 §5.4）：群不住在本服务上，名册、事件序、回执与那
          // 把群钥都在它的 Host 那里。本地**什么都不该做**——照常往下走会去查一个本地
          // 没有的群，于是"转发已经成功"的调用反倒回一句 3000（`group.not_found`）。
          // 落一行本地群同样是错的：那是同一个群的两份名册，而两份会各自演化。
          //
          // 台账照记（`acceptOperation` 写的），所以重试拿到的是同一份答复。这与
          // `attachment.*` 那条早返回同形，是 §3.3"跨域不增加一层新的中继协议"的直接后果。
          if (input.relayed !== undefined) return input.relayed
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
          // 跨域那一档到此为止（P8 §3.3、§5.3）：转发已经发生过，对端就是那个**对象服务**，
          // 槽位、对象字节与票据都在它那里。本地没有任何东西要建，也不该建——"这颗对象是
          // 谁的"答案在对端，在本地落一行只会造出一颗谁也 download 不到的对象。
          //
          // 台账仍然记（`acceptOperation` 写的），所以重试拿到的是同一份答复，那正是
          // §9.1 L630 要的。不需要 `direct.send` 那样的消息行：附件控制面本来就不产生
          // 本地消息。
          if (input.relayed !== undefined) return input.relayed
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
   * 一次 P6 控制调用要的上下文（§9 的四条）。
   *
   * 与 {@link keyContext} 分开写而不是合一个：两条 Key 方法**不要** `origin_proof`
   * （§8.1.2 L706），它们没有 proof 的 `keyid` / `nonce` 可给，而这一族要。两处合的代价是
   * 每个字段都要配一句"哪几条方法有它"，那正是最容易在下一次改动里漂掉的东西。
   */
  function controlContext(spec: MethodSpec, input: PerformInput): GroupControlContext {
    consumeProofNonce(spec, input)
    return {
      storage: deps.storage,
      serviceDid: deps.config.serviceDid,
      meta: input.params.meta,
      body: input.params.body,
      acceptedAt: input.acceptedAt,
      requestDigest: input.requestDigest,
      devices: input.devices,
      ...(input.proofKeyId !== undefined ? { proofKeyId: input.proofKeyId } : {}),
      // §13.6 L1670：`group.incoming` 那一档要把原 proof 连同 `origin_context` 原样保留，
      // 所以 handler 得看见提交时那份 `params.auth`（[groupEnvelopes.ts] 装配）。
      ...(input.params.auth !== undefined ? { auth: input.params.auth } : {}),
    }
  }

  /**
   * §13.6 L1693 逐字：Host **MUST** 在受理 `group.e2ee.create` / `add` / `remove` / `send`
   * 时施加"完整新鲜度窗口 **+** 一次性 nonce 检查"。
   *
   * 时间窗那一半已经由 `authenticate()` 判过（`created` / `expires`，core 的
   * `originProofFreshness`）；这里补 nonce 那一半——`http_nonces` 表按 `(keyid, nonce)`
   * 建键，两小时出清（`federation/nonces.ts` 上写了为什么是这一对而不是裸 nonce）。
   *
   * ## 位置：`perform` 里，不是 `authenticate()` 之后
   *
   * 三件事要同时成立，只有这一个位置能让它们都成立：
   *
   *   - §9.1 L630 要求重试拿到**同一个结果**。重试命中幂等记录时 `acceptOperation()` 根本
   *     不调 `perform`，也就碰不到这个 nonce——放在外面的话，一次合法的重试会被自己那份
   *     证明里的 nonce 拒掉，而那正好是"重放得到同一结果"要保住的东西。
   *   - 被拒的调用**不烧掉** nonce。兑 nonce 那句 INSERT 与处理器的写、幂等记录在同一个
   *     事务里，处理器抛错即整体回滚——调用方改掉正文重签一份就能再来。
   *   - 并发的两份同一 nonce 由 `BEGIN IMMEDIATE` 串行化，第二份撞主键、`changes` 为 0。
   *
   * 证明里没有 `nonce` 时什么也不判：§13.6 那句说的是对新鲜度参数"such as `created`,
   * `expires`, and `nonce`"施加检查，而 A.2 L1018 让 nonce 是可选参数。没有可兑的值，就
   * 不自造一条拒绝理由——`created` / `expires` 那一半照旧生效。
   *
   * 码取方法表给这一族的那一对 `invalidProof`（P1 的 1005）：§17 那一段（5000–5013）没有
   * 一条说"这个证明不能再用了"，而 §17 L1930 逐字要求这类失败复用 P1 Core 的码。
   */
  function consumeProofNonce(spec: MethodSpec, input: PerformInput): void {
    const nonce = input.proofNonce
    const keyid = input.proofKeyId
    if (nonce === undefined || keyid === undefined) return
    if (nonceStore.consume(keyid, nonce)) return
    const codes = spec.authCodes.invalidProof
    throw refusal(
      profileRejection(codes.code, codes.anpCode, 'this origin proof nonce has already been used'),
    )
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

    // A.2 L1018 那个 keyid，验签过了才有值。P6 §13.3 L1626 要拿它比
    // `meta.sender_device_id` 那台设备当前的 `signing_key_id`——比"某个 DID 发的"细一档，
    // 所以只有那一条路用它（`groupControl.ts`）。见 `AuthResult.keyid`。
    let proofKeyId: string | undefined
    // A.2 L1018 那个 nonce，同样只有验签过了才有值。P6 §13.6 L1693 要的一次性检查在
    // `consumeProofNonce()` 里兑，**位置在 `perform` 之内**（那个函数上写了理由）。
    let proofNonce: string | undefined
    // 认证**通过**的锚点。与 `proofKeyId` 分开记：那个是 proof 里声明的 `keyid`（可能缺），
    // 这个是"这次调用是**谁**发起的"，由 `authenticate` 连钥带身份一起验过。账号换钥那条路
    // （`ownerDidUpdate.ts`）要的正是后者。
    let authenticatedAs: string | undefined

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
      const anchor = callerAnchor(spec.name, envelope.params)
      const outcome = await authenticate({
        envelope,
        expectedAnchor: anchor,
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
      proofKeyId = outcome.keyid
      proofNonce = outcome.nonce
      authenticatedAs = anchor
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

      // P4 §8.12 的**请求触发**：来的是一个可能是某个成员后继的 DID，而名册里还写着旧的那个。
      //
      // 位置在两条受理路**分岔之前**，因为触发面里有 `group.get_info`，而它是无状态方法、
      // 走的是下面那个提前返回的分支。也因为它必须在这次调用被授权**之前**走完——规范要求
      // "先补完名册、排好 member-did-updated，再按保留下来的角色受理这次操作"。
      //
      // 与 `relayFor` / `eligibilityFor` 同一条理由它是异步的：要走一次转移链（网络往返），
      // 而它落下的那次改名自己也占一个事务，两件事都进不去 `acceptOperation` 的事务。
      // 绝大多数调用在这里一次查表就过去了（方法名不在触发面上）。
      await adoptDidSuccessor(spec, meta, acceptedAt, pending)

      // TODO7 §3 第 4 条：账号自己的换钥。与上面那一步是同一件事的另一个面——群名册那边
      // 补的是"成员换 DID"，这一步补的是"**这个账号自己的**信箱挂在哪个 DID 下"。触发面比
      // 那一处窄得多：只有这次调用是**账号以自己身份、对自己的信箱**发起的才算数
      // （`isSelfAddressed`），而 `sync.delta` 正是那一类——它也正是取不到旧投递的那条路。
      //
      // 位置在这里、与 `adoptDidSuccessor` 并列：都是**受理前**要补完的事实，也都要网络
      // 往返（走一次转移链），所以都不进 `acceptOperation` 的事务。绝大多数调用在这里一次
      // 索引读就过去了（水位线与调用方一致），只有真的换过钥才解析一次。
      if (authenticatedAs !== undefined && isSelfAddressed(authenticatedAs, meta.target?.did)) {
        await adoptOwnerDidForRequest({
          storage: deps.storage,
          config: deps.config,
          actorDid: authenticatedAs,
          acceptedAt,
          ...(deps.chainResolver !== undefined ? { resolveChain: deps.chainResolver } : {}),
          log,
        })
      }

      // 这个方法不改状态：没有幂等作用域，也就没有要记的操作，直接跑（P1 §9.1 L628 的
      // 四段键里 operation_id 的语义是"重试同一次操作"，无状态调用没有这个东西）。
      //
      // **无状态不等于本地。** `group.get_info` 走的就是这一支，而它读的群可能住在对端
      // ——`RELAYED_METHODS` 里那十一条的开头写着"读"，说的正是它。转发判据与有状态那条路
      // 是同一个 `relayFor`，所以自己命名空间里的群和自己的 `serviceDid` 仍在那里短路成本地，
      // 这里转发出去的只有**别人的**群。
      //
      // 少了这一句，一次跨域的 `group.get_info` 会被**本地处理器**答成 `group.not_member`
      // ——"我们这儿没这个群"——而那是对一个从没查过的群下的判断；转发它才是去问住着它的那个
      // 服务。表里那一行因此不是装饰：它在先，这一句是让它成真的那一步。
      //
      // `replayed` 恒为假：无状态方法不进幂等台账（下面那句"没有操作要记"说的就是这个），
      // 所以这条键上永远不会有记录，也永远不是重放。
      if (spec.targetScope === undefined) {
        const relayed = await relayFor(spec, envelope, false)
        if (relayed.kind === 'refused') return errorResponse(envelope.id, relayed.rejection)
        const result =
          relayed.kind === 'answered'
            ? relayed.result
            : perform(spec, {
                params: envelope.params,
                acceptedAt,
                pending,
                requestDigest,
                devices,
                ...(proofKeyId !== undefined ? { proofKeyId } : {}),
                ...(proofNonce !== undefined ? { proofNonce } : {}),
              })
        // 无状态方法自己不产生投递，所以这段在 §8.12 之前是空转的；而 `group.get_info` 一旦
        // 顺路补了名册，那次补就产生了通知。它与有状态那条路上的 `publish` 是同一句话。
        publish(pending)
        return successResponse(envelope.id, result)
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
      const relayed = await relayFor(spec, envelope, replayed)
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
            ...(proofKeyId !== undefined ? { proofKeyId } : {}),
            ...(proofNonce !== undefined ? { proofNonce } : {}),
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
   * 规则只有一条，接了的两族共用：**请求点名的那颗目标 DID，它的公开 `ANPMessageService`
   * 是不是本服务**。是本服务就本地办完（`relay` 认出自家入口、返回 `local`，一个 HTTP 都
   * 不发），不是就按 §5 把**原始方法**转发过去——§3.1 L61–68 说得很直白：跨域不增加一层
   * 新的中继协议。
   *
   * 目标 DID 一律取自 `meta.target.did`，但三族的语义不同，别把下游的发现义务和这里的
   * 路由混起来：
   *
   *   - `direct.send`：`target.kind = "agent"`，`target.did` 是收件 agent（§5.1）。
   *   - `attachment.*`：`target.kind = "service"`，`target.did` 就是那个对象服务的
   *     `serviceDid`（§10.1 L798）。§5.2/§5.3 额外要的那句"先从**原始附件消息发送者的
   *     DID** 解析出公开服务"，约束的是**调用方**怎么找到这个 `serviceDid`；等请求走到
   *     我们这里，`meta.target.did` 已经写着它解析出来的结果，这一层照转即可，不重解析。
   *   - `group.*`：两档。`group.create` / `group.e2ee.create` 的 `target.did` 是一个
   *     `serviceDid`（§8.1.2 L624–625），与附件同形；其余十一条是 `group_did`
   *     （§8.2.2 L648–649、§8.9.2 L833–834）。
   *
   * **群这一族与附件有一处不同，值得写下来**：群文档由**本服务**发布（groups.md §2.2/§2.3），
   * 而附件的文档不在（§13）。所以自家命名空间里的群（`serviceDid:g:<id>`）在下面那一行就
   * 短路成 {@link LOCAL} 了，连"解析自己的入口"都不做——一个 HTTP 都不发。对端的群照常
   * 转发，由 `relay` 解析它的文档，那正是 A2/A3 那条接缝要撑起来的事。
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
    replayed: boolean,
  ): Promise<ForwardOutcome> {
    if (relay === undefined || !RELAYED_METHODS.has(spec.name)) return LOCAL
    if (replayed) return LOCAL
    const targetDid = envelope.params.meta.target?.did
    if (targetDid === undefined || targetDid === '') return LOCAL
    // 目标写着我们自己的 `serviceDid`：这是同域的附件调用，或 `group.create` /
    // `group.e2ee.create`（它们的目标就是一个 serviceDid）。答案本地就知道，不该让"我们的
    // 文档解析得到我们自己的入口"变成前提——那份文档不在本服务手里
    // （[message-service.md](docs/design/message-service.md) §13），它解析不出来时这次调用
    // 仍该照常办。`direct.send` 走不到这里：它的目标是 agent DID，不会等于一个 serviceDid。
    if (targetDid === deps.config.serviceDid) return LOCAL
    // 住在自己命名空间里的群（`serviceDid:g:<id>`）：群文档由**本服务**发布（groups.md
    // §2.2/§2.3），所以"它的入口在哪"同样是本地已知的常量，不必问网络。**这不是优化**：
    // 那一趟解析要么被 `ANPIOCLI_ALLOWED_DID_HOSTS` 拒掉（清单里是**对端**域，不写自己），
    // 要么要求本服务的 `publicUrl` 是 https，于是一个本服务亲手建的群会在自己的 `group.send`
    // 上报 1012——一个本地就知道答案的调用，不该取决于出站解析成不成功。
    //
    // 群不在本服务上时（`group_did` 属于别的域）走下面那次真的转发，由 `relay` 去解析对端的
    // 文档——那才是这条接缝要撑起来的事。
    if (isOwnGroupDid(deps.config.serviceDid, targetDid)) return LOCAL
    return relay.forward(envelope, targetDid)
  }

  /**
   * P4 §8.12 的请求触发：这次调用是不是该**先补完名册**再受理。
   *
   * 三件事在这一层决定，其余交给 `memberDidUpdate.ts`：
   *
   *   - **定址**。这个动作只对"目标是本服务托管的某个群"成立——`meta.target.did` 就是
   *     `group_did`。群不在本服务上时下面第一次查表就返回了。
   *   - **触发面**（§8.12 L946 那五个方法）。`requestTriggersDidUpdate` 里是那张表；它在
   *     这里而不是在 `handle` 里逐方法写，是因为"哪几个方法会触发"与"触发之后做什么"是同
   *     一件事的两半，分开写就会各自漂。
   *   - **失败的处置**。整块**不吞异常**：这里判不了（对端 DID 服务器不可达、链断了、档位
   *     不够）都已经在 `adoptMemberDidForRequest` 里变成了"不采纳"，走不到这里；能抛到这里的
   *     只剩数据库错这类真问题，它们该由下面那个 catch 变成 -32603 并进日志，而不是被静默
   *     咽掉之后让这次调用拿着一个**没补上的名册**继续跑。
   */
  async function adoptDidSuccessor(
    spec: MethodSpec,
    meta: AnpMeta,
    acceptedAt: string,
    pending: DeliveryRecord[],
  ): Promise<void> {
    const targetDid = meta.target?.did
    const actorDid = meta.sender_did
    // 匿名调用没有发起者可言，也就没有"这是谁的后继"这个问题。
    if (targetDid === undefined || targetDid === '' || actorDid === undefined || actorDid === '') return
    if (!requestTriggersDidUpdate(deps.storage, spec.name, targetDid)) return
    await adoptMemberDidForRequest({
      storage: deps.storage,
      config: deps.config,
      groupDid: targetDid,
      actorDid,
      acceptedAt,
      ...(deps.chainResolver !== undefined ? { resolveChain: deps.chainResolver } : {}),
      ...(log !== undefined ? { log } : {}),
      onDelivery: (record) => pending.push(record),
    })
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
