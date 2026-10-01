// C11 —— 接收侧的外层身份认证（P8 §6.2.2 的八步，federation.md §2）。
//
// 跨域请求上有**两层**身份，§3.6 L90–98 说它们 MUST NOT 混淆：
//
//   外层 HTTP  —— 哪个**域服务**正在调用我（`Signature-Input` / `keyid`）
//   业务层     —— 哪个**业务主体**发起了这个动作（P1 附录 A 的 `origin_proof`）
//
// 这个文件只做外层。业务层仍是 `rpc/auth.ts` 的 `authenticate()`，一层都不省
// （§6.4 L435：目标域服务 MUST 独立验证 `origin_proof`）。
//
// 八步里最容易写错的不是密码学，是**第 2、3 步**：锚点必须由 `callerAnchor()` 按方法算。
// 群通知（`group.incoming` / `group.state_changed` / `group.e2ee.notice`）的锚点是
// `body.group_did` 而不是 `meta.sender_did`（L370–372），L387 专门写了一句
// 「MUST NOT 一律从 `meta.sender_did` 推导」。所以这里不自己判断，直接调用 C3 那个函数
// ——两处各写一遍，就回到了 §6.2.2 想防的那个洞。

import {
  anpErrorForResolveFailure,
  discoverMessageService,
  verifyHttpSignatureForServer,
  type AnpLoginFailure,
  type AnpMeta,
  type KeyResolver,
  type LocateOptions,
  type NonceStore,
  type ResolvedIdentityKey,
  type ServiceLocator,
} from '@agentx/core'
import { parseSignatureInput } from '@agentx/core/advanced'
import type { IncomingHttpHeaders } from 'node:http'
import { callerAnchor } from '../rpc/auth'

/** ANP-02 §3.2.4.1 的挑战方案名。刻意不是 `Bearer`：这里是外层身份，不是 access token。 */
export const CHALLENGE_SCHEME = 'DIDWba'

export interface OuterVerifyInput {
  /** JSON-RPC 方法名。只为算锚点——外层认证本身不看业务语义。 */
  method: string
  params: { meta: AnpMeta; body?: Record<string, unknown> }
  http: {
    /** HTTP 方法（`@method` 覆盖的就是它）。与 JSON-RPC 的方法名是两回事。 */
    method: string
    /** 实际请求的路径，**不带**查询串（`@target-uri` 的那一半由 `search` 补）。 */
    path: string
    /** 带前导 `?`，没有就是空串。 */
    search: string
    /** `host` 头，也就是客户端实际寻址的那个 authority。 */
    authority: string
    headers: IncomingHttpHeaders
    /** 请求体的**原始文本**：`Content-Digest` 覆盖的是这些字节，不是重新序列化的结果。 */
    body: string
  }
  /** 外层签名覆盖的是 `@target-uri`，所以它必须是一个绝对 URI。scheme 由部署声明
   *  （`config.publicUrl` 的协议），不由本连接推断——本服务自己是明文 http 监听，
   *  放在 TLS 终止后面时客户端签的是 `https`。带不带结尾的冒号都收：最常见的来源
   *  `new URL(publicUrl).protocol` 是带冒号的（`"https:"`）。 */
  scheme: string
  resolver: KeyResolver
  locator: ServiceLocator
  locateOptions?: LocateOptions
  nonceStore: NonceStore
}

/**
 * 结局。
 *
 * `absent` 与其余两支是**两个问题**：前者是"这次调用没有外层身份"，后者是"带了、没验过"。
 * 把它们合成一个布尔，调用点就会在"没带"和"验失败了"之间二选一——而这两件事在
 * federation.md §2.3 里是明确的两种处理。
 *
 * `reason` 是给本服务运维看的（哪一步拒的）。它**不上线**：ANP-02 §3.2.4.1 已经把这件事
 * 表示完了，逐条答出去只会多一个 oracle。
 */
export type OuterAuth =
  | { kind: 'absent' }
  | { kind: 'verified'; serviceDid: string; keyid: string; key: ResolvedIdentityKey }
  | { kind: 'refused'; error: AnpLoginFailure; reason: string }

/**
 * 八步。
 *
 * 覆盖集合不在这里定：core 的 `ANP_COMPONENTS` 就是
 * `("@method" "@target-uri" "@authority" "content-digest")`，与 §3.1.2 L112 的
 * 「至少覆盖 `@method` 与 `@target-uri`；有消息体时还必须覆盖 `content-digest`」逐项对上。
 */
export async function verifyOuterIdentity(input: OuterVerifyInput): Promise<OuterAuth> {
  const headers = normalizeHeaders(input.http.headers)
  // §2.3：带了外层身份就八步必过，没带就当作本地调用。这是本服务的选择，代价写在
  // federation.md §2.3 里——一个不带外层身份的跨域调用方换不到额外权限，它失去的只是
  // 域级归属。
  if (headers['signature-input'] === undefined) return { kind: 'absent' }

  // 第 1 步：定 caller anchor。`undefined` 也是失败——方法要外层身份，而承载锚点的那个
  // 字段不在。
  const anchor = callerAnchor(input.method, input.params)
  if (anchor === undefined) return refuse('invalid_request', 'no anchor for this method')

  // 第 5 步先做：`keyid` 在头里，把它解析出来不需要任何 I/O，所以一个不成形的
  // `Signature-Input` 不该先换来一次网络往返。
  let keyid: string
  try {
    const parsed = parseSignatureInput(headers['signature-input'])
    const raw = parsed.params.keyid
    if (typeof raw !== 'string') return refuse('invalid_request', 'Signature-Input has no keyid')
    keyid = raw
  } catch (err) {
    return refuse('invalid_request', `Signature-Input did not parse: ${describe(err)}`)
  }
  // L82：`keyid` MUST 是**完整 DID URL**。没有 fragment 的 `keyid` 指的不是一个验证方法，
  // 而"哪个钥能用"正是这一步之后要问的问题。
  const hash = keyid.indexOf('#')
  if (hash <= 0) return refuse('invalid_request', `keyid is not a DID URL: ${keyid}`)
  const keyidDid = keyid.slice(0, hash)

  // 第 2–4 步：解析锚点自己的文档，选出它**唯一**的公开 `ANPMessageService`，读出
  // `serviceDid`。走的是 P2 §9.1 L549–560 那条路，与同域调用是同一个函数——"一份 DID
  // 文档只许有一个对外入口"（§7.1 L352）在这里也成立，而且更要紧：选错的那个可能
  // 看起来能用。
  let publishedServiceDid: string
  try {
    const target = await discoverMessageService(anchor, {
      locator: input.locator,
      ...input.locateOptions,
    })
    // L385：条目没有 `serviceDid` 就失败。**不回落**到锚点本身：§6.2.2 要比的是一个
    // 明确宣告过的域级身份，拿被调用方的名字去顶替等于把这一步删掉。
    if (target.serviceDid === undefined) {
      return refuse('invalid_did', `${anchor} publishes an ANPMessageService without serviceDid`)
    }
    publishedServiceDid = target.serviceDid
  } catch (err) {
    return refuse(anpErrorForResolveFailure(err), `could not read ${anchor}'s service entry: ${describe(err)}`)
  }

  // 第 6 步：外层 `keyid` 所属的 DID 与步骤 4 读到的 `serviceDid` **完全一致**。
  if (keyidDid !== publishedServiceDid) {
    return refuse(
      'forbidden_did',
      `keyid ${keyid} does not belong to the service ${anchor} publishes (${publishedServiceDid})`,
    )
  }

  // 第 7 步：按 ANP-02 解析并验证 `serviceDid` 的文档，取被 `authentication` 授权的公钥。
  // `DidKeyResolver` 委托 core 的 `resolveVerificationKey`，那一步已经在做"是否被
  // `authentication` 授权"——少它一次，名字里带 keyid 与"这把钥真的能用来认证"就没有
  // 区别了。
  let key: ResolvedIdentityKey
  try {
    key = await input.resolver.resolve(publishedServiceDid, keyid, input.locateOptions)
  } catch (err) {
    return refuse(anpErrorForResolveFailure(err), `could not resolve ${keyid}: ${describe(err)}`)
  }

  // 第 8 步：验外层签名。组件集合、时间窗、`Content-Digest`、以及一次性 nonce 的兑付
  // 都在 core 里，这里只把它的细分理由收成 ANP-02 的九个词（L252–260）。
  const targetUri = `${input.scheme.replace(/:$/, '')}://${input.http.authority}${input.http.path}${input.http.search}`
  const outcome = await verifyHttpSignatureForServer({
    method: input.http.method,
    path: input.http.path,
    authority: input.http.authority,
    targetUri,
    search: input.http.search,
    headers,
    body: input.http.body,
    key,
    nonceStore: input.nonceStore,
  })
  if (!outcome.ok) {
    return refuse(outcome.error, `outer signature did not verify (${outcome.error})`)
  }

  return { kind: 'verified', serviceDid: publishedServiceDid, keyid, key }
}

/**
 * ANP-02 §3.2.4.1 的 401 挑战头。
 *
 * `realm` 取本服务公网地址的主机名，与规范里 `realm="api.example.com"` 的示例同形。
 * `error` 只写 §3.2.4.1 列出的那些值——`unverifiable` 不在其中，调用方必须把它翻成 5xx
 * 而不是塞进这个头（core 的 `AnpLoginFailure` 里有完整的理由）。
 */
export function challengeHeader(realm: string, error: AnpLoginFailure): string {
  return `${CHALLENGE_SCHEME} realm="${realm}", error="${error}"`
}

function refuse(error: AnpLoginFailure, reason: string): OuterAuth {
  return { kind: 'refused', error, reason }
}

/**
 * Node 的头表收成小写字符串表。
 *
 * `set-cookie` 这类头在 Node 里是数组，而 `verifyHttpMessageSignature` 要的是
 * `Record<string, string>`——`@signature-input` 这种头不可能重复，把它接到第一个值上，
 * 比在验签那一层再判一次类型清楚。缺失的头一律不出现在结果里，`?? ''` 会把"没带"
 * 变成一个空串值，而这两件事在 `buildSignatureBase` 里读起来一样、在诊断里不一样。
 */
function normalizeHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue
    out[name.toLowerCase()] = Array.isArray(value) ? (value[0] ?? '') : value
  }
  return out
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
