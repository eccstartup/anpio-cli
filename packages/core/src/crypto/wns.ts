// ANP-04 WNS —— Handle 这一层：语法、解析端点，以及 §6.3.1 的双向绑定校验。
//
// 三件事这个模块**不是**：
//   - 不是 `RegisterOptions.handle`。那是一个 DID server 同意托管你时绑定的名字，
//     是那个 DID 内部的名字；WNS Handle 是 `DID → 名字` 的**外部**映射，权威在
//     Handle Provider 那边（见 actions.ts 与 AgentDescription.handle 的警告）。
//   - 不做注册、不做分配。注册流程、长度策略、保留字列表、`binding_generation` 的
//     递增义务都由 Handle Provider 定义与承担（§8.2 L698–L705）。SDK 只做客户端
//     这一侧：把 Handle 解析成 DID，再校验这个映射是不是真的双向。
//   - 不绕过 DID 文档。§4.5 L407 是 MUST NOT：不得由 Handle 直接推断服务端点、绑定
//     密钥或任何 DID 相关信息。链路只有一条：Handle → DID → DID Document。
//
// 关于原生 `did:web`：附录 B.4 给了它一条**较弱的**兼容路径 —— 只确认「Handle → DID」
// 的正向声明与 DID 文档对 Provider 域的声明，不要求端点解引用。它落在
// `verifyHandleBinding` 里（调用方在解析出 DID 之前无从知道方法），结果值是独立的
// `provider-domain`，理由是 B.4 L31 明说它不等于主线那两档，见该函数的说明。

import { ConnectxError, isConnectxError } from '../errors'
import { HANDLE_SERVICE_TYPE, type DidDocumentService } from './didDocument'
import { didToUrl, fetchControlledJson, resolveDidDocument } from './resolveDid'
import type { FetchErrorCodes, ResolveDidOptions } from './resolveDid'

// ---- Handle 语法（§3）---------------------------------------------------------

// §3.1 L89 的 ABNF：local-part = (ALPHA / DIGIT) *61(ALPHA / DIGIT / "-") (ALPHA / DIGIT)
// ABNF 本身就限定了 1–63 字符、首尾必须是字母数字；它**没有**禁止 `--`，那是 §3.1
// L97 单列的一条 MUST NOT，所以在正则后面单独查一次。
const LOCAL_PART = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
// §3.1 L99–L100 的 domain：受 TLS 保护的合法 FQDN，且**不携带端口号**。要求至少两个
// 标签（即至少一个点）：单标签名不可能拿到公共 CA 的证书（§9.1 L739 要求 Handle 的
// 域名必须由有效 TLS 证书保护），而 §3.1 自己的例子无一例外都是带点的。
const DOMAIN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/

/** 一个已经归一化、且逐条过了 §3.1 语法规则的 Handle。 */
export interface ParsedHandle {
  /** 归一化后的完整 Handle：`local-part.domain`，全小写。 */
  handle: string
  localPart: string
  domain: string
  /** 该 Handle 的标准 Resolution Endpoint（§4.2 L175）。 */
  resolutionUrl: string
}

/**
 * 归一化并校验一个 Handle（§3.1）。**归一化在语法检查之前**：§3.1 L101 是 MUST ——
 * 所有输入在处理前必须归一化为小写，所以 `Alice.Example.com` 是合法输入，归一化后是
 * `alice.example.com`（§3.1 L113 的例子）。
 *
 * 接受 `wba://` 前缀并剥掉它（§3.2 L126–L127）：那是同一个 Handle 的传播写法，剥掉
 * 之后走同一条路。只剥这一种 scheme —— §3.2 L132 提到的 `https://…` Web URL 是**另一
 * 种定位方式**，不是 Handle 的另一种拼法，这里不认。
 *
 * 抛 `invalid_handle`，并在消息里指明是哪一条规则不过：§3.1 的四条（首尾、`--`、长度、
 * 端口）在排查时指向完全不同的修法，合成一句"格式错误"等于把信息丢掉。
 */
export function parseHandle(input: string): ParsedHandle {
  const stripped = input.trim().replace(/^wba:\/\//i, '')
  if (stripped === '') throw new ConnectxError('invalid_handle', 'Empty Handle')

  const normalized = stripped.toLowerCase()
  // §3.1 L83：`local-part "." domain` 只有一个分隔点，而且 local-part 里不含 `.`，
  // 所以**第一个**点就是分界。按最后一个点切会把 `a.b.example.com` 的 local-part
  // 读成 `a.b` —— 那是另一个 Handle。
  const dot = normalized.indexOf('.')
  if (dot < 0) {
    throw new ConnectxError('invalid_handle', `Handle "${input}" is not "local-part.domain" (no domain part)`)
  }
  const localPart = normalized.slice(0, dot)
  const domain = normalized.slice(dot + 1)

  if (!LOCAL_PART.test(localPart)) {
    throw new ConnectxError(
      'invalid_handle',
      `Handle "${input}" has an invalid local part "${localPart}" (1–63 chars, ASCII letters/digits/hyphens, must start and end alphanumeric)`,
    )
  }
  // §3.1 L97 是一条**独立**于 L89 ABNF 的 MUST NOT：ABNF 本身允许 `--`，所以
  // `al--ice` 是正则能过的。挂在上面那个分支里就等于漏掉这一类。
  if (localPart.includes('--')) {
    throw new ConnectxError('invalid_handle', `Handle "${input}" has consecutive hyphens in its local part`)
  }
  if (domain.includes(':')) {
    throw new ConnectxError('invalid_handle', `Handle "${input}" carries a port; a Handle's domain never does`)
  }
  if (!DOMAIN.test(domain)) {
    throw new ConnectxError('invalid_handle', `Handle "${input}" has an invalid domain "${domain}" (a TLS-protected FQDN)`)
  }

  return {
    handle: `${localPart}.${domain}`,
    localPart,
    domain,
    // local-part 只含 `[a-z0-9-]`（上面的正则保证了），所以两段都不需要百分号编码。
    resolutionUrl: `https://${domain}/.well-known/handle/${localPart}`,
  }
}

/** 某个 Handle 的标准 Resolution Endpoint（§4.2 L175）。等价于
 *  `parseHandle(handle).resolutionUrl`，给手上只有 Handle 字符串的调用方用。 */
export function handleResolutionUrl(handle: string): string {
  return parseHandle(handle).resolutionUrl
}

/**
 * 某个 Handle Provider 域下的 DID Confirmation Endpoint（§4.3.1 L239）。这是
 * **私密确认模式**要写进 DID 文档的 `serviceEndpoint`：它不公开具体 Handle，只回答
 * "这个 DID 是不是你负责解析的"。
 *
 * 参数是**域名**而不是 Handle：恰恰因为这一模式不公开 Handle —— 调用方只知道 Provider
 * 的域（§6.2 L518）。
 *
 * `encodeURIComponent` 就是规范自己那个例子（§6.2 L505 的 `did%3Awba%3A…`）的编码方式：
 * 整个 DID 作为**一个**查询值，冒号一并编码。
 */
export function didConfirmationUrl(domain: string, did: string): string {
  const d = domain.trim().toLowerCase()
  if (!DOMAIN.test(d)) {
    throw new ConnectxError('invalid_argument', `"${domain}" is not a valid Handle Provider domain`)
  }
  if (did === '') throw new ConnectxError('invalid_argument', 'didConfirmationUrl needs a DID')
  return `https://${d}/.well-known/handle/by-did?did=${encodeURIComponent(did)}`
}

/**
 * 把 `endpoint` 发布为该 DID 的 Handle 绑定服务端点（§6.2 L503–L513）。`id` 用规范建议
 * 的 `#handle` 后缀（L511）。
 *
 * 和 `agentDescriptionService` 一样，返回值必须放进 DID 文档**签名之前**的构造里：
 * `proof` 覆盖签名时刻的全部字段，事后追加的条目在验签时表现为文档被篡改。
 *
 * 两种模式（§6.2 L486–L487）由 `endpoint` 的形状决定，SDK 不做区分：
 *   - 公开 Handle 模式 —— 传某个具体 Handle 的 `handleResolutionUrl(handle)`，它让验证者
 *     能强校验"输入 Handle 与这个 DID 精确匹配"；
 *   - 私密确认模式 —— 传 `didConfirmationUrl(domain, did)`，只确认 provider 关系，
 *     不在文档里公开具体 Handle。
 */
export function handleService(endpoint: string, did?: string): DidDocumentService {
  return {
    id: did == null ? '#handle' : `${did}#handle`,
    type: HANDLE_SERVICE_TYPE,
    serviceEndpoint: endpoint,
  }
}

// ---- 解析文档（§4.3 / §4.7）----------------------------------------------------

/** §4.7 L421–L427 的三种 Handle 状态。 */
export type HandleStatus = 'active' | 'suspended' | 'revoked'

/** 一份 Handle Resolution Document（§4.3 L196 的字段表）。 */
export interface HandleResolutionDocument {
  /** 完整的 Handle 标识符。 */
  handle: string
  /** 该 Handle 当前绑定的 DID。 */
  did: string
  status: HandleStatus
  /** 十进制字符串；绑定或状态每次变更时严格递增（§4.3、§4.4 规则 6 L386）。 */
  binding_generation: string
  updated?: string
  versionId?: string
  ttl?: number
  /** 该 Handle 所绑定 DID 主体的**公开展示资料**。§4.3 字段表与 MUST 23（L864）都要求
   *  它**不得**用于身份认证、授权、消息路由、服务发现、E2EE 绑定或安全 Profile 协商。
   *  原样带出，SDK 也不验它可选的 `proof`。 */
  profile?: Record<string, unknown>
  [key: string]: unknown
}

const HANDLE_STATUSES: readonly string[] = ['active', 'suspended', 'revoked']

/** 检查一份抓来的 body 确实是 Handle Resolution Document。**故意浅**：只查 §4.3 标为
 *  "必须"的四个字段的存在与类型，外加这里唯一要紧的那条跨文档绑定。
 *
 *  那条绑定是 `handle` 必须**就是所问的那个**：`handle` 是这份文档描述的主体（§4.3
 *  L196 的"完整的 Handle 标识符"），对不上意味着这份内容属于**另一个** Handle，里面
 *  任何字段都不得归到所问的 Handle 名下。缺失即拒收是规范的直接要求（§4.3 表：必须）。
 *  注意 §4.4 规则 1 的"domain 与 DID 主机名一致"**不在这里** —— 它是一条绑定强度规则，
 *  只在 `verifyHandleBinding` 里判（§6.3 L532 允许展示类场景推迟绑定校验，而推迟之后
 *  仍要做的那次校验就是它）。 */
function assertHandleResolutionDocument(body: unknown, handle: string, url: string): HandleResolutionDocument {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConnectxError('handle_malformed', `Handle resolution document from ${url} is not a JSON object`)
  }
  const doc = body as Record<string, unknown>
  for (const field of ['handle', 'did', 'status'] as const) {
    if (typeof doc[field] !== 'string' || doc[field] === '') {
      throw new ConnectxError('handle_malformed', `Handle resolution document from ${url} is missing required field "${field}"`)
    }
  }
  // §4.3 表 + MUST 27（L868）：`binding_generation` 必须是十进制字符串。它要能单调比较，
  // 所以既不能是数字字面量也不能是 `"8 "` 之类 —— 这里按十进制整数的文本形式收。
  if (typeof doc.binding_generation !== 'string' || !/^[0-9]+$/.test(doc.binding_generation)) {
    throw new ConnectxError(
      'handle_malformed',
      `Handle resolution document from ${url} has a non-decimal "binding_generation" (${JSON.stringify(doc.binding_generation)})`,
    )
  }
  if (!HANDLE_STATUSES.includes(doc.status as string)) {
    throw new ConnectxError(
      'handle_malformed',
      `Handle resolution document from ${url} declares status "${String(doc.status)}", not one of active / suspended / revoked`,
    )
  }
  if (doc.handle !== handle) {
    throw new ConnectxError(
      'handle_malformed',
      `Handle resolution document from ${url} describes handle "${String(doc.handle)}", but "${handle}" was requested`,
    )
  }
  return doc as unknown as HandleResolutionDocument
}

/** 一个已解析的 Handle。`domain` 单独给出来是因为 §9.2 L744 要求客户端展示 Handle 时
 *  突出显示域名部分 —— 那正是防混淆的着力点。 */
export interface ResolvedHandle {
  /** 归一化后的 Handle（§3.1 L101），可能和传进去的字符串不同大小写。 */
  handle: string
  /** §9.2 L744：展示时要突出的那一半。 */
  domain: string
  did: string
  status: HandleStatus
  /** 十进制字符串；用于缓存时效与"旧绑定回放"判断（§8.2 L705）。 */
  bindingGeneration: string
  document: HandleResolutionDocument
}

// 两个抓取共用的错误码：调用方对它们的动作是同一个（重试，或者补齐自己允许的主机），
// 所以码保持粗，由 `subject` 说明是**哪一份**文档失败 —— 与 ANP-07 那一组同一个道理。
// 唯一的例外是 body 不是 JSON：那和"JSON 但内容不合规"是同一种情况，都归 `handle_malformed`。
const HANDLE_FETCH_CODES: FetchErrorCodes = {
  subject: 'Handle resolution document',
  blocked: 'handle_fetch_failed',
  failed: 'handle_fetch_failed',
  timeout: 'handle_fetch_failed',
  tooLarge: 'handle_fetch_failed',
  tooManyRedirects: 'handle_fetch_failed',
  invalidDocument: 'handle_malformed',
}
const HANDLE_ENDPOINT_FETCH_CODES: FetchErrorCodes = {
  ...HANDLE_FETCH_CODES,
  subject: 'Handle binding endpoint document',
}

// 抓 Handle 自己的解析文档，并把 §4.8 那两个"根本没有这个 Handle"的状态码单拎出来。
// 它们和"抓取失败"不是一回事：404 / 410 是**一个答案**（从未注册 / 已撤销且永不
// 重新分配，L436–L437），重试不会改变它，所以值得让调用方分得开。
//
// 只在这一份文档上做这个改写：端点那边 404 是"这条绑定解引用不了"（规则 9），
// 与"没有这个 Handle"是两件事。
async function fetchResolutionDocument(url: string, options: HandleFetchOptions): Promise<unknown> {
  try {
    return await fetchControlledJson(url, options, HANDLE_FETCH_CODES)
  } catch (err) {
    if (isConnectxError(err) && (err.status === 404 || err.status === 410)) {
      throw new ConnectxError('handle_not_found', `Handle resolution at ${url} answered ${err.status}`, {
        cause: err,
        status: err.status,
      })
    }
    throw err
  }
}

/**
 * 网络策略。比 `ResolveDidOptions` 少了 `allowRedirects` / `maxRedirects`，而且是**故意
 * 少的**：见 `verifyHandleBinding` 的说明 —— 重定向会让文档来自一个没有被校验过的主机，
 * 于是类型层面就不给这个口子，而不是收下再忽略。
 */
export type HandleFetchOptions = Omit<ResolveDidOptions, 'allowRedirects' | 'maxRedirects'>

/**
 * 解析一个 Handle 得到它当前绑定的 DID（§4.1 L150 的流程第一步）。**解析不等于校验**：
 * 拿到 `did` 只说明这个 Provider 这么声称，它对不对要由 `verifyHandleBinding` 回答
 * （§6.3 L525–L532：展示类场景可以推迟，但一旦进入安全敏感操作就必须做）。
 *
 * 抛 `invalid_handle`（输入本身不是 Handle）、`handle_not_found`（§4.8 的 404 / 410）、
 * `handle_fetch_failed`（抓不到：网络 / 超时 / 超限 / 重定向过多，或**被网络策略拒绝** ——
 * 策略拒绝也归它，因为调用方对它们只有一个动作）、`handle_malformed`（body 不是 JSON，
 * 或不是一份合规的解析文档）。
 */
export async function resolveHandle(
  handle: string,
  options: HandleFetchOptions = {},
): Promise<ResolvedHandle> {
  const parsed = parseHandle(handle)
  const body = await fetchResolutionDocument(parsed.resolutionUrl, options)
  const document = assertHandleResolutionDocument(body, parsed.handle, parsed.resolutionUrl)
  return {
    handle: parsed.handle,
    domain: parsed.domain,
    did: document.did,
    status: document.status,
    bindingGeneration: document.binding_generation,
    document,
  }
}

// ---- 双向绑定校验（§6.3 / §6.3.1 / §6.3.2）--------------------------------------

/**
 * §6.3.2 L594–L598 的三种结果。**必须分开**，因为它们的强度不同：
 * `provider-confirmed` 只说明这个 DID 归这个 Provider 解析，**不**说明某个具体 Handle
 * 与它精确绑定；需要确认"具体 Handle"的场景（身份认证、授权决策、发消息前的收件人确认，
 * §6.3.1 规则 10 L582）**只能**接受 `exact-handle`。
 */
export type HandleBindingResult =
  /** 规则 7：返回的 `handle` 与输入**逐字相同**——这是唯一能确认「具体这个 Handle」的结果
   *  （规则 10 L587–L588 要求安全敏感场景必须拿到它）。 */
  | 'exact-handle'
  /** 规则 8：私密确认端点答"确认"，但不给出 `handle`——只确认了 Provider 与这个 DID 的
   *  关系，**推不出**某个具体 Handle 被确认（§6.2 L518）。 */
  | 'provider-confirmed'
  /** 附录 B.4：原生 `did:web` 的兼容模式——确认了 Handle → DID 的正向声明，以及 DID 文档
   *  对 Provider **域**的声明。不要求端点可解引用，也**不等于**上面两档中的任何一个
   *  （B.4 L31 明说）。 */
  | 'provider-domain'
  /** 规则 9：其余一切——该绑定不得视为已验证。 */
  | 'unverified'

/** 为什么没到 `exact-handle`。每个值对应 §6.3.1 的一条规则（或下面注明出处的那一条），
 *  因为不同规则的修法完全不同：`no_handle_service` 是 DID 持有者该补文档，`did_mismatch`
 *  则可能是攻击。 */
export type HandleBindingFailure =
  /** §4.8 L436–L437：解析端点回答 404（从未注册）或 410（已撤销）。 */
  | 'handle_not_found'
  /** 规则 1–2：Handle 自己的解析文档拿不到，或不是一份合规文档。 */
  | 'handle_unresolved'
  /** §4.7 L425–L427：状态是 `suspended` / `revoked` —— 该 Handle 处于"不可解析"状态。
   *  **这一条不在 §6.3.1 的十条里**，是 SDK 的判断（见 `verifyHandleBinding`）。 */
  | 'handle_not_active'
  /** 规则 3：该 DID 解析不出文档。 */
  | 'did_unresolved'
  /** §4.4 规则 1 L381 / MUST 6 L847：Handle 的 domain 与 DID 的主机名不一致。 */
  | 'did_host_mismatch'
  /** 规则 4：DID 文档里没有 `ANPHandleService` 条目 —— 没有反向声明，就没有绑定可验。 */
  | 'no_handle_service'
  /** 规则 5：`serviceEndpoint` 不是 `https` 绝对 URI。 */
  | 'endpoint_not_https'
  /** 规则 5：`serviceEndpoint` 的 hostname 不等于输入 Handle 的 domain。 */
  | 'endpoint_host_mismatch'
  /** 规则 6：`serviceEndpoint` 解引用失败（网络 / 超时 / 超限 / 非 2xx / 被网络策略拒绝）。 */
  | 'endpoint_unreachable'
  /** 规则 6：端点返回了一个不是 JSON 对象的东西，装不下 `did` / `handle` / `confirmed`。 */
  | 'endpoint_malformed'
  /** 规则 7 / 8：返回文档里的 `did` 与规则 2 拿到的 `did` 不一致。 */
  | 'did_mismatch'
  /** 规则 7 前半句：`serviceEndpoint` 不是这个 Handle 的标准 Resolution Endpoint。 */
  | 'endpoint_not_canonical'
  /** 规则 7 后半句：返回文档里的 `handle` 与输入 Handle 不一致。 */
  | 'handle_mismatch'
  /** 规则 8：既没有 `handle`，也没有 `confirmed = true`。 */
  | 'not_confirmed'

/**
 * `verifyHandleBinding` 的结论。判别联合而不是"带几个可选字段的对象"，是为了让失败
 * 分支不读原因就用不了，也让"我们没能查"不能被当成"查过了，通过"。
 *
 * 与 `AnpLoginResult` 同一条约定：`cause` 和 `detail` 是给调用方**自己的日志**用的，
 * **绝不要**回给对端 —— 它们点名主机、地址和解析内部细节。
 */
export type HandleBindingVerification =
  | {
      result: 'exact-handle' | 'provider-confirmed' | 'provider-domain'
      /** 归一化后的输入 Handle。 */
      handle: string
      /** 规则 2 拿到的 DID；主线两档还经规则 7 / 8 确认回来，`provider-domain` 没有。 */
      did: string
      /** 规则 5 校验过的 `serviceEndpoint`；主线两档还经规则 6 解引用过。 */
      serviceEndpoint: string
      /** 该 Handle 当前状态，已验证为 `active`。 */
      status: 'active'
      /** 十进制字符串；调用方拿去和自己的旧值比较，就能发现旧绑定回放（§8.2 L705）。 */
      bindingGeneration: string
    }
  | {
      result: 'unverified'
      handle: string
      reason: HandleBindingFailure
      /** 走到哪一步为止已经拿到的东西；没走到就是 `undefined`。 */
      did?: string
      serviceEndpoint?: string
      /** 失败规则实际看到了什么（两个对不上的主机、返回的另一个 Handle……）。 */
      detail?: string
      /** 底下那次抛出，例如被网络策略拒绝或 DNS 失败。 */
      cause?: unknown
    }

/** 一个 `unverified` 结论，字段按"走到哪一步"给。 */
function unverified(input: {
  handle: string
  reason: HandleBindingFailure
  did?: string
  serviceEndpoint?: string
  detail?: string
  cause?: unknown
}): HandleBindingVerification {
  return { result: 'unverified', ...input }
}

/** 提取 DID 的主机名：`didToUrl` 已经把 authority 段解出来并校验过了，`URL.hostname`
 *  顺手按 §4.4 L381 的要求丢掉端口（`example.com%3A8800` → `example.com`）。 */
function didHostname(did: string): string {
  return new URL(didToUrl(did)).hostname
}

/** 从 DID 文档里挑出这条绑定要用的 `ANPHandleService` 条目。
 *
 *  §6.3.1 的流程是**单条目**写的（L577"该条目"），而一个 DID 是可能在同一域下持有多个
 *  Handle 的（§4.6 L415：不同域可以有相同 local-part，反过来同一域的多个 Handle 也各有
 *  自己的条目）。所以主线：优先取 `serviceEndpoint` **就是**这个 Handle 标准端点的条目
 *  —— 那正是声明了*这个* Handle 的那条（规则 7 的前半句）；没有这样的条目再退回第一条，
 *  于是规范描述的单条目情形与之前完全一致，多条目也不会因为顺序而误判。
 *
 *  原生 `did:web` 没有可比的标准端点（兼容模式不解引用，见 `verifyHandleBinding`），
 *  改取第一条**位置合法**的条目 —— 否则一个 did:web DID 只要把某个无关条目排在前面，
 *  就会拿到 `endpoint_host_mismatch` 这种和它无关的结论。 */
function handleServiceEntries(didDocument: Record<string, unknown>): DidDocumentService[] {
  const services = Array.isArray(didDocument.service) ? (didDocument.service as DidDocumentService[]) : []
  return services.filter((s) => s !== null && typeof s === 'object' && s.type === HANDLE_SERVICE_TYPE)
}

/** 规则 5 的位置检查：`serviceEndpoint` 必须是 `https` 绝对 URI，且 hostname 就是输入
 *  Handle 的 domain（§4.4 规则 1 L381 把绑定绑在 Handle 的域上，规则 5 要求端点同域）。
 *
 *  抽成函数是因为它有**两个**调用点：选条目时（原生 `did:web` 要挑出位置合法的那条）
 *  和真正校验时。返回 `undefined` 表示通过。 */
function endpointLocationProblem(
  entry: DidDocumentService,
  domain: string,
): { reason: 'endpoint_not_https' | 'endpoint_host_mismatch'; detail: string } | undefined {
  let url: URL
  try {
    url = new URL(entry.serviceEndpoint)
  } catch {
    // 相对 URL（`/.well-known/…`）走的就是这一支：它没有 origin 可比，一步都不能用。
    return {
      reason: 'endpoint_not_https',
      detail: `serviceEndpoint "${entry.serviceEndpoint}" is not an absolute URL`,
    }
  }
  if (url.protocol !== 'https:') {
    return {
      reason: 'endpoint_not_https',
      detail: `serviceEndpoint "${entry.serviceEndpoint}" is not https`,
    }
  }
  if (url.hostname !== domain) {
    return {
      reason: 'endpoint_host_mismatch',
      detail: `serviceEndpoint host "${url.hostname}" is not the Handle domain "${domain}"`,
    }
  }
  return undefined
}

/** 把 `resolveHandle` 的抛出映射成结论的原因：只有"根本没有这个 Handle"值得单独说。 */
function resolutionFailure(err: unknown): HandleBindingFailure {
  return isConnectxError(err) && err.code === 'handle_not_found' ? 'handle_not_found' : 'handle_unresolved'
}

/**
 * 执行 §6.3.1 的双向绑定校验，返回 §6.3.2 的三种结果之一。
 *
 * **为什么需要它**：Handle Provider 可以声称任何 Handle 指向任何 DID（§6 L476 就是冲着
 * 这个来的）。正向声明（Provider 说 Handle → DID）不足以为凭，要加上 DID 持有者在自己的
 * DID 文档里的反向声明（规则 4），并解引用它（规则 6），两边对上了才算 `exact-handle`。
 * 需要确认"具体 Handle"的安全敏感场景**只能**用 `exact-handle`（规则 10 L582）。
 *
 * **绝不跟随重定向**。规则 7 要求 `serviceEndpoint` 与"由**输入 Handle** 构造出的标准
 * 端点"完全一致，而返回文档的 **`did` 与 `handle` 必须与输入一致** —— 也就是说，能得出
 * `exact-handle` 的那份字节，必须来自输入 Handle 自己的域。跟随重定向会让文档来自一个
 * 没被校验过的主机，§8.3 L713 明确要求重定向目标仍要满足输入 Handle 域的验证规则，而
 * §4.8 L444–L446 只把重定向当作迁移**提示**、禁止凭它接受绑定。所以 `allowRedirects`
 * 不在 `HandleFetchOptions` 里：类型层面就没有这个口子，而不是收下再悄悄忽略。代价是
 * 一个正在迁移、临时返回 301 的 Provider 会得到 `unverified` —— 但 §8.1 L689/L716 要求
 * Provider 必须实现标准端点、迁移期间应当维持新旧两端可解析，所以合规的迁移不需要客户端
 * 跟任何一跳。
 *
 * **`status` 必须为 `active`**。这一条**超出 §6.3.1 的十条规则**，是 SDK 自己加的，出处是
 * §4.7 L425–L427：`suspended` 是"暂时不可解析"、`revoked` 是"已撤销、不可恢复"，把一个
 * 处于这两种状态的 Handle 当成已验证绑定，与 §4.7 直接冲突。取的是**失败关闭**的方向：
 * 宁可让调用方看到 `unverified` 去查 §4.7，也不让它拿着一个已撤销身份的 Handle 继续走。
 *
 * **校验失败不抛**。规则 9（L581）把一长串情况都归为"该绑定不得视为已验证"，那是一个
 * **结论**而不是异常，所以它们全部走返回值。只有输入本身不是 Handle（`invalid_handle`）
 * 才是调用方的错误、照抛。
 *
 * **原生 `did:web` 到 `provider-domain` 为止**（附录 B.4）。B.4 L31 的措辞是它"确认了
 * Handle → DID 的正向声明，也确认了 DID 对 Provider 域的声明"，但"不要求精确端点解引用，
 * 也不自动得到 WBA 主线的 `exact-handle` 或私密端点 `provider-confirmed` 结果"。所以它
 * 有自己的结果值、在规则 5 通过之后立刻返回，从不解引用端点、也从不检查指纹（B.4 L57 ——
 * did:web 的 DID 里根本没有指纹可查）。代价是确定的：§6.3.1 规则 10（L587–L588）要求
 * 安全敏感场景必须拿到规则 7 的精确结果，因此原生 did:web 的绑定**永远不能满足**这类流程。
 *
 * 抛 `invalid_handle`；其余情况一律返回 `unverified`，原因在 `reason`、细节在 `detail` /
 * `cause`（两者都只给你自己的日志）。
 */
export async function verifyHandleBinding(
  handle: string,
  options: HandleFetchOptions = {},
): Promise<HandleBindingVerification> {
  const parsed = parseHandle(handle)
  const canonical = parsed.resolutionUrl

  // ---- 规则 1–2：解析输入 Handle ----
  // `resolveHandle` 会重新 parse 一次（输入已经是归一化形式，必过），换来一个"只需一句
  // 话说明它做了什么"的调用。
  let resolved: ResolvedHandle
  try {
    resolved = await resolveHandle(parsed.handle, options)
  } catch (err) {
    return unverified({ handle: parsed.handle, reason: resolutionFailure(err), cause: err })
  }
  const did = resolved.did
  // 原生 did:web 走附录 B 的兼容模式；本题里它只改两处：条目怎么选、以及到哪一步为止。
  const isNativeWeb = did.startsWith('did:web:')

  // ---- §4.7：不可解析的状态不能当成已验证绑定（见上面的说明）----
  if (resolved.status !== 'active') {
    return unverified({
      handle: parsed.handle,
      reason: 'handle_not_active',
      did,
      detail: `Handle status is "${resolved.status}"`,
    })
  }

  // ---- §4.4 规则 1：Handle 的 domain MUST 与 DID 的主机名一致 ----
  // 这是 §6 那道防御的第一道：没有它，一个恶意 Provider 可以把任意 Handle 指向他人
  // 的 DID。端口按 L381 忽略（DID authority 可以带编码端口，Handle 永远不带）。
  let didHost: string
  try {
    didHost = didHostname(did)
  } catch (err) {
    // DID 连主机名都取不出来（例如一个 CAIP-10 账户 id）——§4.3 L196 说这个字段是
    // "该 Handle 当前绑定的 did:wba DID"，那这种 DID 本身就说不通。
    return unverified({
      handle: parsed.handle,
      reason: 'did_host_mismatch',
      did,
      detail: `Cannot derive a hostname from "${did}"`,
      cause: err,
    })
  }
  if (didHost !== parsed.domain) {
    return unverified({
      handle: parsed.handle,
      reason: 'did_host_mismatch',
      did,
      detail: `Handle domain "${parsed.domain}" is not the DID's host "${didHost}"`,
    })
  }

  // ---- 规则 3：解析 DID 文档 ----
  let didDocument: Record<string, unknown>
  try {
    didDocument = (await resolveDidDocument(did, options)).document
  } catch (err) {
    return unverified({ handle: parsed.handle, reason: 'did_unresolved', did, cause: err })
  }

  // ---- 规则 4：找反向声明 ----
  const entries = handleServiceEntries(didDocument)
  if (entries.length === 0) {
    return unverified({
      handle: parsed.handle,
      reason: 'no_handle_service',
      did,
      detail: `The DID document publishes no ${HANDLE_SERVICE_TYPE} service entry`,
    })
  }
  const entry = (
    isNativeWeb
      ? entries.find((e) => endpointLocationProblem(e, parsed.domain) === undefined)
      : entries.find((e) => e.serviceEndpoint === canonical)
  ) ?? entries[0]!

  // ---- 规则 5：端点必须是 https 绝对 URI，且 hostname 就是输入 Handle 的域 ----
  const problem = endpointLocationProblem(entry, parsed.domain)
  if (problem) {
    return unverified({
      handle: parsed.handle,
      reason: problem.reason,
      did,
      serviceEndpoint: entry.serviceEndpoint,
      detail: problem.detail,
    })
  }

  // ---- 附录 B.4（原生 did:web）：到此为止 ----
  // 原生 did:web 走兼容模式：只确认「Handle → DID」的正向声明与 DID 文档对 Provider
  // 域的声明，**不解引用端点**（B.4 L31 明说它「不要求精确端点解引用，也不自动得到
  // WBA 主线的 `exact-handle` 或私密端点 `provider-confirmed` 结果」），也**不做**
  // `e1_`/`k1_` 指纹检查（B.4 L57）——那个检查对本方法根本不成立，did:web 的 DID 里
  // 没有指纹。所以这一档有它自己的结果值，而不是复用那两个：把 domain 声明当成
  // `provider-confirmed` 会是凭空抬高强度，而 §6.3.1 规则 10（L587–L588）要求安全敏感
  // 场景必须拿到规则 7 的精确结果——原生 did:web 因此**永远到不了** `exact-handle`，
  // 需要确认具体 Handle 的流程不能用它。这是 B.4 自己的结论，不是本 SDK 的收缩。
  if (isNativeWeb) {
    return {
      result: 'provider-domain',
      handle: parsed.handle,
      did,
      serviceEndpoint: entry.serviceEndpoint,
      status: 'active',
      bindingGeneration: resolved.bindingGeneration,
    }
  }

  const endpoint = entry.serviceEndpoint
  // ---- 规则 6：解引用端点 ----
  let body: unknown
  try {
    body = await fetchControlledJson(endpoint, options, HANDLE_ENDPOINT_FETCH_CODES)
  } catch (err) {
    return unverified({
      handle: parsed.handle,
      reason: 'endpoint_unreachable',
      did,
      serviceEndpoint: endpoint,
      cause: err,
    })
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return unverified({
      handle: parsed.handle,
      reason: 'endpoint_malformed',
      did,
      serviceEndpoint: endpoint,
      detail: `serviceEndpoint "${endpoint}" did not return a JSON object`,
    })
  }
  const returned = body as Record<string, unknown>

  // ---- 规则 7 / 8：两条路都要求 `did` 回到规则 2 的那个 ----
  if (returned.did !== did) {
    return unverified({
      handle: parsed.handle,
      reason: 'did_mismatch',
      did,
      serviceEndpoint: endpoint,
      detail: `The endpoint answers for "${String(returned.did)}", not "${did}"`,
    })
  }

  // ---- 规则 7：文档里有 `handle` —— 那它必须与输入完全一致，且端点必须是标准端点 ----
  // `undefined` 才叫"不包含 `handle`"（L580 的措辞是"不包含"，所以一个存在但非字符串的
  // `handle` 仍然算包含，会在这里失败）。
  if (returned.handle !== undefined) {
    if (returned.handle !== parsed.handle) {
      return unverified({
        handle: parsed.handle,
        reason: 'handle_mismatch',
        did,
        serviceEndpoint: endpoint,
        detail: `The endpoint answers for handle "${String(returned.handle)}", not "${parsed.handle}"`,
      })
    }
    if (endpoint !== canonical) {
      // 私密确认端点返回了 `handle`：Provider 对**任何**它托管的 Handle 都会这么答，
      // 所以这不是"精确反向确认"（§6.2 L518、规则 8 L580 都这么说）。
      return unverified({
        handle: parsed.handle,
        reason: 'endpoint_not_canonical',
        did,
        serviceEndpoint: endpoint,
        detail: `serviceEndpoint is not this Handle's standard Resolution Endpoint ("${canonical}")`,
      })
    }
    return {
      result: 'exact-handle',
      handle: parsed.handle,
      did,
      serviceEndpoint: endpoint,
      status: 'active',
      bindingGeneration: resolved.bindingGeneration,
    }
  }

  // ---- 规则 8：没有 `handle`，但 `confirmed = true` —— 只到 provider 关系为止 ----
  if (returned.confirmed === true) {
    return {
      result: 'provider-confirmed',
      handle: parsed.handle,
      did,
      serviceEndpoint: endpoint,
      status: 'active',
      bindingGeneration: resolved.bindingGeneration,
    }
  }

  // ---- 规则 9：其余一切都不得视为已验证 ----
  return unverified({
    handle: parsed.handle,
    reason: 'not_confirmed',
    did,
    serviceEndpoint: endpoint,
    detail: `The endpoint returned neither a matching "handle" nor "confirmed": true`,
  })
}
