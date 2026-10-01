// ANP-09 P1 —— JSON-RPC 2.0 绑定、`params` 形状与 ANP 错误对象。
//
// 逐条来自 `chinese/message/01-核心绑定.md`（`main`）。这里只放**信封层**：
// `direct.send` 之类的业务校验在各自 Profile 里。两处都引同一份错误码表，
// 服务端发的码与客户端读的码因此不可能对不上。

import { ConnectxError } from '../errors'

/** P1 §4.1 L125–127：`jsonrpc` MUST 精确等于这个字符串。 */
export const JSONRPC_VERSION = '2.0'

/** P1 §6.2.2 L285 起的 Profile 标识。`.v1` / `.v2` 是 wire 上的值，不含小版本。 */
export const ANP_PROFILE = {
  coreBinding: 'anp.core.binding.v1',
  identityDiscovery: 'anp.identity.discovery.v1',
  directBase: 'anp.direct.base.v1',
  groupBase: 'anp.group.base.v2',
  directE2ee: 'anp.direct.e2ee.v2',
  groupE2ee: 'anp.group.e2ee.v2',
  attachment: 'anp.attachment.v1',
  federationRelay: 'anp.federation.relay.v1',
} as const

export type AnpProfileId = (typeof ANP_PROFILE)[keyof typeof ANP_PROFILE]

/** P1 §6.2.3 L295–298：`security_profile` 的全部允许值。 */
export const ANP_SECURITY_PROFILE = {
  transportProtected: 'transport-protected',
  directE2ee: 'direct-e2ee',
  groupE2ee: 'group-e2ee',
} as const

export type AnpSecurityProfile =
  (typeof ANP_SECURITY_PROFILE)[keyof typeof ANP_SECURITY_PROFILE]

/** P1 §6.2.5 L346、§6.2.5.1 L365–379：`meta.target.kind` 的全部允许值。 */
export const ANP_TARGET_KIND = {
  agent: 'agent',
  group: 'group',
  service: 'service',
} as const

export type AnpTargetKind = (typeof ANP_TARGET_KIND)[keyof typeof ANP_TARGET_KIND]

/** P1 §6.2.5 L343–349。 */
export interface AnpTarget {
  kind: AnpTargetKind
  did: string
}

/**
 * P1 §6.2 L258–460 的**核心** `meta` 字段。未知的**核心**字段 MUST 拒绝，
 * 只有 `x_` 前缀的实现扩展 MAY 忽略（§12.1 L776–777）。
 *
 * `trace_id`（§6.2.9 L415–422）仍在规范里，但已"不再作为标准互通字段"。
 * 它留在这个集合里：它不是**未知**字段，拒掉一个规范写过的字段比忽略它更糟；
 * 它同样 MUST NOT 参与任何安全 / 授权 / 幂等判断（§13.3），本模块不读它。
 */
export interface AnpMeta {
  /** §6.2.1 L262–273：已废弃，仅为兼容保留。接收方 MUST NOT 用它选 Profile。 */
  anp_version?: string
  /** §6.2.2 L275–288：MUST。本次请求的**唯一**解释 Profile。 */
  profile: string
  /** §6.2.3 L290–302：MUST。 */
  security_profile: string
  /** §6.2.4 L304–312：除匿名公共发现外 MUST。业务语义上的发起主体。 */
  sender_did?: string
  /** §6.2.4.1 L314–323：条件式。非 P5/P6 的 E2EE 操作 MUST NOT 出现。 */
  sender_device_id?: string
  /** §6.2.4.2 L325–334：条件式。同上。 */
  recipient_device_id?: string
  /** §6.2.5 L338–359：方法存在协议级目标时 MUST。 */
  target?: AnpTarget
  /** §6.2.6 L385–394：所有改变状态的操作 MUST。 */
  operation_id?: string
  /** §6.2.7 L396–406：message-bearing 操作 MUST。 */
  message_id?: string
  /** §6.2.8 L408–413：SHOULD。RFC 3339。 */
  created_at?: string
  /** §6.2.9 L415–422：见上。 */
  trace_id?: string
  /** §6.2.10 L424–436：message-bearing 操作 MUST。主业务负载类型，不是容器类型。 */
  content_type?: string
  /** §12.1 L777：`x_` 前缀的实现扩展字段。 */
  [x_extension: `x_${string}`]: unknown
}

/** 核心 `meta` 字段名，用于 §12.1 的未知字段拒绝。 */
export const ANP_META_FIELDS: ReadonlySet<string> = new Set([
  'anp_version',
  'profile',
  'security_profile',
  'sender_did',
  'sender_device_id',
  'recipient_device_id',
  'target',
  'operation_id',
  'message_id',
  'created_at',
  'trace_id',
  'content_type',
])

/** P1 附录 A —— `auth` 的形状。`auth` 本身 MUST NOT 进入摘要输入（A.1 L982）。 */
export interface AnpOriginProof {
  /** A.2 L1015：MUST 使用 sha-256。RFC 9530 Content-Digest 字段值。 */
  contentDigest: string
  /** A.2 L1016：MUST 使用标签 `sig1`。RFC 9421 Signature-Input 字段值。 */
  signatureInput: string
  /** A.2 L1017：MUST 使用标签 `sig1`。RFC 9421 Signature 字段值。 */
  signature: string
}

/** A.1 L980–981：`scheme` MUST 等于它，且 `origin_proof` MUST 存在。 */
export const ORIGIN_PROOF_SCHEME = 'anp-rfc9421-origin-proof-v1'

export interface AnpAuth {
  scheme: string
  origin_proof: AnpOriginProof
}

/** P1 §6.1 L212–230：顶层固定 `{meta, auth, body}`。 */
export interface AnpParams {
  meta: AnpMeta
  auth?: AnpAuth
  body: Record<string, unknown>
}

export interface AnpRequest {
  jsonrpc: typeof JSONRPC_VERSION
  id: string
  method: string
  params: AnpParams
}

export interface AnpNotification {
  jsonrpc: typeof JSONRPC_VERSION
  method: string
  params: AnpParams
}

export interface AnpErrorData {
  /** §10.2 L687–695：**仅当** `code` 落在 ANP 自定义段（1000+）时 MUST 存在。
   *  标准码（-32xxx）上没有它——所以它是可选的，不是可省事的。 */
  anp_code?: string
  retryable?: boolean
  details?: Record<string, unknown>
}

export interface AnpErrorObject {
  code: number
  message: string
  data?: AnpErrorData
}

export interface AnpSuccessResponse {
  jsonrpc: typeof JSONRPC_VERSION
  id: string
  result: Record<string, unknown>
}

export interface AnpErrorResponse {
  jsonrpc: typeof JSONRPC_VERSION
  id: string
  error: AnpErrorObject
}

export type AnpResponse = AnpSuccessResponse | AnpErrorResponse

/** §10.1 L669–675：这些形状 SHOULD 用 JSON-RPC 标准码，而不是 ANP 自定义码。 */
export const JSON_RPC_ERROR = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const

/**
 * P1 §10.3 L699–722 的公共错误码表。**码段是规范的公共契约**：
 * 客户端靠 `error.data.anp_code` 分支，服务端靠它发。
 */
export const ANP_ERRORS = {
  'anp.invalid_request_id': 1000,
  'anp.unsupported_profile': 1001,
  'anp.unsupported_security_profile': 1002,
  'anp.invalid_params_shape': 1003,
  'anp.batch_not_supported': 1004,
  'anp.unauthorized': 1005,
  'anp.forbidden': 1006,
  'anp.target_not_found': 1007,
  'anp.idempotency_conflict': 1008,
  'anp.unsupported_content_type': 1009,
  'anp.delivery_rejected': 1010,
  'anp.rate_limited': 1011,
  'anp.temporarily_unavailable': 1012,
  'anp.invalid_security_binding': 1013,
  'anp.invalid_target_binding': 1014,
  'anp.device_binding_required': 1015,
  'anp.device_binding_invalid': 1016,
  'anp.device_not_eligible': 1017,
  'anp.device_state_changed': 1018,
  'anp.did_superseded': 1019,
  'anp.did_transition_invalid': 1020,
  'anp.did_transition_conflict': 1021,
} as const

export type AnpErrorCode = keyof typeof ANP_ERRORS

/**
 * 一个 `anp_code` 的名字。
 *
 * P1 §10.3 L697–722 固定的是**公共**那一段（1000–1021）。各业务 Profile 在那之外
 * 追加自己的段（P3 2000–2007、P4 3000–3010、P5 4000–4012…，见
 * `message-service.md` §4.1），所以这个位置**不是**封闭联合——写成 `AnpErrorCode`
 * 会让服务端拿不到自己 Profile 的码。`(string & {})` 是 TS 的惯用写法：任意字符串
 * 都收，同时保留公共码的字面量补全。
 */
export type AnpErrorName = AnpErrorCode | (string & {})

/**
 * 一次拒绝。`anpCode` 只在 `code` 落在 ANP 自定义段（1000+）时才有值——
 * §10.2 L695 只对那段强制 `error.data.anp_code`。标准码（-32xxx）靠 `message` 区分。
 */
export interface AnpRejection {
  code: number
  anpCode?: AnpErrorName
  retryable: boolean
  message: string
  details?: Record<string, unknown>
}

/** §10.2 L681–693 的错误对象。 */
export function toErrorObject(rejection: AnpRejection): AnpErrorObject {
  return {
    code: rejection.code,
    message: rejection.message,
    data: {
      // `anp_code` 只在 code 落在 ANP 自定义段（1000+）时出现——§10.2 L695 只对那段
      // 强制它。标准码（-32xxx）靠 `message` 分支；硬塞一个空串会让客户端以为那是
      // 一个可以分支的码。
      ...(rejection.anpCode !== undefined ? { anp_code: rejection.anpCode } : {}),
      retryable: rejection.retryable,
      details: rejection.details ?? {},
    },
  }
}

/** 用 ANP 公共错误码表构造一次拒绝。 */
export function anpRejection(
  anpCode: AnpErrorCode,
  message: string,
  opts: { retryable?: boolean; details?: Record<string, unknown> } = {},
): AnpRejection {
  return {
    code: ANP_ERRORS[anpCode],
    anpCode,
    retryable: opts.retryable ?? false,
    message,
    ...(opts.details ? { details: opts.details } : {}),
  }
}

/** 用 JSON-RPC 标准码构造一次拒绝（§10.1 L669–675）。 */
export function rpcRejection(
  code: (typeof JSON_RPC_ERROR)[keyof typeof JSON_RPC_ERROR],
  message: string,
  details?: Record<string, unknown>,
): AnpRejection {
  return {
    code,
    retryable: false,
    message,
    ...(details ? { details } : {}),
  }
}

/**
 * 用**业务 Profile 自己的**错误码构造一次拒绝。
 *
 * `code` 与 `anpCode` 必须来自同一份 Profile 码表，所以由调用方同时给出——规范里
 * 那张表就是这两列，分开硬编码等于给了写错其中一列的机会。
 * （P1 公共段的便捷入口是 {@link anpRejection}。）
 */
export function profileRejection(
  code: number,
  anpCode: string,
  message: string,
  opts: { retryable?: boolean; details?: Record<string, unknown> } = {},
): AnpRejection {
  return {
    code,
    anpCode,
    retryable: opts.retryable ?? false,
    message,
    ...(opts.details ? { details: opts.details } : {}),
  }
}

export type EnvelopeCheck<T> = { ok: true; value: T } | { ok: false; error: AnpRejection }

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * §12.1 L776–780：未知**核心** `meta` 字段 MUST 拒绝；`x_` 前缀 MAY 忽略；
 * 未知 `auth` 字段 MUST 拒绝。返回第一个越界字段名，或 `undefined`。
 */
export function firstUnknownMetaField(meta: Record<string, unknown>): string | undefined {
  return Object.keys(meta).find((k) => !ANP_META_FIELDS.has(k) && !k.startsWith('x_'))
}

/**
 * 解析并校验一个入站请求 / 通知（P1 §4–§6）。
 *
 * 顺序是刻意的，且与规范里各条的 MUST 一一对应：
 * 1. batch（§5.4 L177–179）—— 顶层是数组就是 batch，先判，否则后面的形状检查会误诊；
 * 2. 信封基本形状（§4.1 L127、§5.2 L157–160、§5.6 L201）；
 * 3. `params` 形状（§5.1 L151、§6.1 L224–230）；
 * 4. `meta` 必填与未知字段（§6.2.2 L278、§6.2.3 L293、§12.1 L776–777）；
 * 5. `meta.target` 的形状（§6.2.5 L343–359）。
 *
 * **不是每一条 MUST 都在这里**：目标建模模式（§6.2.5.1 L382）与设备 selector
 * （§6.2.4.1 L317）要看具体方法的声明，属于 Profile 层，调用方在本函数之后再查。
 */
export function parseEnvelope(
  raw: unknown,
): EnvelopeCheck<AnpRequest | AnpNotification> {
  // §5.4 —— 客户端 MUST NOT 发 batch；服务端收到时 MUST 拒绝。
  if (Array.isArray(raw)) {
    return {
      ok: false,
      error: anpRejection('anp.batch_not_supported', 'ANP does not support JSON-RPC batch'),
    }
  }

  if (!isPlainObject(raw)) {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'Request must be a JSON object') }
  }

  // §4.1 L127 —— 精确等于 "2.0"。
  if (raw.jsonrpc !== JSONRPC_VERSION) {
    return {
      ok: false,
      error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'jsonrpc MUST be exactly "2.0"'),
    }
  }

  const method = raw.method
  if (typeof method !== 'string' || method.length === 0) {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'method MUST be a non-empty string') }
  }
  // §5.5 L188 —— 方法名 MUST NOT 以 `rpc.` 开头。
  if (method.startsWith('rpc.')) {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.METHOD_NOT_FOUND, `Method "${method}" uses the reserved "rpc." prefix`) }
  }

  // §5.2 L157–160 —— id 非空字符串；数字与 null 都不行。
  // 有 id = Request，无 id = Notification（§6.1 图 P1-2）。`null` 既不是 Request
  // 也不是合法的 Notification 形状，所以 §5.2 让服务端把它拒成 invalid_request_id。
  const hasId = Object.prototype.hasOwnProperty.call(raw, 'id')
  if (hasId) {
    const id = raw.id
    if (typeof id !== 'string' || id.length === 0) {
      return {
        ok: false,
        error: anpRejection('anp.invalid_request_id', 'id MUST be a non-empty string', {
          details: { received: id === null ? 'null' : typeof id },
        }),
      }
    }
  }

  const params = raw.params
  // §5.1 L151 —— params MUST 为对象，MUST NOT 是数组。
  if (Array.isArray(params)) {
    return {
      ok: false,
      error: anpRejection('anp.invalid_params_shape', 'params MUST be an object, not an array'),
    }
  }
  if (!isPlainObject(params)) {
    return {
      ok: false,
      error: anpRejection('anp.invalid_params_shape', 'params MUST be an object'),
    }
  }

  // §6.1 L230 —— 除 meta / auth / body 之外的顶层成员，只有 Profile 明确定义时才允许。
  const extraTop = Object.keys(params).find((k) => k !== 'meta' && k !== 'auth' && k !== 'body')
  if (extraTop !== undefined) {
    return {
      ok: false,
      error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, `Unknown top-level params member "${extraTop}"`),
    }
  }

  const meta = params.meta
  if (!isPlainObject(meta)) {
    return { ok: false, error: anpRejection('anp.invalid_params_shape', 'params.meta MUST be an object') }
  }
  if (!isPlainObject(params.body)) {
    return { ok: false, error: anpRejection('anp.invalid_params_shape', 'params.body MUST be an object') }
  }

  // §6.2.2 L278 / §6.2.3 L293 —— 两个 MUST 的字符串字段。
  if (typeof meta.profile !== 'string' || meta.profile.length === 0) {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'meta.profile MUST be a non-empty string') }
  }
  if (typeof meta.security_profile !== 'string' || meta.security_profile.length === 0) {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'meta.security_profile MUST be a non-empty string') }
  }

  const unknown = firstUnknownMetaField(meta)
  if (unknown !== undefined) {
    return {
      ok: false,
      error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, `Unknown core meta field "${unknown}"`, {
        field: unknown,
      }),
    }
  }

  if (meta.target !== undefined) {
    const target = meta.target
    if (!isPlainObject(target)) {
      return { ok: false, error: anpRejection('anp.invalid_target_binding', 'meta.target MUST be an object') }
    }
    const kind = target.kind
    if (kind !== 'agent' && kind !== 'group' && kind !== 'service') {
      return {
        ok: false,
        error: anpRejection('anp.invalid_target_binding', 'meta.target.kind MUST be one of agent | group | service', {
          details: { kind: typeof kind === 'string' ? kind : typeof kind },
        }),
      }
    }
    // §6.2.5 L355 —— target.did MUST NOT 直接承载传输层 URL。
    if (typeof target.did !== 'string' || target.did.length === 0) {
      return { ok: false, error: anpRejection('anp.invalid_target_binding', 'meta.target.did MUST be a non-empty string') }
    }
    if (/^https?:\/\//i.test(target.did)) {
      return {
        ok: false,
        error: anpRejection('anp.invalid_target_binding', 'meta.target.did MUST NOT be a transport-layer URL'),
      }
    }
  }

  // auth 可选（§6.1 L228）；出现时形状必须对，且未知字段 MUST 拒绝（§12.1 L778）。
  if (params.auth !== undefined) {
    const auth = params.auth
    if (!isPlainObject(auth)) {
      return { ok: false, error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, 'params.auth MUST be an object') }
    }
    const extraAuth = Object.keys(auth).find((k) => k !== 'scheme' && k !== 'origin_proof')
    if (extraAuth !== undefined) {
      return {
        ok: false,
        error: rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, `Unknown auth field "${extraAuth}"`),
      }
    }
  }

  // `params` 到这里已经验过 meta / body 都是对象，但它的静态类型仍是
  // `Record<string, unknown>`——校验与类型收窄是两件事，这里显式跨过去。
  const checked = params as unknown as AnpParams
  const envelope = hasId
    ? ({ jsonrpc: JSONRPC_VERSION, id: raw.id as string, method, params: checked } as AnpRequest)
    : ({ jsonrpc: JSONRPC_VERSION, method, params: checked } as AnpNotification)

  return { ok: true, value: envelope }
}

/** 区分 Request 与 Notification（§5.6 L201：只有 Notification 不要求回响应）。 */
export function isNotification(
  envelope: AnpRequest | AnpNotification,
): envelope is AnpNotification {
  return !Object.prototype.hasOwnProperty.call(envelope, 'id')
}

/** {@link buildMessageRequest} 的全部输入。 */
export interface BuildMessageRequestInput {
  /** 本次交换的 id（§5.2 L157：非空字符串）。与 `operation_id` 是两件事：这个让
   *  **一次请求/响应**可对账，那个让**一次业务操作**幂等（P3 §8.2）。重试同一条消息
   *  时 `operation_id` 不变，`id` 应当换一个新的。 */
  id: string
  /** 方法名（§5.5 L183–188：字符串、不以 `rpc.` 开头）。 */
  method: string
  meta: AnpMeta
  /** `params.body`。省略即 `{}`——`anp.get_capabilities` 就是这样。 */
  body?: Record<string, unknown>
  /** 需要原发者证明的方法才带（P1 附录 A.1 L980–981）。 */
  auth?: AnpAuth
}

/**
 * 装配一个出站 Request（§4.1 L125–127、§5.1 L151、§6.1 L224–230）。
 *
 * 它存在的理由不是省几行，而是**出站信封只能有一处**：签名要绑的 `meta` / `body`
 * 与实际发出去的必须是同一份字节，两处各拼一次就是"签的和你发的不是一回事"这一类
 * 漏洞的入口。校验也只做**无条件**的那几条——`meta.target`、`auth` 是否必需由各
 * Profile 决定，在这里硬塞等于把 P3 的规则写进 P1。
 *
 * 不变量是它自己的输出必须能过 {@link parseEnvelope}：同一个包既发出站请求又解析
 * 入站请求，两份形状判断分家的代价是"自己发的自己收不了"。
 */
export function buildMessageRequest(input: BuildMessageRequestInput): AnpRequest {
  if (typeof input.id !== 'string' || input.id.length === 0) {
    throw new ConnectxError('message_invalid', 'Request id MUST be a non-empty string (P1 §5.2 L157)')
  }
  if (typeof input.method !== 'string' || input.method.length === 0) {
    throw new ConnectxError('message_invalid', 'method MUST be a non-empty string (P1 §5.5 L183)')
  }
  if (input.method.startsWith('rpc.')) {
    throw new ConnectxError(
      'message_invalid',
      `Method "${input.method}" uses the reserved "rpc." prefix (P1 §5.5 L188)`,
    )
  }
  // §12.1 L776–777：未知**核心** `meta` 字段 MUST 拒绝。类型上 `AnpMeta` 已经限定，
  // 但调用方可能是拼出来的对象（`as`、展开、JSON），所以这里再判一次。
  const unknown = firstUnknownMetaField(input.meta as unknown as Record<string, unknown>)
  if (unknown !== undefined) {
    throw new ConnectxError(
      'message_invalid',
      `Unknown core meta field "${unknown}" (P1 §12.1 L776)`,
    )
  }

  // 顺序照 §6.1 L224–230 写的 `{meta, auth, body}`。JSON 不关心键序，但让线上的
  // 字节与规范里那份例子同形，才看得出"这就是那个信封"。
  const params: AnpParams = {
    meta: input.meta,
    ...(input.auth !== undefined ? { auth: input.auth } : {}),
    body: input.body ?? {},
  }

  return { jsonrpc: JSONRPC_VERSION, id: input.id, method: input.method, params }
}
