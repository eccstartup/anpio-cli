// C3 —— 调用方的身份认证（message-service.md §5）。
//
// 验签本身是 core 的 `verifyOriginProofDetailed`：它在同一个调用里做完"摘要对得上、
// 钥被 `authentication` 授权、签名验得过、钥所属身份 == 锚点"。这一层只补三件
// 服务端才需要的事——**算出锚点**、把失败翻成规范的错误码、以及把时间窗一起判掉。
//
// 锚点必须由**同一个函数**按方法算出（§5.2 第 3 条）。这是本文件存在的主要理由：
// 普通请求的锚点是 `meta.sender_did`，群通知的锚点是 `body.group_did`。分成两处判断
// 就是这类实现最经典的漏洞——用 `sender_did` 去校验一条群通知，攻击者只要在自己域里
// 建一个 DID 就能冒充任何群。

import {
  originProofFreshness,
  profileRejection,
  verifyOriginProofDetailed,
  type AnpMeta,
  type AnpRejection,
  type AnpRequest,
  type KeyResolver,
  type LocateOptions,
  type OriginProofFailure,
  type ResolvedIdentityKey,
} from '@anpio-cli/core'

/**
 * 锚点取 `body.group_did` 的方法。
 *
 * 这三个都是从 Group DID 发出、投给某个 Agent DID 的通知，`body.group_did` 是那条
 * 群身份的权威位置：
 * - P4 §8.11 L922 要求 `meta.sender_did` **必须**等于 `body.group_did`（群通知）；
 * - P6 §13.6 L1692 把保留下来的 proof 的 `@target-uri` 定成
 *   `anp://group/<pct-encoded body.group_did>`。
 *
 * 取 `body` 而不是取 `meta.sender_did`，是为了在两者**不一致时**仍然拿群身份去校验：
 * 那两个字段相等是 P4 处理器要查的另一条 MUST，不是这一层可以假定的前提。
 */
const GROUP_ANCHORED = ['group.incoming', 'group.state_changed', 'group.e2ee.notice']

/**
 * 这次调用**应当**由谁发起。
 *
 * 返回 `undefined` 表示锚点无从确定（方法要 proof，而承载锚点的那个字段不在）。
 * 调用方不要把它读成"不需要认证"。
 */
export function callerAnchor(method: string, params: { meta: AnpMeta; body?: Record<string, unknown> }): string | undefined {
  if (GROUP_ANCHORED.includes(method)) {
    const groupDid = params.body?.group_did
    return typeof groupDid === 'string' && groupDid !== '' ? groupDid : undefined
  }
  const senderDid = params.meta.sender_did
  return typeof senderDid === 'string' && senderDid !== '' ? senderDid : undefined
}

/** 一对 `code` / `anp_code`，来自规范的某一张错误码表。 */
export interface ProfileCode {
  code: number
  anpCode: string
}

/**
 * 本族失败该报哪一对码。
 *
 * 认证失败在各 Profile 里的码**不一样**，所以它由方法表给出（[message-service.md] §4.1
 * 的码段划分），不由这一层决定。默认是 P1 §10.3 L706 的公共码。
 */
export interface AuthErrorCodes {
  /** `origin_proof` 缺失、不成形、摘要不符、钥解析不出、验签不过、或已过期。 */
  invalidProof: ProfileCode
  /** `keyid` 所属身份与调用方锚点不一致。 */
  anchorMismatch: ProfileCode
}

/** P1 §10.3 L706 —— 公共段只有这一个"没通过认证"。 */
export const P1_AUTH_CODES: AuthErrorCodes = {
  invalidProof: { code: 1005, anpCode: 'anp.unauthorized' },
  anchorMismatch: { code: 1005, anpCode: 'anp.unauthorized' },
}

/** P3 §11 L599–600 —— `direct.*` 把"证明不行"与"身份对不上"分成两个码。 */
export const DIRECT_AUTH_CODES: AuthErrorCodes = {
  invalidProof: { code: 2005, anpCode: 'direct.invalid_origin_proof' },
  anchorMismatch: { code: 2006, anpCode: 'direct.origin_did_mismatch' },
}

/** P4 §12 L1162–1163 —— 同一种拆分，`group.*` 的码段。 */
export const GROUP_AUTH_CODES: AuthErrorCodes = {
  invalidProof: { code: 3008, anpCode: 'group.invalid_origin_proof' },
  anchorMismatch: { code: 3009, anpCode: 'group.origin_did_mismatch' },
}

export interface AuthenticateInput {
  envelope: AnpRequest
  /** {@link callerAnchor} 的结果。`undefined` 也算失败——见那个函数的说明。 */
  expectedAnchor: string | undefined
  resolver: KeyResolver
  resolverOptions?: LocateOptions
  codes?: AuthErrorCodes
  /**
   * 时间窗。规范把"多久算过期"留给业务 Profile：P1 附录 A 只规定摘要与签名怎么算，
   * 没规定 `created` / `expires` 的窗口。所以默认**只**认 proof 自己带来的 `expires`
   * 与明显跑在前面的 `created`，不额外强加年龄上限——加了就是替 Profile 立规矩。
   */
  freshness?: { maxAgeSeconds?: number; skewSeconds?: number }
  now?: number
}

/**
 * 结局。
 *
 * `reason` **不**进线上错误对象（core 的 `verify.ts` 里写了原因：逐条回答"这个 keyid
 * 被授权了吗"就成了 oracle）。它是给本服务运维看的，调用方应该记日志而不是转发。
 *
 * `keyid` 是签名底里那个**声明**（A.2 L1018），验签过了才交出来。它比"某个 DID 发来的"
 * 更细一档：Profile 可以拿它比另一处声明的钥（P6 §13.3 L1626）。是否是 oracle 的顾虑不
 * 适用于它——它是调用方自己写进 proof 的字符串，而且只有在证明已经成立之后才交回。
 *
 * `nonce` 同样原样交回（它是 A.2 L1018 的可选参数）。一次性检查**不能**在这里做：那要兑
 * 一个键，而"哪一次调用算重放"只有幂等台账知道——§13.6 L1693 给 P6 四条控制方法要的那次
 * 单次 nonce 检查因此落在 `dispatch.ts` 的 `perform` 里（理由见 `consumeProofNonce`）。
 * 这里只把调用方写的那个值交出去；`undefined` 表示证明里没有这个参数。
 */
export type AuthResult =
  | { ok: true; key: ResolvedIdentityKey; keyid: string; nonce?: string }
  | { ok: false; error: AnpRejection; reason: OriginProofFailure | 'no_anchor' | 'expired' | 'stale' }

/**
 * 认证一次调用。
 *
 * 时间窗在这里判，而不是留给调用方记得去判：core 把 `originProofFreshness` 与验签
 * **分开**是对的（附录 A 不带策略），代价是它可能不被调用。服务端只有这一个入口，
 * 把两者并起来，那个代价就不存在了。
 */
export async function authenticate(input: AuthenticateInput): Promise<AuthResult> {
  const codes = input.codes ?? P1_AUTH_CODES
  const { envelope } = input

  if (input.expectedAnchor === undefined) {
    return {
      ok: false,
      reason: 'no_anchor',
      error: refuse(codes.invalidProof, denial('no_anchor')),
    }
  }

  const outcome = await verifyOriginProofDetailed({
    method: envelope.method,
    meta: envelope.params.meta,
    body: envelope.params.body,
    auth: envelope.params.auth,
    expectedAnchor: input.expectedAnchor,
    resolver: input.resolver,
    resolverOptions: input.resolverOptions,
  })
  if (!outcome.ok) {
    const pair = outcome.reason === 'anchor_mismatch' ? codes.anchorMismatch : codes.invalidProof
    return { ok: false, reason: outcome.reason, error: refuse(pair, denial(outcome.reason)) }
  }

  const freshness = originProofFreshness({
    ...(outcome.created !== undefined ? { created: outcome.created } : {}),
    ...(outcome.expires !== undefined ? { expires: outcome.expires } : {}),
    ...(input.freshness?.maxAgeSeconds !== undefined ? { maxAgeSeconds: input.freshness.maxAgeSeconds } : {}),
    ...(input.freshness?.skewSeconds !== undefined ? { skewSeconds: input.freshness.skewSeconds } : {}),
    ...(input.now !== undefined ? { now: input.now } : {}),
  })
  if (!freshness.ok) {
    // P3 §7.1 L390 把"过期"列在同一个码下：对调用方来说，一个过期的证明与一个伪造的
    // 证明没有区别，都是"你得重新签一个"。
    const reason = freshness.reason === 'expired' ? 'expired' : 'stale'
    return { ok: false, reason, error: refuse(codes.invalidProof, denial(reason)) }
  }

  return {
    ok: true,
    key: outcome.key,
    keyid: outcome.keyid,
    ...(outcome.nonce !== undefined ? { nonce: outcome.nonce } : {}),
  }
}

function refuse(pair: ProfileCode, message: string): AnpRejection {
  return profileRejection(pair.code, pair.anpCode, message)
}

/** 一句话说明，足够让对端知道"要重签"，不足以当 oracle 用。 */
function denial(reason: OriginProofFailure | 'no_anchor' | 'expired' | 'stale'): string {
  switch (reason) {
    case 'anchor_mismatch':
      return 'the origin proof was signed by a key that does not belong to the calling identity'
    case 'expired':
      return 'the origin proof has expired'
    case 'stale':
      return 'the origin proof is timestamped in the future'
    case 'no_anchor':
      return 'the request names no originator for this method to authenticate'
    default:
      return 'the origin proof did not verify'
  }
}
