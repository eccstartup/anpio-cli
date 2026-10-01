// ANP-09 P1 附录 A —— 校验 `auth.origin_proof`。
//
// 与 `sign.ts` 共用 `sro.ts` 的全部规范化（摘要、签名底、百分号编码）。这里只做
// **判定**：逐条比对，并把失败原因分类交出去。
//
// 这个函数**不**判断"这次调用该由谁发起"——caller anchor 是方法相关的规则
// （普通请求看 `meta.sender_did`，群通知看 `body.group_did`，见服务端设计 §5.2），
// 由调用方算出 `expectedAnchor` 传进来。把它塞进来，就等于把那条必须挨着写的
// 两行判断拆到两个文件里。

import { parseSignatureInput, signatureBaseBytes } from '../crypto/signatureBase'
import { decodeSignatureValue, verifySignatureWithKey } from '../crypto/verify'
import type { ParsedSignatureInput } from '../crypto/signatureBase'
import type { AnpAuth, AnpMeta } from './envelope'
import { ORIGIN_PROOF_SCHEME } from './envelope'
import type { KeyResolver, LocateOptions, ResolvedIdentityKey } from './locator'
import {
  ORIGIN_PROOF_COMPONENTS,
  ORIGIN_PROOF_LABEL,
  contentDigestOf,
  originProofSignatureBase,
  signedRequestObject,
} from './sro'

export interface VerifyOriginProofInput {
  method: string
  meta: AnpMeta
  body: Record<string, unknown>
  /**
   * 可选——P1 §6.1 L226 说 `auth` 只在 Profile 明确要求时才出现，而"这个方法是要求
   * proof 的方法"是方法表的判断，不是这个函数的判断。缺了它就是 `scheme_unsupported`
   * （P3 §7.1 L390 把"缺失"与"无效"列在同一个码下），而不是调用方的类型错误。
   */
  auth?: AnpAuth
  /**
   * 这次调用**应当**由谁发起。普通请求传 `meta.sender_did`；群通知传
   * `body.group_did`。服务端必须在同一个函数里按方法算出它——分两处判断就是
   * 那条经典漏洞（用 sender_did 去校验一条群通知）。
   */
  expectedAnchor: string
  resolver: KeyResolver
  resolverOptions?: LocateOptions
}

export type OriginProofFailure =
  /** `auth.scheme` 不是 `anp-rfc9421-origin-proof-v1`（A.1 L980）。 */
  | 'scheme_unsupported'
  /** `signatureInput` / `signature` 不是合法的 RFC 9421 字段值，或组件集合 /
   *  标签不是本 Profile 固定的那一套（A.2 L1016–1022）。 */
  | 'proof_malformed'
  /** 重算的 `contentDigest` 与送来的一致 (A.3)。 */
  | 'digest_mismatch'
  /** 解析不出 keyid 的钥（找不到 / 未被 `authentication` 授权 / 文档不可信）。 */
  | 'key_unresolved'
  /** keyid 所属身份 ≠ 调用方锚点。 */
  | 'anchor_mismatch'
  /** 签名底对上了，但签名验不过。 */
  | 'signature_invalid'

export type OriginProofOutcome =
  | {
      ok: true
      key: ResolvedIdentityKey
      /** A.2 L1018：签名底里那个 `keyid`，原样交回。
       *
       *  调用方已经把它读到手里才能解析钥，但只交回解析结果的话，这个字符串就丢了——
       *  而 Profile 有可能要拿它比**另一处**声明的钥（P6 §13.3 L1626 要求 `group.e2ee.send`
       *  的证明由 `meta.sender_device_id` 那台设备**当前的 `signing_key_id`** 做出）。没有
       *  这个字段，那条 MUST 只能靠重新解析一遍 `signatureInput` 才能判。
       *
       *  它是**声明**而不是结论：`key` 才是解析出来的材料。加了它不改变任何验证结果。 */
      keyid: string
      created?: number
      expires?: number
      nonce?: string
    }
  | { ok: false; reason: OriginProofFailure; cause?: unknown }

const FAIL = {
  schemeUnsupported: { ok: false, reason: 'scheme_unsupported' },
  proofMalformed: { ok: false, reason: 'proof_malformed' },
  digestMismatch: { ok: false, reason: 'digest_mismatch' },
  anchorMismatch: { ok: false, reason: 'anchor_mismatch' },
  signatureInvalid: { ok: false, reason: 'signature_invalid' },
} as const satisfies Record<string, OriginProofOutcome>

/** 布尔形式的 {@link verifyOriginProofDetailed}。 */
export async function verifyOriginProof(input: VerifyOriginProofInput): Promise<boolean> {
  return (await verifyOriginProofDetailed(input)).ok
}

/**
 * 校验一个 `origin_proof`，并报告是哪一条不过。
 *
 * 失败原因只给**服务端运维**看：原样转给对端就成了逐条回答"这个 DID 被授权了吗"
 * "这个 nonce 用过了吗"的 oracle。要不要披露、披露到哪一层，由调用方决定。
 */
export async function verifyOriginProofDetailed(
  input: VerifyOriginProofInput,
): Promise<OriginProofOutcome> {
  const proof = input.auth?.origin_proof
  if (input.auth?.scheme !== ORIGIN_PROOF_SCHEME || proof === undefined) {
    return FAIL.schemeUnsupported
  }
  if (
    typeof proof.contentDigest !== 'string' ||
    typeof proof.signatureInput !== 'string' ||
    typeof proof.signature !== 'string'
  ) {
    return FAIL.proofMalformed
  }

  // A.4 L1068：要求 origin_proof 的方法，meta.target MUST 存在。缺它就没有
  // `@target-uri`，也就没有可重建的签名底——这不是"签名不过"，是请求不成形。
  if (!input.meta.target) return FAIL.proofMalformed

  let parsed: ParsedSignatureInput
  try {
    parsed = parseSignatureInput(proof.signatureInput)
  } catch {
    return FAIL.proofMalformed
  }
  if (parsed.label !== ORIGIN_PROOF_LABEL) return FAIL.proofMalformed
  // A.2 L1018–1022：覆盖组件集合固定。多一个少一个都必须拒——多出来的组件意味着
  // 签名绑定了一些我们并不知道、也就没法审计的东西。
  if (!sameComponents(parsed.components, ORIGIN_PROOF_COMPONENTS)) return FAIL.proofMalformed
  if (typeof parsed.params.keyid !== 'string' || parsed.params.keyid === '') return FAIL.proofMalformed

  const decoded = decodeSignatureValue(proof.signature)
  if (!decoded) return FAIL.proofMalformed
  // RFC 9421 §4.2：两个字段的标签必须一致，否则不同中间件会对"验的是哪个签名"分歧。
  if (decoded.label !== parsed.label) return FAIL.proofMalformed

  const sro = signedRequestObject({ method: input.method, meta: input.meta, body: input.body })

  // A.3：摘要先比。它覆盖 method / meta / body 全部内容，比签名底更早、更廉价地
  // 拦住"meta 被改过"这一类。要在验签**之前**比，理由是签名底里的 content-digest
  // 组件就是它——先拿它比，失败原因才归得到 digest 而不是笼统的 signature。
  if ((await contentDigestOf(sro)) !== proof.contentDigest) return FAIL.digestMismatch

  let key: ResolvedIdentityKey
  try {
    key = await input.resolver.resolve(keyidOwner(parsed.params.keyid), parsed.params.keyid, input.resolverOptions)
  } catch (cause) {
    return { ok: false, reason: 'key_unresolved', cause }
  }

  // 归属校验：签名用的钥属于哪个身份，调用方就必须是那个身份。不做这一步，
  // "签名有效"只证明了"某个钥签的"，而那个钥可能是攻击者自己的。
  if (key.identity !== input.expectedAnchor) return FAIL.anchorMismatch

  const base = await originProofSignatureBase({ sro, signatureParamsValue: parsed.signatureParamsValue })
  const valid = await verifySignatureWithKey({
    signature: decoded.bytes,
    message: signatureBaseBytes(base),
    key,
  })
  if (!valid) return FAIL.signatureInvalid

  return {
    ok: true,
    key,
    keyid: parsed.params.keyid,
    ...(typeof parsed.params.created === 'number' ? { created: parsed.params.created } : {}),
    ...(typeof parsed.params.expires === 'number' ? { expires: parsed.params.expires } : {}),
    ...(typeof parsed.params.nonce === 'string' ? { nonce: parsed.params.nonce } : {}),
  }
}

/**
 * 时间窗校验,与 {@link verifyOriginProof} **分开**。
 *
 * P1 附录 A 只规定摘要与签名怎么算，没规定 `created` / `expires` 必须存在、更没规定
 * 窗口多长——那是各业务 Profile 的事（ANP-02 就有自己的一套上限，见
 * `crypto/verify.ts` 的 `freshnessOk`）。把它并进验签，等于让附录 A 悄悄带上一份
 * 别处借来的策略。
 *
 * 分离的代价是它可能**不被调用**。所以：要求重放防护的调用方别忘调它。签名本身
 * 不提供一次性保证——同一个证明在窗口内可以重放，除非服务端消费 `nonce`。
 */
export function originProofFreshness(input: {
  created?: number
  expires?: number
  /** 允许的最大年龄（秒）。`created` 缺失时不生效。 */
  maxAgeSeconds?: number
  /** 允许的时钟偏斜（秒），用于容忍对端时钟走快。默认 60。 */
  skewSeconds?: number
  now?: number
}): { ok: true } | { ok: false; reason: 'stale' | 'expired' | 'ttl_exceeded' } {
  const now = input.now ?? Math.floor(Date.now() / 1000)
  const skew = input.skewSeconds ?? 60
  const { created, expires } = input

  if (created !== undefined) {
    if (created > now + skew) return { ok: false, reason: 'stale' }
    const maxAge = input.maxAgeSeconds
    if (maxAge !== undefined && now - created > maxAge) return { ok: false, reason: 'stale' }
  }
  if (expires !== undefined) {
    if (created !== undefined && expires <= created) return { ok: false, reason: 'ttl_exceeded' }
    if (now >= expires) return { ok: false, reason: 'expired' }
  }
  return { ok: true }
}

function sameComponents(actual: string[], expected: readonly string[]): boolean {
  return actual.length === expected.length && actual.every((c, i) => c === expected[i])
}

/**
 * keyid 应当属于谁。
 *
 * 一个 keyid 是 `{did}#{fragment}`，DID 部分本可以直接切出来——但那样就等于**相信
 * 请求里那半段**。改用调用方已经算好的锚点，让 resolver 去这个身份下找这把钥：
 * 攻击者拿自己 DID 下的钥签一条声称 `sender_did` 是受害者的请求，钥在受害者身份下
 * 根本不存在，解析阶段就断了。
 *
 * keyid 是裸 DID（无 fragment）时，它自己就是那个身份——CAIP-10 提案 §12 的形态
 * 就是这样，别当 bug 修。
 */
/**
 * keyid 里那个 DID——`{did}#{fragment}` 的前半段；没有 `#` 时它自己就是身份。
 *
 * 裸 DID 形态就是 CAIP-10 提案 §12 的样子（`keyid` 不是 DID URL），**别当 bug 修**。
 *
 * 注意这里取的是**请求里写的**那半段，不是 `expectedAnchor`。两者必须分开，才有下面
 * 那个 `anchor_mismatch`：先按请求说的身份去解析，再要求它跟调用方算出来的锚点相等。
 * 若直接拿 `expectedAnchor` 去解析，就绕过了"keyid 声称的归属"这一步——而它正是
 * P1 与 P8 §6 要求校验的东西。代价是解析的目标由请求方影响，所以 SSRF 的边界仍然
 * 靠 resolver 的 host 允许清单（`ResolveDidOptions.allowedHosts`），不是靠这里。
 */
function keyidOwner(keyid: string): string {
  const hash = keyid.indexOf('#')
  return hash === -1 ? keyid : keyid.slice(0, hash)
}
