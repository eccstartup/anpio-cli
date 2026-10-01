// ANP-09 P1 附录 A —— **Signed Request Object**、`contentDigest`、`@target-uri`
// 与 signature base 的**共用**一半。
//
// 这个文件存在的唯一理由：`sign.ts` 与 `verify.ts` 是同一套规范化的两个方向。
// 各写一份 JCS / 各拼一次 `anp://` 前缀，是这类实现最经典的 bug 来源——两边都能
// 自洽通过自己的测试，直到真的对上一次。**两边都只许从这里取**。
//
// 逐条出处：`chinese/message/01-核心绑定.md` 附录 A（L957 起）。

import { bytesToBase64, sha256, utf8 } from '../crypto/encoding'
import { jcsCanonicalize } from '../crypto/fingerprint'
import { ConnectxError } from '../errors'
import type { AnpMeta, AnpTarget } from './envelope'

/**
 * A.2 L1018–1022：覆盖组件集合 **MUST** 固定为这三个。
 *
 * 注意它**没有** `@authority`——那是 ANP-02 登录签名用的四组件集合
 * （`crypto/signatureBase.ts` 的 `ANP_COMPONENTS`）。两个 Profile 两套集合，
 * 别把其中一套搬去另一套。
 */
export const ORIGIN_PROOF_COMPONENTS = ['@method', '@target-uri', 'content-digest'] as const

/**
 * A.2 L1016–1017：`signatureInput` 与 `signature` **MUST** 都用这个标签。
 *
 * 放在共用模块里，是因为验签时要拿它去比对 `signature` 的标签与 `signatureInput`
 * 的标签是否一致（RFC 9421 §4.2）。签发端与验证端各写一个字面量，就是给未来留了
 * 一个只改一处的机会。
 */
export const ORIGIN_PROOF_LABEL = 'sig1'

/**
 * A.3 L1032–1042：不包含 `auth` 的标准业务对象。
 *
 * `meta` / `body` 直接用调用方传进来的那两个对象（而不是复制一份）——校验过的是
 * 同一个值，签名绑定的也必须是同一个值。
 */
export interface SignedRequestObject {
  method: string
  meta: AnpMeta
  body: Record<string, unknown>
}

/** RFC 3986 §2.3 的 unreserved 集合。`encodeURIComponent` 会漏掉 `!*'()`，不够严。 */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/

/**
 * A.4 L1067：基于 UTF-8 字节，按 RFC 3986 百分号编码。
 *
 * 不用 `encodeURIComponent`：它对 `!` `*` `'` `(` `)` 不转义，而 RFC 3986 的
 * unreserved 只有 `A-Za-z0-9-._~`。DID 里这些字符目前不出现，但"目前不出现"不是
 * 互操作依据——签名底是要跟别的实现逐字节比的。
 */
export function pctEncode(input: string): string {
  let out = ''
  for (const byte of utf8(input)) {
    const ch = String.fromCharCode(byte)
    out += byte < 0x80 && UNRESERVED.test(ch) ? ch : '%' + byte.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

/**
 * A.4 L1062：`@target-uri` 映射为 `anp://{kind}/{pct-encoded did}`。
 *
 * `kind` 不编码（它是 `agent` / `group` / `service` 三个固定词之一）。
 */
export function originProofTargetUri(target: AnpTarget): string {
  return `anp://${target.kind}/${pctEncode(target.did)}`
}

/**
 * A.3 L1044–1050：**只**含 `method` / `meta` / `body`；MUST NOT 含
 * `jsonrpc` / `id` / `auth`；缺省的可选字段 MUST 直接省略（不是填 `null`）。
 *
 * 省略这一步是有后果的：JCS 对 `undefined` 抛错，而一个被填成 `null` 的可选字段
 * 会改变摘要——验签方重建同样的对象时若没有那个 `null`，两边就对不上。
 */
export function signedRequestObject(input: {
  method: string
  meta: AnpMeta
  body: Record<string, unknown>
}): SignedRequestObject {
  return { method: input.method, meta: input.meta, body: input.body }
}

/** A.3 L1048：RFC 8785 JCS 规范化序列化。**唯一**一份 JCS 实现在 `crypto/fingerprint.ts`。 */
export function canonicalizeSignedRequestObject(sro: SignedRequestObject): string {
  return jcsCanonicalize(sro)
}

/**
 * A.2 L1015：`contentDigest` MUST 使用 `sha-256`，保存的是 RFC 9530 `Content-Digest`
 * 的**字段值**（不只是摘要本身）。
 *
 * A.3 L1028：它绑定的是 Signed Request Object，不是外层 HTTP 请求体。
 *
 * 是 `async` 只因为 `crypto/encoding.ts` 的 `sha256` 是 `async`（noble 底下是同步的，
 * 那个签名是为了 API 稳定）。别为此在这里另引一个同步实现——那会让"哪份摘要算得更快"
 * 变成"哪份摘要被谁算"的问题。
 */
export async function contentDigestOf(sro: SignedRequestObject): Promise<string> {
  const bytes = utf8(canonicalizeSignedRequestObject(sro))
  return `sha-256=:${bytesToBase64(await sha256(bytes))}:`
}

/**
 * A.4 L1059–1063：三个组件各有明确的**应用层**映射，不是 HTTP 语义。
 *
 * `@method` 映射为 Signed Request Object 的 `method`，也就是 JSON-RPC 方法名
 * （A.3 L1034 写作 `"<jsonrpc method>"`）——**不是** HTTP 动词。所以这里不能复用
 * `crypto/signatureBase.ts` 的 `buildSignatureBase`：它会把 `@method` 大写成
 * `DIRECT.SEND`，那是另一套东西。
 */
export async function originProofSignatureBase(input: {
  sro: SignedRequestObject
  /** 序列化后的 `@signature-params` 值，例如 `("@method" …);created=...;keyid="..."`。 */
  signatureParamsValue: string
}): Promise<string> {
  const { sro } = input
  if (!sro.meta.target) {
    // A.4 L1068：要求 origin_proof 的方法，meta.target MUST 存在。
    throw new ConnectxError('message_invalid', 'meta.target is required to build an origin-proof signature base')
  }
  const lines = [
    `"@method": ${sro.method}`,
    `"@target-uri": ${originProofTargetUri(sro.meta.target)}`,
    `"content-digest": ${await contentDigestOf(sro)}`,
    `"@signature-params": ${input.signatureParamsValue}`,
  ]
  return lines.join('\n')
}
