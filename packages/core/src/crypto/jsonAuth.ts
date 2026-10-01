import { ed25519 } from '@noble/curves/ed25519.js'
import {
  ANP_COMPONENTS,
  buildContentDigestValue,
  buildSignatureBase,
  serializeSignatureParams,
  signatureBaseBytes,
} from './signatureBase'
import { jcsCanonicalize } from './fingerprint'
import { bytesToBase64, utf8 } from './encoding'
import { ConnectxError } from '../errors'
import type { AnpSigningIdentity } from '../types'

// ANP-02 §4「JSON 认证信息承载」——把 §3 的认证字段搬进一个 JSON 元数据对象，
// 让认证信息随 WebSocket 首包 / 消息总线 envelope / 自定义 RPC 包装层一起走。
//
// §4 开篇那句划定了这一节的边界：「本节仅定义将第 3 节中的认证信息以 JSON 元数据
// 方式承载的方法，**不重新定义新的待签名字段集合**」。所以这里没有第二套 covered
// component、没有第二套参数：`@method` / `@target-uri` / `@authority` /
// `content-digest` 与 §3 逐字相同，签名基字符串也照 RFC 9421 原样构造。
//
// 唯一的实质差别是 `contentDigest` 绑定的对象：§3 绑整个 HTTP 消息体，§4 绑
// **`payload` 那一段**（§4.1.1「在 JSON 承载模式下，`contentDigest` 绑定的是 payload
// 部分，而不是包含 `auth` 在内的整个封装对象。`auth` 是外层认证元数据，不参与业务
// 载荷摘要」）。于是同一个 `content-digest` 组件在两个 profile 里指的字节不同，而
// 这一点必须两边完全一致——不一致就是这个 profile 唯一的坑。
//
// 因此：**构造在这一支，验证在 `verify.ts` 的同一套检查管线里**，两边共用
// `buildContentDigestValue` 与 JCS 规则，并由往返测试（`jsonAuth.test.ts`）盯住它们
// 对「摘要算哪段字节」的判断一致。

const DEFAULT_TTL_SECONDS = 300

/** `auth` 块的字面形状（§4.1.1 的推荐格式）。字段名是 camelCase，**不是** HTTP
 *  头名——它们承载的是同一个值，但不是同一种传输。 */
export interface JsonAuthFields {
  /** 对应 HTTP 的 `Content-Digest`。**绑定的是 `payload`，不含 `auth` 自身。** */
  contentDigest: string
  /** 对应 HTTP 的 `Signature-Input`。 */
  signatureInput: string
  /** 对应 HTTP 的 `Signature`。 */
  signature: string
}

/** §4.1.1 的推荐封装：认证元数据在 `auth`，业务数据在 `payload`。
 *  `payload` 是 `unknown`，因为它是**调用方的业务数据**，SDK 不规定它的形状。 */
export interface JsonAuthEnvelope {
  auth: JsonAuthFields
  payload: unknown
}

export interface SignAnpJsonAuthInput {
  /** 签名身份：`AnpIdentity` 加上签名的 `priv` 密钥。 */
  identity: AnpSigningIdentity
  nonce: string
  /** `@method` 组件的值。底层是 HTTP 时含义同 §3；不是 HTTP 时由上层协议定义
   *  目标消息的等价组件（§4.1.2 第 3 条）。 */
  method: string
  /** `@target-uri` 组件的值。同上：底层不是 HTTP 时由上层协议定义等价组件。 */
  targetUri: string
  /** `@authority` 组件的值。**承载协议没有「权威」这个概念时就不要给**——不给则
   *  该组件不进 covered set。给了一个验证方无法独立核对的 `@authority`，等于让
   *  证明里带一个只被假装检查过的字段。 */
  authority?: string
  /** 业务数据本体。摘要对它计算，`auth` 不参与。 */
  payload: unknown
  /** 签名有效期（秒）。默认 300。 */
  ttlSeconds?: number
}

/**
 * 按 §4 构造一次带认证信息的 JSON 请求。
 *
 * 返回的就是要发出去的那个对象：`{ auth: {…}, payload }`。**摘要覆盖的是 `payload`
 * 的规范字节，不是这个封装序列化后的字节**——所以封装用哪种 JSON 序列化发出去都
 * 无所谓（键序、空白都不影响），服务端只要能拿到同一个 `payload` 值就能重算。
 * 反过来说：`payload` 本身一旦被改动（哪怕只改键序之外的任何一处），验证就会失败。
 *
 * `payload` 是 JSON 对象时，序列化规则在本实现里**固定为 RFC 8785 JCS**（§4.1.1
 * 「实现者应在本地固定其序列化规则；推荐使用 RFC8785」）。这是本 SDK 作为「实现者」
 * 选定的规则，验证侧用同一份 `jcsCanonicalize`，所以自洽；但规范只说「推荐」，另一
 * 家实现若固定了别的规则，两边的摘要对不上——这不是这里能靠代码弥合的，它是 §4 留
 * 给实现方的自由度。JCS 对数字的边角（`-0`、`1e21` 之类的指数形式）不完全覆盖，
 * `jcsCanonicalize` 的注释已写明这一限制；SDK 内部收发一致，不受影响。
 */
export async function signAnpJsonAuthRequest(
  input: SignAnpJsonAuthInput,
): Promise<JsonAuthEnvelope> {
  if (!input.method) throw new ConnectxError('invalid_argument', 'JSON auth needs a non-empty @method')
  if (!input.targetUri) throw new ConnectxError('invalid_argument', 'JSON auth needs a non-empty @target-uri')
  if (input.authority != null && !input.authority) {
    throw new ConnectxError('invalid_argument', 'JSON auth: omit @authority instead of passing it empty')
  }
  if (!('payload' in input)) {
    throw new ConnectxError('invalid_argument', 'JSON auth needs a payload — pass null if there is none')
  }

  // §4.1.1: digest the payload, NOT the wrapper. `auth` is outer metadata.
  const contentDigest = await buildContentDigestValue(utf8(jcsCanonicalize(input.payload)))

  // Same covered set as §3, in the same order; `@authority` drops out only when the
  // carrier has no such thing (a message bus has no authority to name).
  const components = ANP_COMPONENTS.filter((c) => c !== '@authority' || input.authority != null)

  const now = Math.floor(Date.now() / 1000)
  const signatureParams = serializeSignatureParams(components, {
    created: now,
    expires: now + (input.ttlSeconds ?? DEFAULT_TTL_SECONDS),
    nonce: input.nonce,
    keyid: input.identity.keyid,
    // No `alg`, same reason as §3: the verifier rebuilds @signature-params from
    // exactly created/expires/nonce/keyid, so an extra param changes the bytes.
  })

  const base = buildSignatureBase({
    method: input.method,
    // `@path` is not in this profile's covered set — §3.1.2's minimum is
    // `@method` + `@target-uri`, and a non-HTTP carrier has no path to name.
    path: '',
    authority: input.authority ?? '',
    targetUri: input.targetUri,
    // The ONLY header-shaped input is the digest: it is what the `content-digest`
    // component resolves to, and it is now the digest of `payload`.
    headers: { 'content-digest': contentDigest },
    components,
    signatureParams,
  })

  const signature = bytesToBase64(ed25519.sign(signatureBaseBytes(base), input.identity.priv))
  return {
    auth: {
      contentDigest,
      signatureInput: `sig1=${signatureParams}`,
      signature: `sig1=:${signature}:`,
    },
    payload: input.payload,
  }
}
