// C11 —— 出站外层签名。P8 §6.2.2 那八步的另一半：我们作为**发送方域服务**，用
// `serviceDid` 的钥签每一个跨域请求（§3.6 L90–98 的外层那一行）。
//
// 与 `outer.ts` 共用同一份 `ANP_COMPONENTS`——core 的常量就是
// `("@method" "@target-uri" "@authority" "content-digest")`，与 §3.1.2 L112 的要求逐项
// 对上——所以两侧不可能签出与验出两种底。
//
// core 的 `signAnpLoginRequest` **不能**直接用：它签的是 ANP-02 的 DID 服务登录载荷
// （`nonce` + `did` [+ `didDocument`]），外壳是那套流程的，不是任意外层请求的
// （federation.md §4）。这里复用的是它下面那几块，以及 `ed25519OriginProofSigner`
// ——它就是对裸字节做 Ed25519 签名，与本文件要的完全一样。

import { readFile } from 'node:fs/promises'
import { ed25519OriginProofSigner, parsePem, parsePrivateKey } from '@agentx/core'
import type { Config } from '../config'
import {
  ANP_COMPONENTS,
  buildContentDigestValue,
  buildSignatureBase,
  bytesToBase64,
  serializeSignatureParams,
  signatureBaseBytes,
  utf8,
} from '@agentx/core/advanced'

/** ANP-02 §3.1.2 的有效期。core 的登录流程用同一个值，没有理由不一样。 */
const DEFAULT_TTL_SECONDS = 300

export interface OutboundRequest {
  /** HTTP 方法。`@method` 覆盖的是它，不是 JSON-RPC 的方法名。 */
  method: string
  /** 绝对目标 URL。它就是 `@target-uri`，query 一并算进去。 */
  url: string
  /** 请求体的**原始文本**：`content-digest` 覆盖的是这些字节，不是重新序列化的结果。 */
  body: string
  /** 一次性 nonce。验签成功**不是**重放防护——对端的 `http_nonces` 才是（§2.2）。 */
  nonce: string
  /** 签名时刻（epoch 秒）。缺省取现在；注入它，`created` 才是字面量。 */
  now?: number
  /** 缺省 `now + 300`。改了它就要保证对端的时间窗也容得下。 */
  expires?: number
}

export interface HttpSigner {
  /** 完整 DID URL（ANP-02 L82），也就是 `Signature-Input` 里的 `keyid`。 */
  readonly keyid: string
  /** 只产签名相关的三个头。`content-type` 之类由出站那一层自己加：那些不进签名底，
   *  在两处各写一遍只会有一处跟着改。 */
  headers(request: OutboundRequest): Promise<Record<string, string>>
}

/** 拿一把已解出来的裸钥造签发器。 */
export function createHttpSigner(
  keyid: string,
  priv: Uint8Array,
  ttlSeconds = DEFAULT_TTL_SECONDS,
): HttpSigner {
  const signer = ed25519OriginProofSigner(priv, keyid)
  return {
    keyid,
    async headers(request) {
      const created = request.now ?? Math.floor(Date.now() / 1000)
      const contentDigest = await buildContentDigestValue(utf8(request.body))
      // 不加 `alg`：对端按 ANP-02 重建 `@signature-params` 时只认
      // created/expires/nonce/keyid，多一个字段换掉的就是签名的底。
      const signatureParams = serializeSignatureParams(ANP_COMPONENTS, {
        created,
        expires: request.expires ?? created + ttlSeconds,
        nonce: request.nonce,
        keyid,
      })
      const url = new URL(request.url)
      const base = buildSignatureBase({
        method: request.method,
        path: url.pathname,
        authority: url.host,
        targetUri: request.url,
        headers: { 'content-digest': contentDigest },
        components: ANP_COMPONENTS,
        signatureParams,
      })
      const signature = bytesToBase64(await signer.sign(signatureBaseBytes(base)))
      return {
        'content-digest': contentDigest,
        'signature-input': `sig1=${signatureParams}`,
        signature: `sig1=:${signature}:`,
      }
    },
  }
}

/**
 * 从配置读出发送侧的签发器。
 *
 * 没有配钥就返回 `undefined`，而不是抛：`keyFile` 缺席是配置层明说的"这份部署不出站"
 * （`config.ts`），把它变成一个启动期异常等于禁止一个合法的部署形态。出站那一层在真的
 * 需要签名时会拿到 `undefined`，那时才该失败——而它失败得清楚。
 */
export async function loadHttpSigner(config: Config): Promise<HttpSigner | undefined> {
  const file = config.keyFile
  const keyid = config.keyId
  if (file === undefined || keyid === undefined) return undefined
  return createHttpSigner(keyid, parseEd25519(await readFile(file, 'utf8')))
}

/** 私钥文件的两种文本形态：hex，或 PEM 里包着的 DER。与 `connectx --key` 认的同两种
 *  （`packages/cli/src/key.ts`），所以同一个钥文件两边都能用。 */
function parseEd25519(raw: string): Uint8Array {
  const text = raw.trim()
  const parsed = text.startsWith('-----BEGIN') ? parsePem(text, 'ed25519') : parsePrivateKey(text, 'ed25519')
  return parsed.privateKey
}
