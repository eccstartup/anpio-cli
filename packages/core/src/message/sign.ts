// ANP-09 P1 附录 A —— 签发 `auth.origin_proof`。
//
// 只负责**装配**：摘要、签名底、标签、base64。它不知道钥在哪儿、是哪条曲线，
// 因为那三件事在 CLI（本地身份 / 钱包）、在服务端（跨域服务的 `serviceDid` 钥）
// 各不相同，而签名底必须完全一致。所以调用方交进来的是一个 `sign` 回调。

import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64 } from '../crypto/encoding'
import { serializeSignatureParams, signatureBaseBytes } from '../crypto/signatureBase'
import { ConnectxError } from '../errors'
import type { AnpAuth, AnpMeta, AnpOriginProof } from './envelope'
import { ORIGIN_PROOF_SCHEME } from './envelope'
import type { IWallet } from '../wallet/wallet'
import {
  ORIGIN_PROOF_COMPONENTS,
  ORIGIN_PROOF_LABEL,
  contentDigestOf,
  originProofSignatureBase,
  signedRequestObject,
} from './sro'

/**
 * 一次签名所需的**全部**外部知识。
 *
 * `sign` 收签名底的 UTF-8 字节，回原始签名字节。ed25519 直接签；钱包要走 EIP-191
 * `personal_sign`（对同样的字节求个人消息哈希再签），验签侧的 65 字节分支正是为此
 * 存在的——两侧的约定在 `crypto/verify.ts` 的 `verifySignatureWithKey` 里，别各自发明。
 */
export interface OriginProofSigner {
  /** `signatureInput` 的 `keyid` 参数值。 */
  keyid: string
  sign: (message: Uint8Array) => Uint8Array | Promise<Uint8Array>
}

export interface SignOriginProofInput {
  method: string
  meta: AnpMeta
  body: Record<string, unknown>
  signer: OriginProofSigner
  /** Unix 秒。缺省取当前时间——不省略，否则就没有任何时效上限可言。 */
  created?: number
  /** Unix 秒。RFC 9421 里可选；给了就能把重放窗口收窄到明确区间。 */
  expires?: number
  /** RFC 9421 `nonce`。服务端拿它做一次性消费时才需要。 */
  nonce?: string
}

/**
 * 签发一个 `origin_proof`。
 *
 * 顺序即规范顺序（A.2 / A.3 / A.4）：先定 Signed Request Object，再 JCS + sha-256
 * 得 `contentDigest`，最后把 `contentDigest` 当作 `content-digest` 组件参与签名底。
 * 摘要**不**是外层 HTTP 体的摘要，别换成 `buildContentDigestValue(utfb(body))`。
 */
export async function signOriginProof(input: SignOriginProofInput): Promise<AnpOriginProof> {
  const sro = signedRequestObject({ method: input.method, meta: input.meta, body: input.body })

  if (!sro.meta.target) {
    // A.4 L1068：要求 origin_proof 的方法，meta.target MUST 存在。
    // 在这里先抛，是为了让调用方看到"缺的是 target"，而不是一个签名底拼错的消息。
    throw new ConnectxError(
      'message_invalid',
      `Method "${input.method}" requires auth.origin_proof, so meta.target MUST be set`,
    )
  }

  const params: { created?: number; expires?: number; nonce?: string; keyid: string } = {
    created: input.created ?? Math.floor(Date.now() / 1000),
    keyid: input.signer.keyid,
  }
  if (input.expires !== undefined) params.expires = input.expires
  if (input.nonce !== undefined) params.nonce = input.nonce

  const signatureParamsValue = serializeSignatureParams([...ORIGIN_PROOF_COMPONENTS], params)
  const base = await originProofSignatureBase({ sro, signatureParamsValue })
  const raw = await input.signer.sign(signatureBaseBytes(base))

  return {
    contentDigest: await contentDigestOf(sro),
    signatureInput: `${ORIGIN_PROOF_LABEL}=${signatureParamsValue}`,
    signature: `${ORIGIN_PROOF_LABEL}=:${bytesToBase64(raw)}:`,
  }
}

/** 连同 `scheme` 一起装配 `params.auth`（A.1 L980–981）。 */
export async function buildOriginProofAuth(input: SignOriginProofInput): Promise<AnpAuth> {
  return { scheme: ORIGIN_PROOF_SCHEME, origin_proof: await signOriginProof(input) }
}

/** 本地 Ed25519 身份（`createAnpIdentity` 的 `priv` + `keyid`）的签发器。 */
export function ed25519OriginProofSigner(priv: Uint8Array, keyid: string): OriginProofSigner {
  return {
    keyid,
    sign: (message) => ed25519.sign(message, priv),
  }
}

/**
 * 任意 `IWallet` 的签发器——本地密钥、EIP-1193 钱包、别的链，都走这一条。
 *
 * 密钥在哪儿、是哪条曲线，是 `IWallet` 自己的事（`keypairWallet` 直接签、
 * `chainWallet` 走 `personal_sign`），这里只把它的 `signMessage` 接到签名底上。
 * 两条路产出的**字节形态不同而验签侧都认**：`crypto/verify.ts` 的
 * `verifySignatureWithKey` 按签名长度分流（65 字节 = EIP-191 个人消息签名，
 * 64 字节 = 原始 r||s），所以这里不需要、也不该按曲线分支。
 */
export function walletOriginProofSigner(wallet: IWallet, keyid: string): OriginProofSigner {
  return {
    keyid,
    sign: (message) => wallet.signMessage(message),
  }
}
