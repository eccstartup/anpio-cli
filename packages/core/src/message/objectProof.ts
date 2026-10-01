// P1 附录 B —— 共享 Object Proof Profile 的**验证**半边。
//
// 附录 B 是"给一个**任意** JSON 对象盖一个可被第三方验证的章"的公共底座：P5 的
// `prekey_bundle.proof`（§6.2.3 L395、§6.4 L406–410）是它最直接的用例，P2 的
// `deviceManifest` 条目引用、P6 的 KeyPackage 也都落在同一份 Profile 上。
//
// 它与 `crypto/dataIntegrity.ts` 的关系值得说清楚，因为两者读的是**同一个** proof 形状：
//
//   - `dataIntegrity.ts` 验的是 **DID 文档自己的** `proof`（`verifyDidDocumentProof`）。
//     它的公钥从**这份文档**里取，并且当 DID 路径段带指纹时，还要把钥绑回那个指纹——
//     因为一份自签文档本身什么都不证明。
//   - 这里是**别的东西**的 proof（Bundle 没有 `id`，也没有指纹可绑）。它的公钥只能从
//     **issuer 的 DID 文档**里取，而 issuer 是谁由 Profile 说了算（P5 §6.2.3 L395 说
//     就是 `prekey_bundle.owner_did`）。
//
// 所以两者共用同一套规范化（`didDocumentProofPayload`：剥顶层 `proof` → JCS →
// `sha256(jcs(options)) || sha256(jcs(doc))`）与同一个钥查找（`documentProofKey`），
// 但**不共用入口**——把两份文档、两种信任根塞进一个函数会让"这份 proof 该由谁签"
// 变成一个只有调用方能回答的问题，而那个问题正是本模块存在的理由。
//
// 九步与 P1 附录 B.7 逐条对应，严格程度对齐官方 Rust 参考实现
// （`rust/src/proof/object_proof.rs` 的 `verify_object_proof_detailed`），包括它比字面
// 更严的两处：`verificationMethod` 必须是**完整** DID URL（相对形式 `#key-1` 被拒），
// 且六个必填字段每个都要是**非空字符串**（`null` / 空串都算缺）。

import { ed25519 } from '@noble/curves/ed25519.js'
import { didDocumentProofPayload, documentProofKey, decodeProofValue, canonicalDidUrl } from '../crypto/dataIntegrity'
import { isMethodAuthorized } from '../crypto/resolveDid'

/** B.2 L1196–1210：这个 Profile 固定的三个值。 */
const PROOF_TYPE = 'DataIntegrityProof'
const CRYPTOSUITE = 'eddsa-jcs-2022'
const PROOF_PURPOSE = 'assertionMethod'

/** B.2：`proof` **MUST** 至少含这六个字段。 */
const REQUIRED_FIELDS = ['type', 'cryptosuite', 'verificationMethod', 'proofPurpose', 'created', 'proofValue'] as const

/**
 * RFC 3339 的 `date-time`。B.2 L1206 要求 `created` 是这个格式，而 `Date.parse` 太宽容
 * ——它收 `2026-10-01` 这样的日期（没有时刻），也收 `October 1, 2026`。用它当校验等于把
 * 这条 SHOULD 变成"能被 V8 读懂就行"。
 */
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/

export interface VerifyObjectProofInput {
  /** 被证明的那个对象（它自己的顶层 `proof` 就是待验的证明）。 */
  document: Record<string, unknown>
  /**
   * Profile 规定的 issuer DID——P5 §6.2.3 L395 里是 `prekey_bundle.owner_did`。
   *
   * 它**必须**由调用方给出，不从 `document` 里读：一个让被证明对象自己声明"我是谁签的"
   * 的验证器，验的是自洽性，不是归属。
   */
  issuerDid: string
  /** issuer 的 DID 文档——公钥与 `assertionMethod` 授权都从这里读。 */
  issuerDocument: Record<string, unknown>
  /**
   * 期望的 `verificationMethod`，可选。
   *
   * 有些 Profile 除了"证明是有效的"之外还要它**就是某一颗钥**：P5 §6.5 L415 第 2 项要求
   * Bundle 的证明必须由设备清单里那条 `signing_key_id` 签出。这个判断要读 Manifest，
   * 而 Manifest 不是本模块的事——所以期望值由调用方传进来，本模块只负责拿**解析后的
   * DID URL** 比一次（`#key-1` 与 `did:…#key-1` 是同一个标识符）。
   *
   * 不传就只验证明本身。与 `verifyDidDocumentProof(doc, { did })` 里那个可选的 `did`
   * 同形：模块不替任何 Profile 决定政策。
   */
  expectedVerificationMethod?: string
}

/** 失败原因**只给本服务的运维看**：逐条答出去等于给对端一个"哪一步没过"的探针。 */
export type ObjectProofFailure =
  /** issuer 文档的 `id` 不是调用方说的那个 issuer（B.5 L1236）。 */
  | 'issuer_document_mismatch'
  /** `document.proof` 缺席或不是一个对象（B.2 L1194）。 */
  | 'missing_proof'
  /** 六个必填字段里有一个缺了、不是字符串、或是空串。 */
  | 'missing_proof_field'
  /** `type` / `cryptosuite` / `proofPurpose` 不是本 Profile 固定的值。 */
  | 'unsupported_proof_type'
  /** `verificationMethod` 不是完整 DID URL，或它的 DID 段不是 `issuerDid`。 */
  | 'verification_method_mismatch'
  /** `created` 不是 RFC 3339。 */
  | 'invalid_created'
  /** `verificationMethod` 未被 issuer 文档的 `assertionMethod` 授权（B.5 L1238）。 */
  | 'unauthorized_key'
  /** issuer 文档里取不出那颗公钥（找不到、不是本文档的、不是 Ed25519）。 */
  | 'key_unresolved'
  /** `proofValue` 不是 multibase base58-btc 的 64 字节签名（B.2 L1208）。 */
  | 'invalid_proof_value'
  /** 签名验不过。 */
  | 'signature_invalid'
  /** 调用方给了 `expectedVerificationMethod`，而证明用的不是它。 */
  | 'unexpected_verification_method'

export type ObjectProofOutcome =
  | { ok: true; verificationMethod: string }
  | { ok: false; reason: ObjectProofFailure }

const FAIL = {
  issuerDocumentMismatch: { ok: false, reason: 'issuer_document_mismatch' },
  missingProof: { ok: false, reason: 'missing_proof' },
  missingProofField: { ok: false, reason: 'missing_proof_field' },
  unsupportedProofType: { ok: false, reason: 'unsupported_proof_type' },
  verificationMethodMismatch: { ok: false, reason: 'verification_method_mismatch' },
  invalidCreated: { ok: false, reason: 'invalid_created' },
  unauthorizedKey: { ok: false, reason: 'unauthorized_key' },
  keyUnresolved: { ok: false, reason: 'key_unresolved' },
  invalidProofValue: { ok: false, reason: 'invalid_proof_value' },
  signatureInvalid: { ok: false, reason: 'signature_invalid' },
  unexpectedVerificationMethod: { ok: false, reason: 'unexpected_verification_method' },
} as const satisfies Record<string, ObjectProofOutcome>

/**
 * B.7 L1252 的九步最小验证。任一步失败即拒。
 *
 * 返回结构而不是布尔：调用方（Key Service）要按失败**归类**选错误码（§6.2.3 L398 把所有
 * "不合附录 B"收成 4001），而且要把原因写进日志。
 */
export function verifyObjectProofDetailed(input: VerifyObjectProofInput): ObjectProofOutcome {
  const { document, issuerDid, issuerDocument } = input

  // 第 1 步：issuer 文档得**是**那个 issuer 的。缺了它，后面查出来的公钥属于谁就没有答案，
  // 而"keyid 属于 owner_did"是 §6.2.3 L396 的 MUST。
  if (issuerDocument.id !== issuerDid) return FAIL.issuerDocumentMismatch

  const proof = document.proof
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) return FAIL.missingProof
  const proofRecord = proof as Record<string, unknown>

  // 第 2 步：六个字段每个都要是非空字符串。`proofValue` 也在这里判"在不在、是不是串"，
  // 它的编码在第 8 步。
  for (const field of REQUIRED_FIELDS) {
    const value = proofRecord[field]
    if (typeof value !== 'string' || value === '') return FAIL.missingProofField
  }

  // 第 3、4、5 步：三个固定值。
  if (proofRecord.type !== PROOF_TYPE) return FAIL.unsupportedProofType
  if (proofRecord.cryptosuite !== CRYPTOSUITE) return FAIL.unsupportedProofType
  if (proofRecord.proofPurpose !== PROOF_PURPOSE) return FAIL.unsupportedProofType

  // 第 6 步：`verificationMethod` 是一个**完整**的 DID URL，且它的 DID 段就是 issuer。
  // 相对形式 `#key-1` 在这里被拒——B.2 L1204 写的是 "complete DID URL"，它必须自带
  // 授权它的那个 DID，否则"这颗钥属于谁"要靠读取方的上下文补，而 proof 是要离开发出
  // 环境去别处被验的。
  const verificationMethod = proofRecord.verificationMethod as string
  const hash = verificationMethod.indexOf('#')
  if (hash === -1) return FAIL.verificationMethodMismatch
  const did = verificationMethod.slice(0, hash)
  const fragment = verificationMethod.slice(hash + 1)
  if (!did.startsWith('did:') || fragment === '') return FAIL.verificationMethodMismatch
  if (did !== issuerDid) return FAIL.verificationMethodMismatch

  // 第 7 步：`created` 是 RFC 3339。
  const created = proofRecord.created as string
  if (!RFC3339.test(created) || Number.isNaN(Date.parse(created))) return FAIL.invalidCreated

  // 第 8 步：那颗钥要在 issuer 文档里、被 `assertionMethod` 授权、且是 Ed25519。
  // 两件分开判：没被授权与取不出钥是两种不同的文档问题，日志里要能分开。
  const wanted = canonicalDidUrl(issuerDocument.id, verificationMethod)
  if (wanted === undefined) return FAIL.verificationMethodMismatch
  if (!isMethodAuthorized(issuerDocument, 'assertionMethod', verificationMethod)) return FAIL.unauthorizedKey
  const publicKey = documentProofKey(issuerDocument, verificationMethod)
  if (publicKey === null) return FAIL.keyUnresolved

  // 调用方点名了"必须是谁"时在这里比。用解析后的 DID URL 比，所以清单写 `#key-1` 而
  // proof 写完整形式时不会误判（P5 §6.5 L415 第 2 项要的是"同一颗钥"，不是"同一串字符"）。
  if (input.expectedVerificationMethod !== undefined) {
    const expected = canonicalDidUrl(issuerDocument.id, input.expectedVerificationMethod)
    if (expected === undefined || expected !== wanted) return FAIL.unexpectedVerificationMethod
  }

  const signature = decodeProofValue(proofRecord.proofValue)
  // `decodeProofValue` 只保证"是 multibase base58-btc"，Ed25519 的签名长度还得自己判——
  // 一个 32 字节的串也能解出来，但它不可能是签名。
  if (signature === null || signature.length !== 64) return FAIL.invalidProofValue

  // 第 9 步：验签。签名底与 `dataIntegrity.ts` 是**同一个**函数：剥掉顶层 `proof` 后的
  // 整个对象（B.3 L1214——不得缩小也不得扩大范围），options 是 proof 去掉 `proofValue`。
  const proofOptions: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(proofRecord)) if (key !== 'proofValue') proofOptions[key] = value
  if (!ed25519.verify(signature, didDocumentProofPayload(proofOptions, document), publicKey)) {
    return FAIL.signatureInvalid
  }

  return { ok: true, verificationMethod }
}

/** 布尔形式。调用方只有"要不要收"这一件事要判时用它。 */
export function verifyObjectProof(input: VerifyObjectProofInput): boolean {
  return verifyObjectProofDetailed(input).ok
}
