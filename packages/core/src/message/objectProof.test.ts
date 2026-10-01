// P1 附录 B 的共享 Object Proof Profile。用真钥、真签名跑：这一层要判的是"这颗章算不算数"，
// 而"章怎么盖"是 `crypto/dataIntegrity.ts` 的事——两个文件共用同一份 JCS 与同一个钥查找，
// 所以签名侧直接用那个模块的签名器，验签侧走本模块的入口。
//
// 每个用例都盯 `reason` 而不只是"拒了"：P5 §6.2.3 L398 把所有"不合附录 B"收成同一个 4001，
// 于是**原因只进日志**，而日志要能分清"文档坏了"与"有人改了字"。

import { describe, expect, it } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { signDidDocumentProofSync } from '../crypto/dataIntegrity'
import { encodeMultibaseEd25519 } from '../crypto/multicodec'
import { verifyObjectProof, verifyObjectProofDetailed } from './objectProof'

const ISSUER = 'did:web:example.com:alice'
const KEYID = `${ISSUER}#dev-sign`
const OTHER_KEYID = `${ISSUER}#stale`
const CREATED = '2026-10-01T00:00:00Z'

/** issuer 的 DID 文档 + 一把真钥。`assertionMethod` 只授权 `dev-sign`——P2 §10.2.1 L630
 *  说 Bundle 的证明场合要落在 `assertionMethod`，而 `#stale` 是文档里存在但没被授权的那个。 */
function issuer() {
  const priv = ed25519.utils.randomSecretKey()
  const pub = ed25519.getPublicKey(priv)
  const document = {
    id: ISSUER,
    verificationMethod: [
      { id: KEYID, type: 'Multikey', controller: ISSUER, publicKeyMultibase: encodeMultibaseEd25519(pub) },
      { id: OTHER_KEYID, type: 'Multikey', controller: ISSUER, publicKeyMultibase: encodeMultibaseEd25519(pub) },
    ],
    assertionMethod: [KEYID],
  }
  return { priv, document }
}

/** 被证明的对象。形状取 P5 §6.1 的一小半就行——本模块不认识 Bundle，只认识"一个对象"。 */
function bundle(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    owner_did: ISSUER,
    owner_device_id: 'dev-a-7N3KQ2',
    suite: 'X25519+XEd25519+AES-256-GCM',
    static_key_agreement_id: `${ISSUER}#dev-a-e2ee`,
    ...overrides,
  }
}

function signed(document: Record<string, unknown>, priv: Uint8Array, keyid = KEYID, created = CREATED) {
  return { ...document, proof: signDidDocumentProofSync(document, keyid, priv, { created }) }
}

function verify(document: Record<string, unknown>, document_?: Record<string, unknown>, expected?: string) {
  return verifyObjectProofDetailed({
    document,
    issuerDid: ISSUER,
    issuerDocument: document_ ?? issuer().document,
    ...(expected !== undefined ? { expectedVerificationMethod: expected } : {}),
  })
}

describe('verifyObjectProof', () => {
  it('accepts a proof made by a key the issuer document authorizes', () => {
    const { priv, document } = issuer()
    const outcome = verify(signed(bundle(), priv), document)
    expect(outcome).toEqual({ ok: true, verificationMethod: KEYID })
    expect(verifyObjectProof({ document: signed(bundle(), priv), issuerDid: ISSUER, issuerDocument: document })).toBe(true)
  })

  it('refuses when the issuer document is not the issuer it was asked about', () => {
    // B.5 L1236：`verificationMethod` 所属的 DID 必须**是** Profile 规定的 issuer。文档
    // 对不上时，后面查出来的公钥属于谁就没有答案——"这颗钥在这份文档里被授权了"与
    // "这颗钥是 owner_did 的"是两件事。
    const { priv, document } = issuer()
    const outcome = verifyObjectProofDetailed({
      document: signed(bundle(), priv),
      issuerDid: `${ISSUER}x`,
      issuerDocument: document,
    })
    expect(outcome).toEqual({ ok: false, reason: 'issuer_document_mismatch' })
  })

  it('refuses an object with no proof at all', () => {
    expect(verify(bundle())).toEqual({ ok: false, reason: 'missing_proof' })
    expect(verify(bundle({ proof: 'signed, trust me' }))).toEqual({ ok: false, reason: 'missing_proof' })
    expect(verify(bundle({ proof: [{}] }))).toEqual({ ok: false, reason: 'missing_proof' })
  })

  it('requires all six fields to be non-empty strings', () => {
    // 比字面更严的一处：`created: ''` 是"这个字段在场"，但一个空的时间戳说明不了任何事。
    const { priv } = issuer()
    const good = signed(bundle(), priv)
    for (const field of ['type', 'cryptosuite', 'verificationMethod', 'proofPurpose', 'created', 'proofValue']) {
      const proof = { ...(good.proof as Record<string, unknown>) }
      delete proof[field]
      expect(verify({ ...bundle(), proof })).toEqual({ ok: false, reason: 'missing_proof_field' })
      expect(verify({ ...bundle(), proof: { ...proof, [field]: '' } })).toEqual({
        ok: false,
        reason: 'missing_proof_field',
      })
      expect(verify({ ...bundle(), proof: { ...proof, [field]: null } })).toEqual({
        ok: false,
        reason: 'missing_proof_field',
      })
    }
  })

  it('pins the three values the profile fixes', () => {
    const { priv } = issuer()
    const good = signed(bundle(), priv).proof as Record<string, unknown>
    expect(verify({ ...bundle(), proof: { ...good, type: 'Ed25519Signature2020' } })).toEqual({
      ok: false,
      reason: 'unsupported_proof_type',
    })
    expect(verify({ ...bundle(), proof: { ...good, cryptosuite: 'eddsa-rdfc-2022' } })).toEqual({
      ok: false,
      reason: 'unsupported_proof_type',
    })
    expect(verify({ ...bundle(), proof: { ...good, proofPurpose: 'authentication' } })).toEqual({
      ok: false,
      reason: 'unsupported_proof_type',
    })
  })

  it('refuses a verificationMethod written as a relative DID URL', () => {
    // B.2 L1204 要的是 **complete** DID URL。相对形式要被签的那份上下文补全，而 proof 是要
    // 离开发出环境去别处被验的——官方 Rust 实现（`did_from_verification_method`）同样拒它。
    const { priv } = issuer()
    const document = bundle()
    const proof = signDidDocumentProofSync(document, '#dev-sign', priv, { created: CREATED })
    expect(verify({ ...document, proof })).toEqual({ ok: false, reason: 'verification_method_mismatch' })
  })

  it('refuses a verificationMethod whose DID is not the issuer', () => {
    const { priv } = issuer()
    const document = bundle()
    const proof = signDidDocumentProofSync(document, 'did:web:evil.example:mallory#key-1', priv, { created: CREATED })
    expect(verify({ ...document, proof })).toEqual({ ok: false, reason: 'verification_method_mismatch' })
  })

  it('refuses a method the issuer document does not authorize for assertionMethod', () => {
    const { priv, document } = issuer()
    // `#stale` 在 `verificationMethod` 里、也解得出同一条公钥，但没被 `assertionMethod`
    // 授权——B.5 L1238。列在文档里不等于被授权（P2 §10.2.1 要的正是关系）。
    expect(verify(signed(bundle(), priv, OTHER_KEYID), document)).toEqual({ ok: false, reason: 'unauthorized_key' })
  })

  it('refuses a key the issuer document cannot produce', () => {
    const { priv } = issuer()
    const foreign = { id: ISSUER, verificationMethod: [], assertionMethod: [`${ISSUER}#dev-sign`] }
    expect(verify(signed(bundle(), priv), foreign)).toEqual({ ok: false, reason: 'key_unresolved' })
  })

  it('refuses a created that is not RFC 3339', () => {
    // `Date.parse` 会收下这三种，所以只判它等于没判。
    const { priv, document } = issuer()
    for (const created of ['2026-10-01', 'October 1, 2026', '2026-10-01T00:00:00']) {
      expect(verify(signed(bundle(), priv, KEYID, created), document)).toEqual({ ok: false, reason: 'invalid_created' })
    }
  })

  it('accepts the offsets RFC 3339 allows, not just Z', () => {
    const { priv, document } = issuer()
    expect(verify(signed(bundle(), priv, KEYID, '2026-10-01T08:00:00+08:00'), document).ok).toBe(true)
  })

  it('refuses a proofValue that is not a multibase base58-btc signature', () => {
    const { priv } = issuer()
    const good = signed(bundle(), priv).proof as Record<string, unknown>
    // 没有 `z` 标记。
    expect(verify({ ...bundle(), proof: { ...good, proofValue: 'g1pf7bhsMXu' } })).toEqual({
      ok: false,
      reason: 'invalid_proof_value',
    })
    // 是 base58btc，但只有 32 字节——Ed25519 的签名是 64 字节。
    expect(verify({ ...bundle(), proof: { ...good, proofValue: 'z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7' } })).toEqual(
      { ok: false, reason: 'invalid_proof_value' },
    )
  })

  it('refuses a signature made over a different object', () => {
    const { priv, document } = issuer()
    const proof = signed(bundle(), priv).proof
    // B.3 L1214：签名覆盖的是**移除顶层 `proof` 后的整个对象**——不多也不少。改任何一个
    // 字段都要失效，这是整份 Profile 唯一的力量来源。
    expect(verify({ ...bundle({ owner_device_id: 'dev-b-OTHER' }), proof }, document)).toEqual({
      ok: false,
      reason: 'signature_invalid',
    })
    // …多一个字段同样要失效：把范围缩小到"只签某几个字段"就等于允许在别处动手脚。
    expect(verify({ ...bundle({ extra: 1 }), proof }, document)).toEqual({ ok: false, reason: 'signature_invalid' })
  })

  it('refuses a signature made by a key other than the one it names', () => {
    const { document } = issuer()
    const mallory = ed25519.utils.randomSecretKey()
    // 名字写的是 `#dev-sign`，签的是另一把钥。
    expect(verify(signed(bundle(), mallory), document)).toEqual({ ok: false, reason: 'signature_invalid' })
  })
})

describe('verifyObjectProof with an expected verification method', () => {
  it('accepts the same key written in either form', () => {
    // P5 §6.5 L415 第 2 项要的是"证明用的**就是**清单里那条 `signing_key_id`"，不是
    // "两串字符相同"——清单写相对形式、proof 写完整形式时它们仍是同一颗钥。
    const { priv, document } = issuer()
    expect(verify(signed(bundle(), priv), document, '#dev-sign')).toEqual({ ok: true, verificationMethod: KEYID })
    expect(verify(signed(bundle(), priv), document, KEYID).ok).toBe(true)
  })

  it('refuses a proof made by a key other than the expected one', () => {
    // 一颗**被授权**、签名也**有效**的钥，仍然可能不是这次操作该用的那一颗（旧钥、另一台
    // 设备的钥）。这条是本模块不替 Profile 决定的那个政策口子。
    const { priv, document } = issuer()
    const other = { ...document, assertionMethod: [KEYID, OTHER_KEYID] }
    const signed2 = signed(bundle(), priv, OTHER_KEYID)
    expect(verify(signed2, other).ok).toBe(true)
    expect(verify(signed2, other, KEYID)).toEqual({ ok: false, reason: 'unexpected_verification_method' })
  })
})
