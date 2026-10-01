import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { createAnpIdentity } from '../crypto/signer'
import type { AnpMeta } from './envelope'
import type { KeyResolver, ResolvedIdentityKey } from './locator'
import { ORIGIN_PROOF_SCHEME } from './envelope'
import { keypairWallet } from '../protocol/adapters/chain'
import type { IWallet } from '../wallet/wallet'
import { ethPersonalSignHash } from '../wallet/eip1193'
import { contentDigestOf, originProofSignatureBase, pctEncode, signedRequestObject } from './sro'
import {
  buildOriginProofAuth,
  ed25519OriginProofSigner,
  signOriginProof,
  walletOriginProofSigner,
} from './sign'
import { originProofFreshness, verifyOriginProof, verifyOriginProofDetailed } from './verify'

const identity = createAnpIdentity('example.com')

/** 一个不起网络的 resolver：身份对得上就交钥，对不上就是解析不出来。 */
function resolverFor(priv: Uint8Array, did: string): KeyResolver {
  return {
    async resolve(resolvedIdentity: string, keyid: string): Promise<ResolvedIdentityKey> {
      if (resolvedIdentity !== did) throw new Error(`unknown identity ${resolvedIdentity}`)
      return {
        curve: 'ed25519',
        bytes: ed25519.getPublicKey(priv),
        identity: resolvedIdentity,
        anchor: { kind: 'fingerprint', thumbprint: 'test' },
        docUrl: keyid,
      }
    },
  }
}

function meta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: identity.did,
    target: { kind: 'agent', did: 'did:wba:peer.example:user:bob:e1_xyz' },
    ...overrides,
  }
}

const BODY = { content_type: 'text/plain', content: 'hello' }

describe('pctEncode', () => {
  it('escapes everything outside the RFC 3986 unreserved set', () => {
    // `encodeURIComponent` would leave `!'()*` alone; RFC 3986 does not.
    expect(pctEncode("a!*'()b")).toBe('a%21%2A%27%28%29b')
    expect(pctEncode('did:wba:example.com:user:alice:e1_abc')).toBe(
      'did%3Awba%3Aexample.com%3Auser%3Aalice%3Ae1_abc',
    )
  })

  it('percent-encodes non-ASCII by UTF-8 byte', () => {
    expect(pctEncode('é')).toBe('%C3%A9')
  })
})

describe('originProofSignatureBase', () => {
  const sro = signedRequestObject({
    method: 'direct.send',
    meta: {
      profile: 'anp.direct.base.v1',
      security_profile: 'transport-protected',
      sender_did: 'did:wba:example.com:user:alice:e1_abc',
      target: { kind: 'agent', did: 'did:wba:peer.example:user:bob:e1_xyz' },
    },
    body: { content_type: 'text/plain', content: 'hello' },
  })

  it('pins the exact bytes of the four base lines', async () => {
    const base = await originProofSignatureBase({
      sro,
      signatureParamsValue: '("@method" "@target-uri" "content-digest");created=1700000000;keyid="k"',
    })
    // The digest is pinned as a literal: it is a function of the JCS serialization
    // (RFC 8785 key ordering, no whitespace), so a refactor that quietly changes
    // either the ordering or the encoding breaks here rather than in the field.
    expect(base).toBe(
      [
        '"@method": direct.send',
        '"@target-uri": anp://agent/did%3Awba%3Apeer.example%3Auser%3Abob%3Ae1_xyz',
        '"content-digest": sha-256=:bEyzL15FDyGAKrA0OI/krYq5A2xxGmgwyfMqbyDNZow=:',
        '"@signature-params": ("@method" "@target-uri" "content-digest");created=1700000000;keyid="k"',
      ].join('\n'),
    )
  })

  it('maps @method to the JSON-RPC method verbatim, NOT uppercased', async () => {
    // This is the exact reason the message layer does not reuse `buildSignatureBase`
    // (crypto/signatureBase.ts): that helper uppercases `@method` for HTTP, which
    // would turn `direct.send` into `DIRECT.SEND` and break interop silently.
    const base = await originProofSignatureBase({ sro, signatureParamsValue: '(x)' })
    expect(base.split('\n')[0]).toBe('"@method": direct.send')
  })

  it('digest equals contentDigestOf so sign and verify cannot disagree', async () => {
    const digest = await contentDigestOf(sro)
    const base = await originProofSignatureBase({ sro, signatureParamsValue: '(x)' })
    expect(base).toContain(`"content-digest": ${digest}`)
  })
})

describe('signOriginProof / verifyOriginProof', () => {
  it('round-trips a proof the verifier accepts', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
      nonce: 'n-1',
    })

    expect(auth.scheme).toBe(ORIGIN_PROOF_SCHEME)
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome.ok).toBe(true)
    if (outcome.ok) expect(outcome.nonce).toBe('n-1')
  })

  it('rejects a proof whose meta was changed after signing', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta({ target: { kind: 'group', did: 'did:wba:peer.example:user:bob:e1_xyz' } }),
      body: BODY,
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome).toEqual({ ok: false, reason: 'digest_mismatch' })
  })

  it('rejects a proof whose body was changed after signing', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: { ...BODY, content: 'tampered' },
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome).toEqual({ ok: false, reason: 'digest_mismatch' })
  })

  it('rejects when the keyid belongs to someone other than the caller anchor', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      auth,
      expectedAnchor: 'did:wba:example.com:user:mallory:e1_evil',
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) expect(outcome.reason).toBe('anchor_mismatch')
  })

  it('rejects a signature made by a different key', async () => {
    const other = createAnpIdentity('example.com')
    // The proof names `identity`'s keyid but is signed by another key.
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(other.priv, identity.keyid),
    })
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome).toEqual({ ok: false, reason: 'signature_invalid' })
  })

  it('rejects an extra covered component', async () => {
    const proof = await signOriginProof({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const auth = {
      scheme: ORIGIN_PROOF_SCHEME,
      origin_proof: {
        ...proof,
        signatureInput: proof.signatureInput.replace('"content-digest")', '"content-digest" "@authority")'),
      },
    }
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome).toEqual({ ok: false, reason: 'proof_malformed' })
  })

  it('rejects a mismatched signature label', async () => {
    const proof = await signOriginProof({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const auth = {
      scheme: ORIGIN_PROOF_SCHEME,
      origin_proof: { ...proof, signature: proof.signature.replace(/^sig1=/, 'sig2=') },
    }
    const outcome = await verifyOriginProofDetailed({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      auth,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    })
    expect(outcome).toEqual({ ok: false, reason: 'proof_malformed' })
  })

  it('rejects an unsupported scheme and a target-less meta', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    const base = {
      method: 'direct.send',
      body: BODY,
      expectedAnchor: identity.did,
      resolver: resolverFor(identity.priv, identity.did),
    }

    expect(
      await verifyOriginProofDetailed({ ...base, meta: meta(), auth: { ...auth, scheme: 'other' } }),
    ).toEqual({ ok: false, reason: 'scheme_unsupported' })

    const targetless = meta()
    delete targetless.target
    expect(await verifyOriginProofDetailed({ ...base, meta: targetless, auth })).toEqual({
      ok: false,
      reason: 'proof_malformed',
    })
  })

  it('refuses to sign a method that has no meta.target', async () => {
    const targetless = meta()
    delete targetless.target
    await expect(
      signOriginProof({
        method: 'direct.send',
        meta: targetless,
        body: BODY,
        signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
      }),
    ).rejects.toThrow(/meta\.target/)
  })

  it('boolean form mirrors the detailed form', async () => {
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: meta(),
      body: BODY,
      signer: ed25519OriginProofSigner(identity.priv, identity.keyid),
    })
    expect(
      await verifyOriginProof({
        method: 'direct.send',
        meta: meta(),
        body: BODY,
        auth,
        expectedAnchor: identity.did,
        resolver: resolverFor(identity.priv, identity.did),
      }),
    ).toBe(true)
  })
})

describe('walletOriginProofSigner', () => {
  /** 一个只认一条钥的 resolver：身份对不上就解析不出来。 */
  function resolverFor(curve: 'ed25519' | 'secp256k1', bytes: Uint8Array, did: string): KeyResolver {
    return {
      async resolve(resolvedIdentity: string): Promise<ResolvedIdentityKey> {
        if (resolvedIdentity !== did) throw new Error(`unknown identity ${resolvedIdentity}`)
        return { curve, bytes, identity: did, anchor: { kind: 'fingerprint', thumbprint: 'test' }, docUrl: did }
      },
    }
  }

  const DID = 'did:wba:wallet.example:user:alice:e1_wallet'
  const KEYID = `${DID}#key-1`

  async function roundTrip(wallet: IWallet, curve: 'ed25519' | 'secp256k1'): Promise<boolean> {
    const wire = meta({ sender_did: DID })
    const auth = await buildOriginProofAuth({
      method: 'direct.send',
      meta: wire,
      body: BODY,
      signer: walletOriginProofSigner(wallet, KEYID),
    })
    return verifyOriginProof({
      method: 'direct.send',
      meta: wire,
      body: BODY,
      auth,
      expectedAnchor: DID,
      resolver: resolverFor(curve, await wallet.getPublicKey(), DID),
    })
  }

  it('round-trips a local ed25519 keypair wallet', async () => {
    // 这条证明 `IWallet` 就是 CLI 需要的那个接口：发送侧不必知道钥在本地还是
    // 在钱包里，钥的形状由 wallet 自己交出来。
    const priv = ed25519.utils.randomSecretKey()
    expect(await roundTrip(keypairWallet(priv), 'ed25519')).toBe(true)
  })

  it('round-trips a secp256k1 keypair wallet, whose signature is raw r||s', async () => {
    // `keypairWallet` 的 secp256k1 分支直接签，产出 64 字节；验签侧靠长度选到
    // `secp256k1.verify(sig, msg, key)` 这条，不做 EIP-191 变换。
    const priv = secp256k1.utils.randomSecretKey()
    expect(await roundTrip(keypairWallet(priv, { curve: 'secp256k1' }), 'secp256k1')).toBe(true)
  })

  it('round-trips an EIP-191 wallet, whose signature is 65 bytes and carries recovery id v', async () => {
    // `chainWallet` 走的就是这条：对签名底求个人消息哈希再签，尾部带 v。验签侧看到
    // 65 字节会重算 `ethPersonalSignHash` 并剥掉 v，所以两侧的字节约定必须对得上，
    // 而这正是"签名在本地过、在对端不过"最容易出岔子的地方。
    const priv = secp256k1.utils.randomSecretKey()
    const wallet: IWallet = {
      async getPublicKey() {
        return secp256k1.getPublicKey(priv, true)
      },
      async signMessage(message) {
        const hash = ethPersonalSignHash(message)
        const sig = secp256k1.sign(hash, priv, { prehash: false })
        const expected = secp256k1.getPublicKey(priv, false)
        const parsed = secp256k1.Signature.fromBytes(sig)
        for (const rec of [0, 1]) {
          const point = parsed.addRecoveryBit(rec).recoverPublicKey(hash)
          if (Buffer.from(point.toBytes(false)).equals(Buffer.from(expected))) {
            const out = new Uint8Array(65)
            out.set(sig, 0)
            out[64] = rec + 27
            return out
          }
        }
        throw new Error('could not recover pubkey')
      },
    }
    expect(await roundTrip(wallet, 'secp256k1')).toBe(true)
  })
})

describe('originProofFreshness', () => {
  const now = 1_700_000_000

  it('accepts a fresh proof and reports why an old one is not', () => {
    expect(originProofFreshness({ created: now - 10, now, maxAgeSeconds: 300 })).toEqual({ ok: true })
    expect(originProofFreshness({ created: now - 3600, now, maxAgeSeconds: 300 })).toEqual({
      ok: false,
      reason: 'stale',
    })
    expect(originProofFreshness({ created: now - 10, expires: now - 1, now })).toEqual({
      ok: false,
      reason: 'expired',
    })
  })

  it('tolerates clock skew but not a proof from well into the future', () => {
    expect(originProofFreshness({ created: now + 30, now })).toEqual({ ok: true })
    expect(originProofFreshness({ created: now + 600, now })).toEqual({ ok: false, reason: 'stale' })
  })

  it('rejects a non-positive TTL window', () => {
    expect(originProofFreshness({ created: now - 10, expires: now - 10, now })).toEqual({
      ok: false,
      reason: 'ttl_exceeded',
    })
  })
})
