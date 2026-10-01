// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createAnpIdentity } from '../crypto/signer'
import { resolveVerificationKey } from '../crypto/resolveDid'
import { createNonceStore } from '../crypto/verify'
import { keypairWallet } from '../protocol/adapters/chain'
import { anpProofAdapter, buildWalletIdentity } from './anp'

// ANP-02 proof adapter verify — replay protection. `anpProofAdapter.verify` is the
// server-facing one-call entry point. It is FAIL-CLOSED: it REQUIRES `expectedNonce`
// (the server-issued challenge) and a `nonceStore` that consumes it, proving
// integrity + freshness + one-time use. A call without both throws (ANP-2026-09-08-05).
// The stateless, replayable path is the low-level `verifyHttpMessageSignature`, which
// is intentionally NOT the security boundary for a server that authenticates on true.

const host = 'localhost:3000'
const url = `http://${host}/api/login/anp/verify`

async function buildProof() {
  const identity = createAnpIdentity(host)
  const key = await resolveVerificationKey(identity.keyid, identity.didDocument)
  const { body, headers } = await anpProofAdapter.sign({
    identity,
    nonce: 'n1',
    method: 'POST',
    path: '/api/login/anp/verify',
    authority: host,
    targetUri: url,
    body: JSON.stringify({ nonce: 'n1' }), // ignored by the ANP signer (it rebuilds the body)
  })
  return {
    identity,
    key,
    proof: {
      kind: 'anp',
      method: 'POST',
      path: '/api/login/anp/verify',
      authority: host,
      targetUri: url,
      headers,
      body,
      didDocument: identity.didDocument,
    },
  }
}

describe('buildWalletIdentity — consistent account/key snapshot (ANP-2026-09-08-02)', () => {
  it('fails if the account changes across the snapshot (would build a mismatched DID)', async () => {
    let reads = 0
    const wallet = {
      getPublicKey: async () => new Uint8Array(32),
      signMessage: async () => new Uint8Array(32),
      curve: () => 'ed25519' as const,
      getAccount: async () => {
        reads++
        return reads === 1
          ? { address: '0x1111111111111111111111111111111111111111', chainId: 'eip155:1' }
          : { address: '0x2222222222222222222222222222222222222222', chainId: 'eip155:1' }
      },
    }
    await expect(buildWalletIdentity(wallet, 'localhost')).rejects.toThrow(
      /changed while building identity/,
    )
  })

  it('builds an identity when the account is stable across the snapshot', async () => {
    const wallet = {
      getPublicKey: async () => new Uint8Array(32),
      signMessage: async () => new Uint8Array(32),
      curve: () => 'ed25519' as const,
      getAccount: async () => ({ address: '0x1111111111111111111111111111111111111111', chainId: 'eip155:1' }),
    }
    const identity = await buildWalletIdentity(wallet, 'localhost')
    expect(identity.did.startsWith('eip155:1:')).toBe(true)
  })
})

describe('buildWalletIdentity — baseDocument (the document as the server has it on file)', () => {
  const base = { host: 'did.example.com', path: ['user', 'alice'] }

  /** A real key + the document a DID server would have on file for it, carrying a
   *  `service` entry the builder has no flag for — the field an update hop must not
   *  silently drop (§2.5.3 L411 / L417 / L419). */
  async function onFileDocument() {
    const key = ed25519.utils.randomSecretKey()
    const wallet = keypairWallet(key, { curve: 'ed25519' })
    const composed = await buildWalletIdentity(wallet, base.host, { path: base.path })
    const document = {
      ...composed.didDocument,
      service: [{ id: `${composed.did}#ad`, type: 'AgentDescription', serviceEndpoint: 'https://did.example.com/ad.json' }],
    }
    return { wallet, composed, document }
  }

  it('uses the supplied document verbatim, proof and service included', async () => {
    const { wallet, composed, document } = await onFileDocument()
    const identity = await buildWalletIdentity(wallet, base.host, {
      path: base.path,
      baseDocument: document,
    })

    expect(identity.did).toBe(composed.did)
    expect(identity.didDocument).toEqual(document)
    // NOT re-signed: handing back a copy must not swap a document the server published
    // for one it never saw.
    expect(identity.didDocument.proof).toEqual(composed.didDocument.proof)
    expect(identity.didDocument.service).toEqual(document.service)
  })

  it('refuses a document that describes a different DID', async () => {
    const { wallet, document } = await onFileDocument()
    const otherDid = 'did:wba:did.example.com:user:bob:e1_zzzz'
    await expect(
      buildWalletIdentity(wallet, base.host, {
        path: base.path,
        baseDocument: { ...document, id: otherDid },
      }),
    ).rejects.toThrow(/describes a different DID/)
  })

  it('refuses baseDocument together with service', async () => {
    const { wallet, document } = await onFileDocument()
    await expect(
      buildWalletIdentity(wallet, base.host, {
        path: base.path,
        baseDocument: document,
        service: [{ id: '#x', type: 'AgentDescription', serviceEndpoint: 'https://did.example.com/x' }],
      }),
    ).rejects.toThrow(/not both/)
  })
})

describe('buildWalletIdentity — the binding-key representation (Appendix A A.4)', () => {
  // A.3 L39: the binding key is "Represented as `publicKeyJwk` in DID documents". A.4
  // L76–89 fixes the shape: `type: EcdsaSecp256k1VerificationKey2019` with a
  // `publicKeyJwk` whose members are exactly `{crv, kty, x, y}` (A.3 step 2).
  it('publishes a secp256k1 binding key as publicKeyJwk, never as publicKeyMultibase', async () => {
    const priv = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
    const identity = await buildWalletIdentity(keypairWallet(priv, { curve: 'secp256k1' }), 'example.com')
    expect(identity.did).toContain(':k1_')

    const [vm] = identity.didDocument.verificationMethod as Array<Record<string, unknown>>
    expect(vm.type).toBe('EcdsaSecp256k1VerificationKey2019')
    // ANP-03 L149 reserves `publicKeyMultibase` for Ed25519 `Multikey`; a secp256k1
    // multibase is a shape no other implementation reads (and Appendix A contains no
    // occurrence of the property at all).
    expect(vm).not.toHaveProperty('publicKeyMultibase')
    expect(Object.keys(vm.publicKeyJwk as object).sort()).toEqual(['crv', 'kty', 'x', 'y'])
    expect(vm.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'secp256k1' })
    // base64url, no padding (A.3 step 2) — 32 bytes of coordinate is 43 chars.
    const { x, y } = vm.publicKeyJwk as { x: string; y: string }
    expect(x).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(y).toMatch(/^[A-Za-z0-9_-]{43}$/)

    expect(identity.didDocument['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/secp256k1-2019/v1',
    ])
    // The identity carries the representation the document publishes — not a
    // translated copy of it.
    expect(identity.publicKey).toEqual({ publicKeyJwk: vm.publicKeyJwk })
    // The DID's fingerprint binds that same key: the representation changed, the DID
    // did not.
    await expect(resolveVerificationKey(identity.keyid, identity.didDocument)).resolves.toMatchObject({
      curve: 'secp256k1',
    })
  })

  it('keeps the Multikey representation for Ed25519', async () => {
    const identity = await buildWalletIdentity(
      keypairWallet(ed25519.utils.randomSecretKey(), { curve: 'ed25519' }),
      'example.com',
    )
    const [vm] = identity.didDocument.verificationMethod as Array<Record<string, unknown>>
    expect(vm.type).toBe('Multikey')
    expect(vm).not.toHaveProperty('publicKeyJwk')
    expect((vm.publicKeyMultibase as string).startsWith('z')).toBe(true)
    expect(identity.publicKey).toEqual({ publicKeyMultibase: vm.publicKeyMultibase })
  })
})

describe('anpProofAdapter.verify — replay protection', () => {
  it('rejects a replayed proof when expectedNonce + nonceStore are supplied', async () => {
    const { key, proof } = await buildProof()
    const store = createNonceStore()
    const input = { ...proof, key, expectedNonce: 'n1', nonceStore: store }

    expect(await anpProofAdapter.verify(input)).toBe(true) // first use, consumed
    expect(await anpProofAdapter.verify(input)).toBe(false) // replayed → rejected
  })

  it('rejects when the proof nonce is not bound to the server challenge (extra nonceStore)', async () => {
    const { key, proof } = await buildProof()
    // expectedNonce 'n2' != the proof's 'n1' → the signature is not bound to the
    // challenge. A valid nonceStore is irrelevant here; binding fails first.
    expect(
      await anpProofAdapter.verify({ ...proof, key, expectedNonce: 'n2', nonceStore: createNonceStore() }),
    ).toBe(false)
  })

  it('fail-closed: throws invalid_argument when expectedNonce/nonceStore are omitted', async () => {
    const { key, proof } = await buildProof()
    // The TYPE requires both, but guard against a caller (or a JS consumer) that
    // omits them — a stateless success must never come out of the high-level
    // adapter, since a server would treat `true` as a one-time login event.
    const noGuard = {
      ...proof,
      key,
    } as unknown as Parameters<typeof anpProofAdapter.verify>[0]
    await expect(anpProofAdapter.verify(noGuard)).rejects.toThrow(/expectedNonce|nonceStore/)
  })

  it('single-use across concurrent re-submissions (at most one succeeds)', async () => {
    const { key, proof } = await buildProof()
    const store = createNonceStore()
    const input = { ...proof, key, expectedNonce: 'n1', nonceStore: store }
    // Two in-flight verifications of the same proof share one store → only the
    // first may consume the nonce; the second must be rejected.
    const results = await Promise.all([
      anpProofAdapter.verify(input),
      anpProofAdapter.verify(input),
    ])
    expect(results.filter(Boolean).length).toBe(1)
  })
})
