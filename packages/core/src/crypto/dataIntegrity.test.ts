// eddsa-jcs-2022 DID-document proof: the fixed vector (N3), shape, sign→verify
// round-trip, and the identifier binding that makes a self-signed document mean
// something.

import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  signDidDocumentProof,
  signDidDocumentProofSync,
  verifyDidDocumentProof,
  encodeProofValue,
  decodeProofValue,
  didDocumentProofOptions,
  didDocumentProofPayload,
} from './dataIntegrity'
import { ed25519Fingerprint } from './fingerprint'
import { encodeMultibaseEd25519 } from './multicodec'
import { buildBaseDidDocument } from './didDocument'

function hex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

// A real key + real path-type DID (a genuine e1_ fingerprint), so verification
// exercises the identifier binding rather than a placeholder.
function docFor(did?: string) {
  const priv = ed25519.utils.randomSecretKey()
  const pub = ed25519.getPublicKey(priv)
  const id = did ?? `did:wba:localhost:user:test:${ed25519Fingerprint(pub)}`
  const keyid = `${id}#key-1`
  const doc = buildBaseDidDocument({ did: id, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) })
  return { priv, pub, did: id, keyid, doc }
}

// N3: a fixed vector whose expected `proofValue` was computed by an INDEPENDENT
// implementation (Python `cryptography` Ed25519 + hand-written RFC 8785 JCS and
// base58btc), not by this SDK. It pins the whole encoding chain at once: the JCS
// payload, the Ed25519 signature, and the multibase `z…` base58btc wrapper.
//
// Seed 0x01..0x20; did:wba path with the matching e1_ fingerprint; proof created
// 2026-01-01T00:00:00Z over the base document below.
const VECTOR = {
  privHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  did: 'did:wba:example.com:user:alice:e1_WWpn_pfHui9YKR4CZtQsDGMu7_Gch2zYChfSvnxgtPk',
  publicKeyMultibase: 'z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
  created: '2026-01-01T00:00:00Z',
  payloadHex:
    '4bcd3bc5f97f66b69f1ac871ee70bd519e03fc25f46a8116c1702a96841a8b93' +
    'eaf53fff28ed5febbdae39599aa4acc83143786dad9c1219cb05b2fc36431306',
  proofValue: 'zg1pf7bhsMXuHmsBa8BCoLLFL6WLaVF47c1PitEYhSuHrcPvaU9dBmFYtk7VATx8EtND5DassWaVaZsYVUMP8FiE',
}

describe('eddsa-jcs-2022 fixed vector (N3)', () => {
  it('reproduces the independently computed signature and proofValue', () => {
    const keyid = `${VECTOR.did}#key-1`
    const doc = buildBaseDidDocument({
      did: VECTOR.did,
      keyid,
      publicKeyMultibase: VECTOR.publicKeyMultibase,
    })
    const proof = signDidDocumentProofSync(doc, keyid, hex(VECTOR.privHex), {
      created: VECTOR.created,
    })

    // The payload is what the signature commits to; compare it first so a
    // mismatch points at JCS rather than at Ed25519 or base58.
    expect(didDocumentProofPayload(didDocumentProofOptions(keyid, { created: VECTOR.created }), doc))
      .toEqual(hex(VECTOR.payloadHex))
    expect(proof.proofValue).toBe(VECTOR.proofValue)
    // 64-byte signature → 88 base58 chars is not implied; just pin the marker.
    expect(String(proof.proofValue).startsWith('z')).toBe(true)
    expect(decodeProofValue(proof.proofValue)).toHaveLength(64)
  })

  it('verifies the vector against its own identifier', () => {
    const keyid = `${VECTOR.did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({
        did: VECTOR.did,
        keyid,
        publicKeyMultibase: VECTOR.publicKeyMultibase,
      }),
      proof: {
        type: 'DataIntegrityProof',
        created: VECTOR.created,
        verificationMethod: keyid,
        proofPurpose: 'assertionMethod',
        cryptosuite: 'eddsa-jcs-2022',
        proofValue: VECTOR.proofValue,
      },
    }
    expect(verifyDidDocumentProof(doc, { did: VECTOR.did })).toBe(true)
  })

  it('encodeProofValue is the multibase base58btc form, not base64', () => {
    const bytes = hex(VECTOR.payloadHex)
    const encoded = encodeProofValue(bytes)
    expect(encoded[0]).toBe('z')
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
    expect(encoded).not.toContain('=')
    expect(decodeProofValue(encoded)).toEqual(bytes)
  })

  it('decodeProofValue rejects anything that is not multibase base58btc', () => {
    // The SAME signature in base64url — the pre-0.3.0 SDK form, and still what
    // agent-on emits. It must not decode: the `z` marker is the whole point.
    expect(
      decodeProofValue(
        'IaTzPPExHykFeZViw1R4uKS9_ghxgZSf5apXedXXqbvsZn_KqqAvlFrk51qVxTJibbjHshLdB5GdPYsgOWzyBw',
      ),
    ).toBeNull()
    expect(decodeProofValue('AbC+/=')).toBeNull() // no `z` marker
    expect(decodeProofValue('z0OIl')).toBeNull() // 0/O/I/l are not base58 chars
    expect(decodeProofValue('z')).toBeNull() // no signature at all
    expect(decodeProofValue(42)).toBeNull()
    expect(decodeProofValue(null)).toBeNull()
    expect(decodeProofValue(undefined)).toBeNull()
  })
})

describe('signDidDocumentProof (eddsa-jcs-2022)', () => {
  it('produces the ANP proof shape and a signature that verifies over the doc', async () => {
    const { priv, pub, did, keyid, doc } = docFor()
    const proof = await signDidDocumentProof(doc, keyid, (m) => ed25519.sign(m, priv))

    expect(proof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      proofPurpose: 'assertionMethod',
      verificationMethod: keyid,
    })
    expect(typeof proof.created).toBe('string')

    // Recompute the signed payload from the document + proof options and verify.
    const options = { ...proof }
    delete (options as Record<string, unknown>).proofValue
    const payload = didDocumentProofPayload(options, doc)
    const signature = decodeProofValue(proof.proofValue)
    expect(signature).not.toBeNull()
    expect(ed25519.verify(signature!, payload, pub)).toBe(true)

    // Tampering with the document breaks the signature.
    const tampered = didDocumentProofPayload(options, { ...doc, id: 'did:wba:evil' })
    expect(ed25519.verify(signature!, tampered, pub)).toBe(false)

    // The full-document verify path agrees.
    expect(verifyDidDocumentProof({ ...doc, proof }, { did })).toBe(true)
  })

  it('sync and async paths produce identical bytes for the same created/DOM', async () => {
    const { priv, keyid, doc } = docFor()
    const opts = { created: '2026-01-01T00:00:00Z' }
    const a = await signDidDocumentProof(doc, keyid, (m) => ed25519.sign(m, priv), opts)
    const b = signDidDocumentProofSync(doc, keyid, priv, opts)
    expect(a).toEqual(b)
  })

  it('settings include domain/challenge only when provided', () => {
    expect(didDocumentProofOptions('k#1')).not.toHaveProperty('domain')
    expect(didDocumentProofOptions('k#1', { domain: 'example.com', challenge: 'abc' })).toMatchObject({
      domain: 'example.com',
      challenge: 'abc',
    })
  })
})

describe('verifyDidDocumentProof', () => {
  function signed(did?: string) {
    const parts = docFor(did)
    const proof = signDidDocumentProofSync(parts.doc, parts.keyid, parts.priv, {
      created: '2026-01-01T00:00:00Z',
    })
    return { ...parts, signedDoc: { ...parts.doc, proof } }
  }

  it('binds the proof key to the DID fingerprint', () => {
    const victim = signed()
    expect(verifyDidDocumentProof(victim.signedDoc, { did: victim.did })).toBe(true)

    // The attack this check exists for: an attacker builds a perfectly
    // self-consistent document — their own key, correctly signed by that key —
    // but serves it under the VICTIM's DID and keyid. Without the fingerprint
    // binding the proof verifies; with it, the key does not reproduce `e1_…`.
    const attackerPriv = ed25519.utils.randomSecretKey()
    const attackerDoc = buildBaseDidDocument({
      did: victim.did,
      keyid: victim.keyid,
      publicKeyMultibase: encodeMultibaseEd25519(ed25519.getPublicKey(attackerPriv)),
    })
    const spoofed = {
      ...attackerDoc,
      proof: signDidDocumentProofSync(attackerDoc, victim.keyid, attackerPriv, {
        created: '2026-01-01T00:00:00Z',
      }),
    }
    expect(verifyDidDocumentProof(spoofed)).toBe(true) // self-signature alone proves nothing
    expect(verifyDidDocumentProof(spoofed, { did: victim.did })).toBe(false)
  })

  it('rejects a proof whose verificationMethod is not in this document', () => {
    const { signedDoc } = signed()
    const forged = {
      ...signedDoc,
      proof: { ...(signedDoc.proof as Record<string, unknown>), verificationMethod: 'did:wba:evil#key-1' },
    }
    expect(verifyDidDocumentProof(forged)).toBe(false)
  })

  it('rejects a wrong cryptosuite, purpose, type, or a non-multibase proofValue', () => {
    const { signedDoc } = signed()
    const proof = signedDoc.proof as Record<string, unknown>
    const base = { ...signedDoc }
    expect(verifyDidDocumentProof({ ...base, proof: { ...proof, cryptosuite: 'eddsa-rdfc-2022' } })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: { ...proof, proofPurpose: 'authentication' } })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: { ...proof, type: 'Ed25519Signature2020' } })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: { ...proof, proofValue: 'AbC+/=' } })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: undefined })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: [proof] })).toBe(false)
    expect(verifyDidDocumentProof({ ...base, proof: 'nope' })).toBe(false)
  })

  it('rejects a tampered document under a valid proof', () => {
    const { did, signedDoc } = signed()
    expect(verifyDidDocumentProof({ ...signedDoc, alsoKnownAs: ['did:web:evil'] }, { did })).toBe(false)
  })

  // A proof key is only this document's key when the document ESTABLISHES the DID Core
  // relationship: it must control the method the proof names, and name it as the SAME
  // resolved DID URL. The check used to demand merely that a string `controller` not
  // differ, so a missing / array / non-string controller slipped through; and both
  // sides used to be compared by raw spelling, so a fragment alias could cross DID
  // namespaces (ANP-2026-09-17-02, ANP-2026-09-17-R01).
  describe('the proof key must be controlled by the document', () => {
    /** A document whose proof is internally consistent — signed AFTER the ids and the
     *  controller were set — so the ONLY thing that can reject it is the binding under
     *  test. `methodId` / `proofKeyId` receive `(did, absoluteKeyid)` so a test can
     *  spell either one absolutely or relatively; both default to the document's
     *  absolute keyid, and `proofKeyId` defaults to whatever `methodId` produced.
     *  `controller` absent from `opts` means "the document id", the valid shape;
     *  `dropController` removes the field entirely. */
    function signedWith(
      opts: {
        controller?: unknown
        dropController?: boolean
        methodId?: (did: string, keyid: string) => string
        proofKeyId?: (did: string, keyid: string) => string
      } = {},
    ): { did: string; doc: Record<string, unknown> } {
      const priv = ed25519.utils.randomSecretKey()
      const pub = ed25519.getPublicKey(priv)
      const did = `did:wba:example.com:user:test:${ed25519Fingerprint(pub)}`
      const absolute = `${did}#key-1`
      const methodId = opts.methodId ? opts.methodId(did, absolute) : absolute
      const keyid = opts.proofKeyId ? opts.proofKeyId(did, absolute) : methodId
      const doc = buildBaseDidDocument({ did, keyid: methodId, publicKeyMultibase: encodeMultibaseEd25519(pub) })
      const vm = { ...(doc.verificationMethod as Record<string, unknown>[])[0] }
      if (opts.dropController) delete vm.controller
      else vm.controller = 'controller' in opts ? opts.controller : did
      doc.verificationMethod = [vm]
      doc.proof = signDidDocumentProofSync(doc, keyid, priv, { created: '2026-01-01T00:00:00Z' })
      return { did, doc }
    }

    it('accepts the document id as controller, in absolute and relative form', () => {
      const absolute = signedWith()
      expect(verifyDidDocumentProof(absolute.doc, { did: absolute.did })).toBe(true)

      // The DID-spec relative form carries no DID of its own, so `controller` is the
      // only thing that places it — which is the case this binding exists for. It also
      // resolves against `doc.id`, so it IS the document's own keyid and must pass the
      // fingerprint binding too.
      const relative = signedWith({ methodId: () => '#key-1' })
      expect(verifyDidDocumentProof(relative.doc)).toBe(true)
      expect(verifyDidDocumentProof(relative.doc, { did: relative.did })).toBe(true)
    })

    it('rejects a controller that is absent, non-string, an array or another DID', () => {
      const cases: Record<string, unknown>[] = [
        { dropController: true }, // no relationship is stated at all
        { controller: 42 },
        { controller: null },
        { controller: ['did:wba:example.com:user:test'] }, // a set is not the exact id
        { controller: 'did:wba:evil.com:user:test' },
      ]
      for (const shape of cases) {
        const { did, doc } = signedWith(shape)
        // The signature IS valid over this document — the binding is what rejects it.
        expect(verifyDidDocumentProof(doc, { did })).toBe(false)
        expect(verifyDidDocumentProof(doc)).toBe(false)
      }
    })

    it('rejects an absolute method id that names a DIFFERENT DID', () => {
      // The controller says "this document's DID" while the id lives in another DID's
      // space — a method cannot be the document's own key and someone else's at once.
      const { doc } = signedWith({ methodId: () => 'did:wba:evil.com:user:test#key-1' })
      expect(verifyDidDocumentProof(doc)).toBe(false)
    })

    it('does not let a fragment alias a method across DID namespaces', () => {
      // The document describes its OWN `#key-1`; the proof names
      // `did:wba:evil.com:user:test#key-1`. Matching the fragment alone would call
      // those one identifier and let an outsider's DID URL resolve — and be recorded
      // as — this document's key (ANP-2026-09-17-R01). The signature is valid over
      // this document, so only the namespace check can reject it.
      const { did, doc } = signedWith({
        methodId: () => '#key-1',
        proofKeyId: () => 'did:wba:evil.com:user:test#key-1',
      })
      expect(verifyDidDocumentProof(doc)).toBe(false)
      expect(verifyDidDocumentProof(doc, { did })).toBe(false)
    })

    it('treats the absolute and relative spellings of one DID URL as the same keyid', () => {
      // `#key-1` inside a document whose id is `did:X` IS `did:X#key-1`, so the two
      // spellings interoperate in EITHER direction — the method may be written
      // absolutely and named relatively, or the other way round.
      const relativeProof = signedWith({ proofKeyId: () => '#key-1' })
      expect(verifyDidDocumentProof(relativeProof.doc)).toBe(true)

      const relativeMethod = signedWith({ methodId: () => '#key-1', proofKeyId: (_did, keyid) => keyid })
      expect(verifyDidDocumentProof(relativeMethod.doc)).toBe(true)
      expect(verifyDidDocumentProof(relativeMethod.doc, { did: relativeMethod.did })).toBe(true)
    })
  })
})
