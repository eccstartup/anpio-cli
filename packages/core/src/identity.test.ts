import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  normalizeChainId,
  normalizeAddress,
  identityDid,
  domainServiceDid,
  webIdentityDid,
  encodeDidHost,
  subjectOf,
  stableSubjectId,
  DEFAULT_WBA_PATH,
} from './identity'
import { didToUrl } from './crypto/resolveDid'
import { errorCode } from './errors'
import { keypairWallet, chainWalletConnector } from './protocol/adapters/chain'

const ADDR_UPPER = '0x' + 'AB'.repeat(20) // valid 40-hex, checksummed-looking
const ADDR_LOWER = '0x' + 'ab'.repeat(20)

// Two deterministic ed25519 public keys (distinct private keys).
const pubA = ed25519.getPublicKey(new Uint8Array(32).fill(1))
const pubB = ed25519.getPublicKey(new Uint8Array(32).fill(2))
const keyA = { curve: 'ed25519' as const, publicKey: pubA }
const FP_A = identityDid('localhost', undefined, undefined, keyA).split(':').pop()!

describe('identity format contract', () => {
  it('binds a key into a path-type did:wba with an e1_ fingerprint (default path)', () => {
    const did = identityDid('localhost', undefined, undefined, keyA)
    expect(did).toBe(`did:wba:localhost:${DEFAULT_WBA_PATH.join(':')}:${FP_A}`)
    expect(FP_A).toMatch(/^e1_[A-Za-z0-9_-]{43}$/)
    // A partial chain descriptor falls back to the keyed did:wba identity.
    expect(identityDid('example.com', 'eip155:1', undefined, keyA)).toMatch(/^did:wba:example\.com:/)
    expect(identityDid('example.com', undefined, ADDR_LOWER, keyA)).toMatch(/^did:wba:example\.com:/)
  })

  it('two distinct keys on one host get distinct DIDs (no bare-domain collision)', () => {
    expect(identityDid('localhost', undefined, undefined, keyA)).not.toBe(
      identityDid('localhost', undefined, undefined, { curve: 'ed25519', publicKey: pubB }),
    )
  })

  it('honours a custom path and rejects a path-injecting segment', () => {
    expect(identityDid('localhost', undefined, undefined, { ...keyA, path: ['user', 'claude-code'] })).toBe(
      `did:wba:localhost:user:claude-code:${FP_A}`,
    )
    expect(errorCode(catchErr(() => identityDid('localhost', undefined, undefined, { ...keyA, path: ['a:b'] })))).toBe(
      'invalid_argument',
    )
    expect(errorCode(catchErr(() => identityDid('localhost', undefined, undefined, { ...keyA, path: [] })))).toBe(
      'invalid_argument',
    )
  })

  it('percent-encodes a host port so it is not read as a path separator', () => {
    expect(encodeDidHost('localhost:3000')).toBe('localhost%3A3000')
    expect(identityDid('localhost:3000', undefined, undefined, keyA)).toBe(`did:wba:localhost%3A3000:${DEFAULT_WBA_PATH.join(':')}:${FP_A}`)
  })

  it('refuses to emit a keyless bare-domain DID', () => {
    expect(errorCode(catchErr(() => identityDid('localhost')))).toBe('invalid_argument')
  })

  it('builds the bare-domain service DID without reopening the identity refusal', () => {
    // The boundary in one place: the SAME host. An identity needs a key and is
    // refused without one; a domain-level service DID has no key by definition and
    // is exactly what this constructor is for. Keeping them separate is what stops
    // "serviceDid has a constructor" from being read as "the SDK emits bare domains
    // as identities".
    expect(errorCode(catchErr(() => identityDid('example.com')))).toBe('invalid_argument')
    expect(domainServiceDid('example.com')).toBe('did:wba:example.com')
  })

  it('percent-encodes a port into the service DID and accepts either spelling', () => {
    expect(domainServiceDid('example.com:8800')).toBe('did:wba:example.com%3A8800')
    // The spec writes the encoded form; feeding it back must not double-encode.
    expect(domainServiceDid('example.com%3A8800')).toBe('did:wba:example.com%3A8800')
  })

  it('derives the bare-domain URL a resolver would use, with no fingerprint to strip', () => {
    const did = domainServiceDid('example.com:8800')
    expect(didToUrl(did)).toBe('https://example.com:8800/.well-known/did.json')
    // No `e1_`/`k1_` segment: the path-fingerprint binding does not apply, so this
    // DID can never be mistaken for a keyed identity.
    expect(did).not.toMatch(/e1_|k1_/)
    // With no fingerprint segment there is nothing to strip, so the service DID is
    // its own stable subject.
    expect(stableSubjectId(did)).toBe('example.com%3A8800')
  })

  it('rejects a host that could not resolve as a bare-domain DID', () => {
    // Each of these would produce a DID whose document URL the resolver refuses —
    // failing here instead keeps a malformed serviceDid out of a signed document.
    for (const host of ['https://example.com', 'example.com/users/alice', 'example.com:http']) {
      expect(errorCode(catchErr(() => domainServiceDid(host))), host).toBe('invalid_did')
    }
    // An empty host never reaches the DID shape at all — `encodeDidHost` rejects it.
    expect(errorCode(catchErr(() => domainServiceDid('')))).toBe('invalid_argument')
  })

  it('forms a native did:web DID, with or without a path (Appendix B)', () => {
    expect(webIdentityDid('identity.example')).toBe('did:web:identity.example')
    expect(webIdentityDid('identity.example', [])).toBe('did:web:identity.example')
    expect(webIdentityDid('identity.example', ['users', 'alice'])).toBe('did:web:identity.example:users:alice')
    // The DID carries no key material of any kind: the trust root is the domain's
    // TLS certificate plus the document it serves (ANP-02 附录 B B.1 L470).
    expect(webIdentityDid('identity.example', ['alice'])).not.toMatch(/e1_|k1_/)
  })

  it('maps a did:web to the URL that serves its document', () => {
    // A bare host is served from the well-known path; a path is served from the
    // path itself. This is the ONE location a verifier may fetch from.
    expect(didToUrl(webIdentityDid('identity.example'))).toBe('https://identity.example/.well-known/did.json')
    expect(didToUrl(webIdentityDid('identity.example', ['users', 'alice']))).toBe(
      'https://identity.example/users/alice/did.json',
    )
  })

  it('percent-encodes a port in a did:web host, exactly as did:wba does', () => {
    // `:` is the method-specific-id separator, so an unencoded port would be read
    // as a path segment rather than part of the host.
    expect(webIdentityDid('identity.example:8443')).toBe('did:web:identity.example%3A8443')
    expect(didToUrl(webIdentityDid('identity.example:8443'))).toBe('https://identity.example:8443/.well-known/did.json')
  })

  it("is its own subject — a did:web DID has no fingerprint to drop", () => {
    const did = webIdentityDid('identity.example', ['alice'])
    expect(subjectOf(did)).toBe(did)
    // And it never collapses onto a did:wba subject of the same host.
    expect(subjectOf(did)).not.toBe(subjectOf(identityDid('identity.example', undefined, undefined, keyA)))
  })

  it('rejects a did:web that could not resolve as one', () => {
    // Each would produce a DID whose document URL the resolver refuses, so the
    // failure belongs at construction, not at the far end of a network call.
    for (const host of ['https://identity.example', 'identity.example/users/alice', 'identity.example:http']) {
      expect(errorCode(catchErr(() => webIdentityDid(host))), host).toBe('invalid_did')
    }
    expect(errorCode(catchErr(() => webIdentityDid('')))).toBe('invalid_argument')
    // A path segment that could forge another segment (`:`) or escape the DID (`/`).
    for (const segment of ['a:b', 'a/b', '']) {
      expect(errorCode(catchErr(() => webIdentityDid('identity.example', [segment]))), segment).toBe('invalid_argument')
    }
  })

  it('forms a CAIP-10 account id from chain id + address, lowercasing EVM addresses', () => {
    expect(identityDid('example.com', 'eip155:1', ADDR_UPPER, keyA)).toBe(`eip155:1:${ADDR_LOWER}`)
  })

  it('normalizes EIP-1193 hex and bare decimal chain ids to CAIP-2 eip155', () => {
    expect(normalizeChainId('0x1')).toBe('eip155:1')
    expect(normalizeChainId('0x89')).toBe('eip155:137')
    expect(normalizeChainId('1')).toBe('eip155:1')
    expect(normalizeChainId('eip155:1')).toBe('eip155:1')
    expect(normalizeChainId('cosmos:cosmoshub-3')).toBe('cosmos:cosmoshub-3')
  })

  it('keeps large chain ids exact instead of collapsing them onto one value', () => {
    // 2^53 and 2^53 + 1: `Number` rounds both to the same value, which would make
    // two different chains share one CAIP-10 account id. `BigInt` must not.
    expect(normalizeChainId('9007199254740992')).toBe('eip155:9007199254740992')
    expect(normalizeChainId('9007199254740993')).toBe('eip155:9007199254740993')
    expect(normalizeChainId('9007199254740992')).not.toBe(normalizeChainId('9007199254740993'))
    // The same boundary in EIP-1193 hex form.
    expect(normalizeChainId('0x20000000000000')).toBe('eip155:9007199254740992')
    expect(normalizeChainId('0x20000000000001')).toBe('eip155:9007199254740993')
    expect(normalizeChainId('0x20000000000000')).not.toBe(normalizeChainId('0x20000000000001'))
  })

  it('rejects a chain id that is out of range instead of parsing an unbounded value', () => {
    expect(errorCode(catchErr(() => normalizeChainId('9'.repeat(65))))).toBe('invalid_argument')
    expect(errorCode(catchErr(() => normalizeChainId('0x' + 'A'.repeat(65))))).toBe('invalid_argument')
  })

  it('rejects a malformed chain id instead of emitting a malformed DID', () => {
    expect(errorCode(catchErr(() => normalizeChainId('garbage')))).toBe('invalid_argument')
    expect(errorCode(catchErr(() => normalizeChainId('')))).toBe('invalid_argument')
  })

  it('validates and lowercases EVM addresses, leaves non-EVM addresses verbatim', () => {
    expect(normalizeAddress('eip155:1', ADDR_UPPER)).toBe(ADDR_LOWER)
    expect(normalizeAddress('solana:mainnet', '  SomeAddr  ')).toBe('SomeAddr')
    expect(errorCode(catchErr(() => normalizeAddress('eip155:1', '0x123')))).toBe('invalid_argument')
  })

  it('a chain wallet with a raw EIP-1193 chain id resolves to a normalized CAIP-10 DID', async () => {
    // A non-zero deterministic secp256k1 key. The DID is built from the descriptor
    // (keypairWallet has no live account), so the address need not match the key here.
    const priv = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
    const connector = chainWalletConnector(keypairWallet(priv, { curve: 'secp256k1' }), {
      host: 'localhost',
      chainId: '0x89', // raw EIP-1193 hex, must become eip155:137
      address: ADDR_UPPER,
    })
    const identity = await connector.getIdentity()
    expect(identity.did).toBe(`eip155:137:${ADDR_LOWER}`)
    expect(identity.keyid).toBe(`eip155:137:${ADDR_LOWER}#key-1`)
    const vm = (identity.didDocument as { verificationMethod: { controller: string; type: string }[] })
      .verificationMethod[0]
    expect(vm.controller).toBe(identity.did)
    // A CAIP-10 account id binds no key to the DID, yet the document still publishes
    // the wallet's key — in the representation that curve's profile uses (Appendix A
    // A.4): a secp256k1 JWK, never a secp256k1 multibase.
    expect(vm.type).toBe('EcdsaSecp256k1VerificationKey2019')
  })
})

function catchErr(fn: () => unknown): unknown {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected fn to throw')
}


// Part S3 (0.3.0): the two-layer identity. A DID binds a key, so it CHANGES when the
// key changes; the subject does not. These cover the half of that promise the rest of
// the suite only exercised indirectly (every other use of `subjectOf` is a fixture).
describe('stable subject — update survives, key does not (S3)', () => {
  // Same agent, same path, two DIFFERENT keys: the case an update produces.
  const AGENT_PATH = ['user', 'claude-code']

  it('keeps one subject across a key update while the DID changes', () => {
    const didA = identityDid('example.com', undefined, undefined, { ...keyA, path: AGENT_PATH })
    const didB = identityDid('example.com', undefined, undefined, {
      curve: 'ed25519',
      publicKey: pubB,
      path: AGENT_PATH,
    })

    expect(didA).not.toBe(didB) // the fingerprint segment differs
    expect(subjectOf(didA)).toBe(subjectOf(didB))
    expect(subjectOf(didA)).toBe('did:wba:example.com:user:claude-code')
    // ...and the subject carries no trace of either key.
    expect(subjectOf(didA)).not.toContain(FP_A)
  })

  it('keeps one subject across an update through the connector that produces it', async () => {
    // Same claim as above, but through the REAL production path (`buildWalletIdentity`
    // → `subjectOf`) rather than by calling the derivation directly, so a connector
    // that stopped filling `subject` (or filled the DID) would fail here.
    const mk = (fill: number) =>
      chainWalletConnector(keypairWallet(new Uint8Array(32).fill(fill), { curve: 'ed25519' }), {
        host: 'example.com',
        path: AGENT_PATH,
      })
    const a = await mk(11).getIdentity()
    const b = await mk(12).getIdentity()

    expect(a.did).not.toBe(b.did)
    expect(a.subject).toBe(b.subject)
    expect(a.subject).toBe('did:wba:example.com:user:claude-code')
    // The DID stays the wire credential: keyid and document are built from it, not
    // from the subject.
    expect(a.keyid).toBe(`${a.did}#key-1`)
    expect((a.didDocument as { id: string }).id).toBe(a.did)
  })

  it('keeps a did:web identity as its own subject', () => {
    // A did:web DID has no fingerprint segment, so there is nothing to strip: the
    // subject IS the DID, method and all.
    expect(subjectOf('did:web:example.com:users:alice')).toBe('did:web:example.com:users:alice')
    expect(subjectOf('did:web:example.com')).toBe('did:web:example.com')
    // did:web and did:wba share a host and a path but NOT a trust root (a native
    // did:web document carries no WBA proof — ANP-02 Appendix B), so one method's
    // identity must never address the other's. Keeping the method in the subject is
    // what makes that structural rather than a convention.
    expect(subjectOf('did:web:example.com:alice')).not.toBe(subjectOf('did:wba:example.com:alice'))
    // Only `did:wba` has a fingerprint concept, so a fingerprint-LOOKING segment of a
    // did:web is a real path segment and must be kept.
    expect(subjectOf('did:web:example.com:e1_abc')).toBe('did:web:example.com:e1_abc')
  })

  it('returns a CAIP-10 account id verbatim as the subject', () => {
    // A chain account is already a stable, namespace-qualified identity — there is
    // nothing to strip and nothing to add.
    const account = `eip155:1:${ADDR_LOWER}`
    expect(subjectOf(account)).toBe(account)
  })

  it('derives a did:webvh subject from the identifier path, dropping the scid', () => {
    // connectx's LOCAL convention (ADR-0002 §2.6): upstream defines no stable subject
    // for did:webvh. The SCID self-certifies the LOG, not the subject, so it is
    // dropped — which is also why the subject does not change when the log is
    // re-created. May change to the official rule in 0.4.0.
    expect(subjectOf('did:webvh:abc123:example.com:user:alice')).toBe('did:webvh:example.com:user:alice')
    expect(subjectOf('did:webvh:abc123:example.com:user:alice')).toBe(
      subjectOf('did:webvh:zzz999:example.com:user:alice'),
    )
  })

  it('rejects a DID it cannot derive a subject from', () => {
    expect(errorCode(catchErr(() => subjectOf('')))).toBe('invalid_did')
    expect(errorCode(catchErr(() => subjectOf('did:webvh:onlyscid')))).toBe('invalid_did')
  })
})

describe('stableSubjectId — the protocol concept, did:wba only (S3)', () => {
  it('strips the method prefix and the trailing key fingerprint', () => {
    expect(stableSubjectId(`did:wba:example.com:user:alice:e1_${'a'.repeat(43)}`)).toBe('example.com:user:alice')
    expect(stableSubjectId(`did:wba:localhost%3A3000:user:claude-code:e1_${'a'.repeat(43)}`)).toBe(
      'localhost%3A3000:user:claude-code',
    )
    // The port stays percent-encoded, so the subject cannot be re-split on `:` into
    // a different host/path pair than the DID it came from.
    expect(stableSubjectId(`did:wba:localhost%3A3000:user:claude-code:e1_${'a'.repeat(43)}`)).not.toContain(
      'localhost:3000',
    )
  })

  it('only strips the last segment when it really is a fingerprint', () => {
    // Fingerprints are fixed-length (43 chars after the `e1_`/`k1_` prefix). A short
    // or malformed look-alike is kept as a path segment rather than guessed at, so
    // `stableSubjectId` never silently drops a real segment.
    expect(stableSubjectId('did:wba:example.com:user:e1_short')).toBe('example.com:user:e1_short')
    expect(stableSubjectId(`did:wba:example.com:user:k1_${'a'.repeat(42)}`)).toBe(
      `example.com:user:k1_${'a'.repeat(42)}`,
    )
  })

  it('keeps a bare-domain did:wba whole (there is no fingerprint to strip)', () => {
    expect(stableSubjectId('did:wba:example.com')).toBe('example.com')
    // A last segment that merely LOOKS like a path segment is not a fingerprint.
    expect(stableSubjectId('did:wba:example.com:alice')).toBe('example.com:alice')
  })

  it('throws invalid_did for every method that defines no stable subject path', () => {
    // Returning a look-alike for these would invent a protocol concept upstream has
    // not defined. `subjectOf` is the total function; this one is deliberately partial.
    for (const did of [
      'did:web:example.com:users:alice',
      'did:web:example.com',
      'did:webvh:abc123:example.com:user:alice',
      `eip155:1:${ADDR_LOWER}`,
      'did:key:z6Mk',
      '',
    ]) {
      expect(errorCode(catchErr(() => stableSubjectId(did)))).toBe('invalid_did')
    }
  })

  it('agrees with stableSubjectId on the did:wba part it does define', () => {
    const did = `did:wba:example.com:user:alice:e1_${'b'.repeat(43)}`
    // The two are deliberately different shapes (naked protocol field vs showable
    // local identity), so the invariant is stated as what it is: same path, and for
    // did:wba the only difference is the method prefix.
    expect(stableSubjectId(did)).toBe('example.com:user:alice')
    expect(subjectOf(did)).toBe(`did:wba:${stableSubjectId(did)}`)
  })
})
