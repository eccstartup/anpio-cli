import { describe, it, expect } from 'vitest'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  didToUrl,
  resolveVerificationKey,
  resolveDidDocument,
  verifyDidDocument,
  createDidDocumentStore,
  fetchControlledJson,
  pinnedFetch,
  DID_DOCUMENT_FETCH_CODES,
} from './resolveDid'
import { encodeMultibaseEd25519, encodeMultibaseSecp256k1 } from './multicodec'
import { didFingerprint } from './fingerprint'
import { bytesToBase64 } from './encoding'
import { signDidDocumentProofSync } from './dataIntegrity'
import { buildBaseDidDocument } from './didDocument'

// A `k1_` document in the shape the READER tolerates: a secp256k1 key published as
// `publicKeyMultibase`. This SDK does not PRODUCE that shape — Appendix A A.4 gives a
// secp256k1 binding key as `publicKeyJwk`, and ANP-03 L149 reserves the multibase
// property for Ed25519 `Multikey` — but another implementation's document may carry it,
// so `resolveVerificationKey` accepts it and these fixtures pin that tolerance.
function k1Doc(did: string, keyid: string, publicKeyMultibase: string): Record<string, unknown> {
  return {
    id: did,
    verificationMethod: [{ id: keyid, type: 'Multikey', controller: did, publicKeyMultibase }],
    authentication: [keyid],
  }
}

describe('didToUrl', () => {
  it('maps a bare did:web host to the well-known document', () => {
    expect(didToUrl('did:web:example.com')).toBe('https://example.com/.well-known/did.json')
  })

  it('maps a did:web with path segments to a nested did.json', () => {
    expect(didToUrl('did:web:example.com:users:alice')).toBe('https://example.com/users/alice/did.json')
  })

  it('decodes a %3A-encoded port on the host segment', () => {
    expect(didToUrl('did:web:example.com%3A8080')).toBe('https://example.com:8080/.well-known/did.json')
  })

  it('keeps path segments after a %3A-encoded port (no false separator)', () => {
    expect(didToUrl('did:web:example.com%3A8080:users:alice')).toBe(
      'https://example.com:8080/users/alice/did.json',
    )
  })

  it('supports did:wba with a %3A-encoded port', () => {
    expect(didToUrl('did:wba:localhost%3A3000')).toBe('https://localhost:3000/.well-known/did.json')
  })

  it('resolves a path-type did:wba (fingerprint segment) to a nested did.json', () => {
    expect(didToUrl('did:wba:example.com:user:alice:e1_abc')).toBe('https://example.com/user/alice/e1_abc/did.json')
    expect(didToUrl('did:wba:localhost%3A3000:user:claude-code:e1_abc')).toBe(
      'https://localhost:3000/user/claude-code/e1_abc/did.json',
    )
  })

  it('treats a bare colon segment (unencoded port) as a path segment', () => {
    expect(didToUrl('did:wba:localhost:3000')).toBe('https://localhost/3000/did.json')
  })

  it('throws when no host can be derived', () => {
    expect(() => didToUrl('did:web:')).toThrow()
  })
})

// ANP-2026-09-11-04: `didToUrl` feeds a network fetch on an allowlisted host, so a
// DID segment must not be able to escape its path. Every segment is validated AFTER
// decoding, and the method prefix is matched case-sensitively.
describe('didToUrl — syntax and traversal strictness (ANP-2026-09-11-04)', () => {
  it('rejects a non-DID string', () => {
    expect(() => didToUrl('example.com:user')).toThrow(/Cannot derive URL/)
  })

  it('rejects a different DID method', () => {
    expect(() => didToUrl('did:key:z6Mk')).toThrow(/Cannot derive URL/)
  })

  it('rejects an uppercase method prefix (exact lowercase match required)', () => {
    expect(() => didToUrl('did:WEB:example.com')).toThrow(/Cannot derive URL/)
    expect(() => didToUrl('did:WBA:example.com')).toThrow(/Cannot derive URL/)
  })

  it('rejects empty segments from a leading, doubled or trailing colon', () => {
    expect(() => didToUrl('did:web::example.com')).toThrow(/empty segment/)
    expect(() => didToUrl('did:web:example.com::users')).toThrow(/empty segment/)
    expect(() => didToUrl('did:web:example.com:users:')).toThrow(/empty segment/)
  })

  it('rejects `.` and `..` path segments', () => {
    expect(() => didToUrl('did:web:example.com:.')).toThrow(/invalid path segment/)
    expect(() => didToUrl('did:web:example.com:..')).toThrow(/invalid path segment/)
  })

  it('rejects percent-encoded traversal and separators', () => {
    expect(() => didToUrl('did:web:example.com:%2e%2e')).toThrow(/invalid path segment/)
    expect(() => didToUrl('did:web:example.com:%2E%2E')).toThrow(/invalid path segment/)
    expect(() => didToUrl('did:web:example.com:a%2fb')).toThrow(/invalid path segment/)
    expect(() => didToUrl('did:web:example.com:a%5Cb')).toThrow(/invalid path segment/)
  })

  it('rejects double encoding that URL normalisation would decode again', () => {
    expect(() => didToUrl('did:web:example.com:%252e%252e')).toThrow(/double-encoded/)
  })

  it('rejects malformed percent-encoding', () => {
    expect(() => didToUrl('did:web:example.com:%')).toThrow(/bad percent-encoding/)
  })

  it('rejects a host with characters outside the host charset', () => {
    expect(() => didToUrl('did:web:exam!ple.com')).toThrow(/invalid host/)
  })
})

// ANP-2026-09-11-01: a path-type DID commits to its key in the last segment. The
// resolved key must reproduce that fingerprint, so a DID document cannot bind an
// attacker's key to a victim's DID.
describe('resolveVerificationKey — path-type DID fingerprint binding (ANP-2026-09-11-01)', () => {
  it('accepts a document whose key matches the DID fingerprint', async () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) }),
    }
    // An e1_ document's proof is mandatory (ANP-03 §2.5.5), so a resolvable one
    // carries it — and the proof itself is bound to the same fingerprint.
    doc.proof = signDidDocumentProofSync(doc, keyid, priv)
    const { curve, bytes } = await resolveVerificationKey(keyid, doc)
    expect(curve).toBe('ed25519')
    expect(bytes).toEqual(pub)
  })

  it('rejects a self-signed document that binds a different key to the DID', async () => {
    // The impersonation PoC: attacker signs with their own key while claiming the
    // victim's DID, by inlining a document whose method carries the attacker's key.
    // The document is internally consistent — the identifier binding is what
    // rejects it, because the proof is signed by a key the DID does not commit to.
    const victimPriv = ed25519.utils.randomSecretKey()
    const victimPub = ed25519.getPublicKey(victimPriv)
    const attackerPriv = ed25519.utils.randomSecretKey()
    const attackerPub = ed25519.getPublicKey(attackerPriv)
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', victimPub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(attackerPub) }),
    }
    doc.proof = signDidDocumentProofSync(doc, keyid, attackerPriv)
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/proof .* is invalid/)
  })

  it('rejects an e1_ document with no proof at all', async () => {
    const pub = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc = buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) })
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/no proof, which this profile requires/)
  })

  it('rejects a key that does not reproduce a path-type fingerprint (no proof in play)', async () => {
    // A k1_ DID: its proof is optional and its cryptosuite is one the SDK does not
    // implement, so the fingerprint binding is the check that has to hold.
    const good = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
    const bad = new Uint8Array(Array.from({ length: 32 }, (_, i) => 200 - i))
    const { secp256k1 } = await import('@noble/curves/secp256k1.js')
    const did = `did:wba:example.com:user:alice:${didFingerprint('secp256k1', secp256k1.getPublicKey(good, true))}`
    const keyid = `${did}#key-1`
    const doc = k1Doc(did, keyid, encodeMultibaseSecp256k1(secp256k1.getPublicKey(bad, true)))
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/fingerprint/)
  })

  it('rejects a key that is not listed in the authentication relationship', async () => {
    // ANP-02 §3.2.1 step 5: naming a key in `verificationMethod` (or in
    // `assertionMethod`) does not make it a login key. A document that withholds
    // the key from `authentication` must not authenticate a request.
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) }),
    }
    // Empty `authentication` BEFORE signing, so the proof covers the document as
    // it stands and the only thing wrong with it is the withheld authorization.
    doc.authentication = []
    doc.proof = signDidDocumentProofSync(doc, keyid, priv)
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/not listed in the document's authentication/)
  })

  it('treats compressed and uncompressed secp256k1 keys as the same k1_ fingerprint', async () => {
    const { secp256k1 } = await import('@noble/curves/secp256k1.js')
    const priv = new Uint8Array(Array.from({ length: 32 }, () => 0x11))
    const compressed = secp256k1.getPublicKey(priv, true) // 33 bytes
    const uncompressed = secp256k1.getPublicKey(priv, false) // 65 bytes
    const fingerprint = didFingerprint('secp256k1', compressed)
    // SEC1 encoding is normalised to uncompressed before hashing, so a DID that
    // commits to either form accepts the other.
    expect(didFingerprint('secp256k1', uncompressed)).toBe(fingerprint)

    const did = `did:wba:example.com:user:alice:${fingerprint}`
    const keyid = `${did}#key-1`
    const doc = k1Doc(did, keyid, encodeMultibaseSecp256k1(compressed))
    const { curve } = await resolveVerificationKey(keyid, doc)
    expect(curve).toBe('secp256k1')
  })
})

describe('resolveVerificationKey', () => {
  const edPub = new Uint8Array(Array.from({ length: 32 }, (_, i) => i))
  const multibase = encodeMultibaseEd25519(edPub)
  const did = 'did:web:example.com'
  const keyid = `${did}#key-1`

  // URL-safe base64 (base64url), no padding — the alphabet a DID document JWK uses.
  function base64url(bytes: Uint8Array): string {
    return Buffer.from(bytes)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')
  }

  function doc(vm: Record<string, unknown>): unknown {
    // A resolvable document lists the key in `authentication` — anything else is
    // rejected by `resolveVerificationKey` (ANP-02 §3.2.1 step 5).
    return {
      id: did,
      verificationMethod: [{ id: keyid, type: 'Multikey', ...vm }],
      authentication: [keyid],
    }
  }

  it('resolves an Ed25519 publicKeyJwk whose x field is url-safe base64 without padding', async () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: base64url(edPub) }
    const { curve, bytes } = await resolveVerificationKey(keyid, doc({ publicKeyJwk: jwk }))
    expect(curve).toBe('ed25519')
    expect(bytes).toEqual(edPub)
  })

  it('throws on an Ed25519 publicKeyJwk whose x field is not 32 bytes', async () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: base64url(new Uint8Array(64)) }
    await expect(resolveVerificationKey(keyid, doc({ publicKeyJwk: jwk }))).rejects.toThrow(
      /Invalid Ed25519 JWK public key length/,
    )
  })

  it('resolves a key from an inline document by publicKeyMultibase', async () => {
    const { curve, bytes } = await resolveVerificationKey(keyid, doc({ publicKeyMultibase: multibase }))
    expect(curve).toBe('ed25519')
    expect(bytes).toEqual(edPub)
  })

  it('matches a verification method by fragment suffix', async () => {
    const { curve } = await resolveVerificationKey(`${did}#key-1`, doc({ publicKeyMultibase: multibase }))
    expect(curve).toBe('ed25519')
  })

  it('resolves an OKP Ed25519 publicKeyJwk', async () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64(edPub) }
    const { curve, bytes } = await resolveVerificationKey(keyid, doc({ publicKeyJwk: jwk }))
    expect(curve).toBe('ed25519')
    expect(bytes).toEqual(edPub)
  })

  it('resolves an EC secp256k1 publicKeyJwk into a compressed point', async () => {
    const priv = new Uint8Array(Array.from({ length: 32 }, () => 0x22))
    const { secp256k1 } = await import('@noble/curves/secp256k1.js')
    const pub = secp256k1.getPublicKey(priv, false) // 65-byte uncompressed
    const x = pub.slice(1, 33)
    const y = pub.slice(33, 65)
    const prefix = (y[31] & 0x01) === 1 ? 0x03 : 0x02
    const jwk = { kty: 'EC', crv: 'secp256k1', x: bytesToBase64(x), y: bytesToBase64(y) }
    const { curve, bytes } = await resolveVerificationKey(keyid, doc({ publicKeyJwk: jwk }))
    expect(curve).toBe('secp256k1')
    expect(bytes.length).toBe(33)
    expect(bytes[0]).toBe(prefix)
    expect(bytes.slice(1)).toEqual(x)
  })

  it('throws when no verification method matches the keyid', async () => {
    await expect(
      resolveVerificationKey(`${did}#nope`, doc({ publicKeyMultibase: multibase })),
    ).rejects.toThrow(/No verification method/)
  })

  it('throws when the verification method has no usable public key', async () => {
    await expect(resolveVerificationKey(keyid, doc({}))).rejects.toThrow(/no usable public key/)
  })
})

describe('pinnedFetch — connection pinned to the validated address (3.1)', () => {
  // Prove the anti-rebinding fix: `pinnedFetch` connects to the address it was
  // GIVEN, not to a fresh system DNS resolution of the hostname. The hostname
  // `edge.test` is not routed; only successfully connecting to the pinned
  // 127.0.0.1 (which serves our local socket) can make this test pass.
  it('connects to the pinned address and preserves the virtual Host header', async () => {
    let seenHost = ''
    const server = createServer((req, res) => {
      seenHost = req.headers.host ?? ''
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ id: 'did:web:edge.test' }))
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    const port = (server.address() as AddressInfo).port
    try {
      const res = await pinnedFetch(`http://edge.test:${port}/.well-known/did.json`, { method: 'GET' }, '127.0.0.1')
      const body = (await res.json()) as { id: string }
      expect(body.id).toBe('did:web:edge.test')
      // Host header stays the virtual host even though the socket went to 127.0.0.1.
      expect(seenHost).toBe(`edge.test:${port}`)
    } finally {
      await new Promise<void>((r) => server.close(() => r()))
    }
  })

  it('surfaces a network failure when the pinned address is unreachable', async () => {
    // A valid but closed port → the request must reject rather than hang or resolve.
    await expect(
      pinnedFetch('http://edge.test:9/.well-known/did.json', { method: 'GET' }, '127.0.0.1'),
    ).rejects.toBeTruthy()
  }, 5000)
})

// A host whose name answers for both address families is the ordinary case, and the two
// answers are usually two different sockets. `localhost` on macOS resolves to `::1`
// first, so a server bound to IPv4 alone would be refused by a name that is in fact
// reachable. What has to move on is a FAILED connect, and only that.
describe('address fallback — every validated address is tried (3.1)', () => {
  async function loopbackServer(
    address: string,
    handler: (req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void,
  ): Promise<{ port: number; close: () => Promise<void> }> {
    const server = createServer(handler)
    await new Promise<void>((r) => server.listen(0, address, r))
    return {
      port: (server.address() as AddressInfo).port,
      close: () => new Promise<void>((r) => server.close(() => r())),
    }
  }

  it('reaches the second address when the first refuses the connection', async () => {
    // The host is a NAME, not an IP literal: pinning is about replacing the name's
    // resolution (Node connects straight to a literal and consults no lookup), so this
    // is the shape the pin exists for — and the shape `localhost` has in the wild.
    let did = ''
    const server = await loopbackServer('127.0.0.1', (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ id: did }))
    })
    did = `did:web:edge.test%3A${server.port}`
    try {
      const entry = await resolveDidDocument(did, {
        allowedHosts: ['edge.test'],
        allowPrivateHosts: ['edge.test'],
        allowInsecureTransport: ['edge.test'],
        // `::1` is loopback too and nothing listens there, so the IPv6 attempt is
        // refused and the IPv4 one answers.
        resolveAddresses: async () => ['::1', '127.0.0.1'],
      })
      expect(entry.source).toBe('network')
      expect(entry.document.id).toBe(did)
    } finally {
      await server.close()
    }
  }, 5000)

  it('does not fall through when the address answered with an HTTP error', async () => {
    // A status is that server answering. Retrying a 404 against the next address would
    // turn one host's answer into a request to a different server, which is the SSRF
    // window the pinning exists to close — so the second address must never be reached.
    let secondHits = 0
    const first = await loopbackServer('127.0.0.1', (_req, res) => {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end('{"error":"not_found"}')
    })
    // The same port, the other family: a fall-through would land here and succeed.
    const secondFamily = createServer((_req, res) => {
      secondHits += 1
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ id: `did:web:edge.test%3A${first.port}` }))
    })
    try {
      await new Promise<void>((r) => secondFamily.listen(first.port, '::1', r))
      await expect(
        resolveDidDocument(`did:web:edge.test%3A${first.port}`, {
          allowedHosts: ['edge.test'],
          allowPrivateHosts: ['edge.test'],
          allowInsecureTransport: ['edge.test'],
          resolveAddresses: async () => ['127.0.0.1', '::1'],
        }),
      ).rejects.toMatchObject({ code: 'did_resolve_failed', status: 404 })
      expect(secondHits).toBe(0)
    } finally {
      await first.close()
      await new Promise<void>((r) => secondFamily.close(() => r()))
    }
  }, 5000)
})

describe('resolveVerificationKey — remote fetch constraints (3.1)', () => {
  const edPub = new Uint8Array(Array.from({ length: 32 }, (_, i) => i))
  const multibase = encodeMultibaseEd25519(edPub)
  const keyid = 'did:web:example.com#key-1'
  const doc = {
    id: 'did:web:example.com',
    verificationMethod: [{ id: keyid, type: 'Multikey', publicKeyMultibase: multibase }],
    authentication: [keyid],
  }

  function okFetch() {
    return async () => new Response(JSON.stringify(doc), { status: 200, headers: { 'content-type': 'application/json' } })
  }
  // Keep tests offline and deterministic: resolve the allowlisted host to a public
  // address instead of doing a real DNS lookup.
  const publicResolve = async () => ['93.184.216.34']

  it('rejects remote resolution without a non-empty allowedHosts allowlist', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, { allowUncontrolledFetch: true, fetch: okFetch() }),
    ).rejects.toThrow(/allowlist|allowedHosts/)
  })

  it('rejects a host that is not in the allowedHosts list', async () => {
    await expect(
      resolveVerificationKey('did:web:evil.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/not in the allowed hosts list/)
  })

  it('rejects a host whose resolved address is loopback (DNS rebinding)', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['127.0.0.1'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it('rejects an allowlisted host that resolves to an RFC1918 address', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['10.0.0.5'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it('rejects an IPv4-mapped IPv6 loopback address', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['::ffff:127.0.0.1'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it.each([
    '::ffff:7f00:1', // IPv4-mapped 127.0.0.1 written in hexadecimal
    '0:0:0:0:0:0:0:1', // expanded IPv6 loopback
    '::ffff:a00:1', // IPv4-mapped 10.0.0.1 written in hexadecimal
  ])('rejects an equivalent private IPv6 representation (%s)', async (address) => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => [address],
        allowUncontrolledFetch: true,
        fetch: okFetch(),
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it('accepts an allowlisted host that resolves to a public address', async () => {
    const { curve } = await resolveVerificationKey('did:web:example.com#key-1', undefined, {
      allowedHosts: ['example.com'],
      resolveAddresses: publicResolve,
      allowUncontrolledFetch: true, fetch: okFetch(),
    })
    expect(curve).toBe('ed25519')
  })

  it('accepts a loopback address when that host is named in allowPrivateHosts', async () => {
    const { curve } = await resolveVerificationKey('did:web:example.com#key-1', undefined, {
      allowedHosts: ['example.com'],
      allowPrivateHosts: ['example.com'],
      resolveAddresses: async () => ['127.0.0.1'],
      allowUncontrolledFetch: true, fetch: okFetch(),
    })
    expect(curve).toBe('ed25519')
  })

  it('matches allowPrivateHosts case-insensitively', async () => {
    const { curve } = await resolveVerificationKey('did:web:example.com#key-1', undefined, {
      allowedHosts: ['example.com'],
      allowPrivateHosts: ['Example.COM'],
      resolveAddresses: async () => ['10.0.0.5'],
      allowUncontrolledFetch: true, fetch: okFetch(),
    })
    expect(curve).toBe('ed25519')
  })

  it('exempts only the host it names — a sibling host stays blocked', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        allowPrivateHosts: ['other.test'],
        resolveAddresses: async () => ['127.0.0.1'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/private|loopback/)
  })

  it('does not let allowPrivateHosts widen the allowlist', async () => {
    // A private exemption is a second gate, never a substitute for `allowedHosts`.
    await expect(
      resolveVerificationKey('did:web:evil.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        allowPrivateHosts: ['evil.com'],
        resolveAddresses: async () => ['127.0.0.1'],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/not in the allowed hosts list/)
  })

  // Every refusal below shares the coarse `did_resolve_blocked` code, so the gate that
  // refused is reported separately — a caller that can name a remedy needs to know WHICH
  // option lifts the refusal, and the message is not a contract to parse.
  describe('blockedReason — which gate refused', () => {
    it('names the allowlist when the host did not match it', async () => {
      await expect(
        resolveVerificationKey('did:web:evil.com#key-1', undefined, {
          allowedHosts: ['example.com'],
          allowUncontrolledFetch: true, fetch: okFetch(),
        }),
      ).rejects.toMatchObject({ code: 'did_resolve_blocked', blockedReason: 'host_not_allowlisted' })
    })

    it('names the private-address gate, for a host that DID match the allowlist', async () => {
      await expect(
        resolveVerificationKey('did:web:example.com#key-1', undefined, {
          allowedHosts: ['example.com'],
          resolveAddresses: async () => ['::1'],
          allowUncontrolledFetch: true, fetch: okFetch(),
        }),
      ).rejects.toMatchObject({ code: 'did_resolve_blocked', blockedReason: 'private_address' })
    })

    it('names the transport gate for a plain-http URL', async () => {
      await expect(
        fetchControlledJson('http://example.com/.well-known/did.json', {
          allowedHosts: ['example.com'],
          resolveAddresses: publicResolve,
          allowUncontrolledFetch: true, fetch: okFetch(),
        }, DID_DOCUMENT_FETCH_CODES),
      ).rejects.toMatchObject({ code: 'did_resolve_blocked', blockedReason: 'insecure_transport' })
    })

    it('reports no liftable gate when the host could not be cleared', async () => {
      // Nothing the caller can name turns this into a fetch, so nothing may suggest a
      // flag — `unmatched` is the honest answer.
      await expect(
        resolveVerificationKey('did:web:example.com#key-1', undefined, {
          allowedHosts: ['example.com'],
          resolveAddresses: async () => [],
          allowUncontrolledFetch: true, fetch: okFetch(),
        }),
      ).rejects.toMatchObject({ code: 'did_resolve_blocked', blockedReason: 'unmatched' })
    })
  })

  it('rejects a document larger than maxBytes', async () => {
    const big = new Response('x'.repeat(2000), { status: 200, headers: { 'content-type': 'application/json' } })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: publicResolve,
        maxBytes: 100,
        allowUncontrolledFetch: true, fetch: async () => big,
      }),
    ).rejects.toThrow(/too large|exceeds/)
  })

  it('aborts a fetch that exceeds the timeout', async () => {
    const never = (_u: string, init: RequestInit) =>
      new Promise<Response>((_, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')))
      })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: publicResolve,
        timeoutMs: 30,
        allowUncontrolledFetch: true, fetch: never,
      }),
    ).rejects.toThrow(/aborted/i)
  }, 5000)

  it('rejects a 3xx response by default (redirects not followed)', async () => {
    const redirect = async () => new Response('', { status: 302, headers: { location: 'https://example.com/did.json' } })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: publicResolve,
        allowUncontrolledFetch: true, fetch: redirect,
      }),
    ).rejects.toThrow(/Failed to fetch DID document/)
  })

  it('re-checks a redirect target host against the allowlist', async () => {
    const redirect = async () =>
      new Response('', { status: 302, headers: { location: 'https://evil.com/did.json' } })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        allowRedirects: true,
        resolveAddresses: publicResolve,
        allowUncontrolledFetch: true, fetch: redirect,
      }),
    ).rejects.toThrow(/not in the allowed hosts list/)
  })

  it('re-checks a redirect target address for private space', async () => {
    const redirect = async () =>
      new Response('', { status: 302, headers: { location: 'https://internal.example.com/did.json' } })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com', 'internal.example.com'],
        allowRedirects: true,
        resolveAddresses: async (host) =>
          host === 'internal.example.com' ? ['10.0.0.1'] : ['93.184.216.34'],
        allowUncontrolledFetch: true, fetch: redirect,
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it('re-checks EVERY hop in a redirect chain, not just the final host', async () => {
    // example.com (allowed, public) → internal.example.com (allowed name, private IP)
    // → would bounce back to example.com. The middle private hop must be rejected even
    // though the final target is allowlisted + public — a `redirect: 'follow'` would
    // have silently traversed it (SSRF).
    const fetch = async (url: string) => {
      if (url.includes('internal.example.com')) {
        return new Response('', { status: 302, headers: { location: 'https://example.com/did.json' } })
      }
      return new Response('', { status: 302, headers: { location: 'https://internal.example.com/did.json' } })
    }
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com', 'internal.example.com'],
        allowRedirects: true,
        resolveAddresses: async (host) =>
          host === 'internal.example.com' ? ['10.0.0.1'] : ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch,
      }),
    ).rejects.toThrow(/private|loopback|resolves/)
  })

  it('fails after too many redirect hops', async () => {
    const loop = async () =>
      new Response('', { status: 302, headers: { location: 'https://example.com/did.json' } })
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        allowRedirects: true,
        maxRedirects: 2,
        resolveAddresses: publicResolve,
        allowUncontrolledFetch: true, fetch: loop,
      }),
    ).rejects.toThrow(/Too many redirects/)
  })

  it('fails closed when a host resolves to no address', async () => {
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => [],
        allowUncontrolledFetch: true, fetch: okFetch(),
      }),
    ).rejects.toThrow(/did not resolve to any address/)
  })

  it('rejects a custom fetch() unless allowUncontrolledFetch is explicit (fail-closed)', async () => {
    // A caller-injected fetcher bypasses the SDK's pinned connect, so it must not be
    // silently accepted. Without the opt-in flag, remote resolution is refused even
    // though the fetch itself would succeed — an uncontrolled network side-channel
    // cannot replace the pinned default in a secure path.
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: publicResolve,
        fetch: okFetch(),
      }),
    ).rejects.toThrow(/allowUncontrolledFetch/)
  })

  it('uses a caller fetch() when allowUncontrolledFetch is explicit', async () => {
    const { curve } = await resolveVerificationKey('did:web:example.com#key-1', undefined, {
      allowedHosts: ['example.com'],
      resolveAddresses: publicResolve,
      allowUncontrolledFetch: true,
      fetch: okFetch(),
    })
    expect(curve).toBe('ed25519')
  })

  it('fails closed on a no-resolver (browser) environment that cannot pin the connection', async () => {
    // A resolver returning null means "no address information available", i.e. the
    // browser case where the SDK cannot pin DNS. Remote resolution must be refused:
    // the hostname allowlist alone is NOT an SSRF guarantee.
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => null,
      }),
    ).rejects.toThrow(/resolver|pin/i)
  })
})

describe('resolveVerificationKey — identity binding (3.2)', () => {
  const edPub = new Uint8Array(Array.from({ length: 32 }, (_, i) => i))
  const multibase = encodeMultibaseEd25519(edPub)
  const did = 'did:web:example.com'
  const keyid = `${did}#key-1`

  it('rejects a document whose id does not match the requested DID', async () => {
    const other = {
      id: 'did:web:evil.com',
      verificationMethod: [
        { id: 'did:web:evil.com#key-1', type: 'Multikey', publicKeyMultibase: multibase },
      ],
    }
    await expect(resolveVerificationKey(keyid, other)).rejects.toThrow(/does not match/)
  })

  it('rejects a verification method controlled by a different DID', async () => {
    const doc = {
      id: did,
      verificationMethod: [
        { id: keyid, type: 'Multikey', controller: 'did:web:evil.com', publicKeyMultibase: multibase },
      ],
    }
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/No verification method/)
  })

  it('rejects a method whose id is a different DID with the same fragment', async () => {
    // id.endsWith('#key-1') would accept this; the strict match must not.
    const doc = {
      id: did,
      verificationMethod: [
        { id: 'did:web:evil.com#key-1', type: 'Multikey', publicKeyMultibase: multibase },
      ],
    }
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(/No verification method/)
  })

  it('accepts a relative fragment id (#key-1) with a matching controller', async () => {
    const doc = {
      id: did,
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', controller: did, publicKeyMultibase: multibase },
      ],
      // A relative reference in `authentication` is the same DID-spec form.
      authentication: ['#key-1'],
    }
    const { curve } = await resolveVerificationKey(keyid, doc)
    expect(curve).toBe('ed25519')
  })

  it('accepts an embedded verification method object in authentication', async () => {
    // DID Core lets `authentication` hold the method object itself instead of a
    // reference; the pair must still be recognized as the same key.
    const doc = {
      id: did,
      verificationMethod: [{ id: keyid, type: 'Multikey', publicKeyMultibase: multibase }],
      authentication: [{ id: keyid, type: 'Multikey', publicKeyMultibase: multibase }],
    }
    const { curve } = await resolveVerificationKey(keyid, doc)
    expect(curve).toBe('ed25519')
  })

  it('rejects a document that lists the key only under assertionMethod', async () => {
    // Present in the document, controlled by the right DID, but not authorized to
    // authenticate: a proof key is not a login key.
    const doc = {
      id: did,
      verificationMethod: [{ id: keyid, type: 'Multikey', publicKeyMultibase: multibase }],
      assertionMethod: [keyid],
    }
    await expect(resolveVerificationKey(keyid, doc)).rejects.toThrow(
      /not listed in the document's authentication/,
    )
  })
})

// Part R (0.3.x): the document, not just the key. `resolveVerificationKey` used to
// throw the parsed document away after extracting one key from it; these cover the
// document-level entry points that keep it, plus the store and the wire checks.
describe('verifyDidDocument — document-level integrity (R2)', () => {
  function wbaFixture() {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) }),
    }
    doc.proof = signDidDocumentProofSync(doc, keyid, priv)
    return { did, keyid, doc }
  }

  it('accepts a document that matches the DID and carries a valid proof', () => {
    const { did, doc } = wbaFixture()
    expect(() => verifyDidDocument(doc, did)).not.toThrow()
  })

  it('rejects a document whose id is a different DID', () => {
    const { doc } = wbaFixture()
    expect(() => verifyDidDocument(doc, 'did:wba:example.com:user:bob:e1_other')).toThrow(/does not match/)
  })

  it('rejects an e1_ document with no proof at all', () => {
    const { did, doc } = wbaFixture()
    delete doc.proof
    expect(() => verifyDidDocument(doc, did)).toThrow(/no proof, which this profile requires/)
  })

  it('rejects a document whose proof has been tampered with', () => {
    const { did, doc } = wbaFixture()
    const proof = doc.proof as Record<string, unknown>
    // Swap in a different verification method WITHOUT re-signing: the payload the
    // signature covers no longer matches the document.
    doc.verificationMethod = [
      { ...(doc.verificationMethod as Record<string, unknown>[])[0]!, publicKeyMultibase: encodeMultibaseEd25519(new Uint8Array(32).fill(7)) },
    ]
    expect(proof.proofValue).toBeTruthy()
    expect(() => verifyDidDocument(doc, did)).toThrow(/proof .* is invalid/)
  })

  it('needs no proof for a native did:web document (ANP-02 Appendix B)', () => {
    expect(() => verifyDidDocument({ id: 'did:web:example.com' }, 'did:web:example.com')).not.toThrow()
  })
})

// A DEACTIVATED `e1_` document is a transition record, not a credential, and §2.5.5
// treats it as the opposite case from an active one: its proof MAY be absent (both the
// old private key and a pre-authorized recovery key can be gone), and when present it
// may be a RECOVERY proof — which is deliberately not fingerprinted to the DID path.
// Demanding the binding proof here would reject every legitimate transition.
describe('verifyDidDocument — the deactivated transition document (ANP-03 §2.5.5)', () => {
  const successor = 'did:wba:example.com:user:alice:e1_successor'

  function deactivated() {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = `did:wba:example.com:user:alice:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) }),
      deactivated: true,
      successorDid: successor,
    }
    return { did, keyid, doc, priv }
  }

  it('accepts a deactivated document with no proof at all', () => {
    const { did, doc } = deactivated()
    expect(() => verifyDidDocument(doc, did)).not.toThrow()
  })

  it('accepts a deactivated document whose proof the binding key made', () => {
    const { did, keyid, doc, priv } = deactivated()
    doc.proof = signDidDocumentProofSync(doc, keyid, priv)
    expect(() => verifyDidDocument(doc, did)).not.toThrow()
  })

  it('rejects a deactivated document whose proof does not verify', () => {
    const { did, doc } = deactivated()
    const other = ed25519.utils.randomSecretKey()
    ;(doc.verificationMethod as unknown[]).push({
      id: `${did}#key-2`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: encodeMultibaseEd25519(ed25519.getPublicKey(other)),
    })
    // Signed by a method the document DOES describe, but with some other private key:
    // the proof is well-formed and its key is present, and it does not hold. §2.5.5
    // forbids downgrading this to a provider assertion or an unverified hint.
    doc.proof = signDidDocumentProofSync(doc, `${did}#key-2`, ed25519.utils.randomSecretKey())
    expect(() => verifyDidDocument(doc, did)).toThrow(/proof .* is invalid/)
  })

  it('rejects a deactivated document whose proof is structurally malformed', () => {
    const { did, keyid, doc, priv } = deactivated()
    doc.proof = { ...signDidDocumentProofSync(doc, keyid, priv), cryptosuite: 'eddsa-rdfc-2022' }
    expect(() => verifyDidDocument(doc, did)).toThrow(/malformed/)
  })

  it('defers to the chain layer a proof whose key it cannot see', () => {
    // The recovery case (§2.5.5 rule 2): the proof names a key this transition document
    // does not describe, because the key material and its `assertionMethod`
    // authorization live in the PRE-deactivation document. This layer cannot judge it
    // and must not guess — `resolveDidChain` holds the trusted document, and fails
    // closed when neither authorized form holds.
    const { did, doc } = deactivated()
    const proof = signDidDocumentProofSync(doc, `${did}#recovery-1`, ed25519.utils.randomSecretKey())
    expect(() => verifyDidDocument({ ...doc, proof }, did)).not.toThrow()
  })
})

describe('resolveDidDocument — document entry point + store (R2)', () => {
  const publicResolve = async () => ['93.184.216.34']
  const did = 'did:web:example.com'
  const keyid = `${did}#key-1`

  function doc() {
    return {
      id: did,
      verificationMethod: [{ id: keyid, type: 'Multikey', publicKeyMultibase: encodeMultibaseEd25519(new Uint8Array(Array.from({ length: 32 }, (_, i) => i))) }],
      authentication: [keyid],
    }
  }

  // A fetch that counts its calls and records the Accept header it was sent.
  //
  // The body is BYTES, not a string: `new Response('...')` makes undici synthesize a
  // `content-type: text/plain` header, which would make the "no Content-Type" case
  // untestable.
  function countingFetch(overrides: { contentType?: string | null; body?: unknown; onCall?: (n: number) => Response } = {}) {
    const state = { calls: 0, accept: [] as (string | null)[] }
    const fetch = async (_url: string, init: RequestInit) => {
      state.calls += 1
      state.accept.push(new Headers(init.headers).get('accept'))
      if (overrides.onCall) return overrides.onCall(state.calls)
      const headers = new Headers()
      if (overrides.contentType !== null) headers.set('content-type', overrides.contentType ?? 'application/json')
      const body = new TextEncoder().encode(JSON.stringify(overrides.body ?? doc()))
      return new Response(body, { status: 200, headers })
    }
    return { fetch, state }
  }

  const net = (fetch: (url: string, init: RequestInit) => Promise<Response>) => ({
    allowedHosts: ['example.com'],
    resolveAddresses: publicResolve,
    allowUncontrolledFetch: true,
    fetch,
  })

  it('returns the parsed document alongside where it came from', async () => {
    const { fetch } = countingFetch()
    const resolved = await resolveDidDocument(did, net(fetch))
    expect(resolved.did).toBe(did)
    expect(resolved.docUrl).toBe('https://example.com/.well-known/did.json')
    expect(resolved.source).toBe('network')
    expect(resolved.fetchedAt).toBeGreaterThan(0)
    expect((resolved.document as { id?: string }).id).toBe(did)
  })

  it('asks for a DID document rather than anything the server has', async () => {
    const { fetch, state } = countingFetch()
    await resolveDidDocument(did, net(fetch))
    expect(state.accept[0]).toContain('application/did+json')
  })

  it('rejects an HTML response (a soft 404 must not become a document)', async () => {
    const { fetch } = countingFetch({ contentType: 'text/html; charset=utf-8' })
    await expect(resolveDidDocument(did, net(fetch))).rejects.toThrow(/unsupported Content-Type "text\/html"/)
  })

  it('tolerates an absent Content-Type, leaving the JSON parse as the guard', async () => {
    const { fetch } = countingFetch({ contentType: null })
    const resolved = await resolveDidDocument(did, net(fetch))
    expect(resolved.source).toBe('network')
  })

  it('verifies the document before returning it', async () => {
    // The document-level check runs on the network path too, not only in
    // resolveVerificationKey — otherwise a caller using this entry point directly
    // would hold an unverified document.
    const { fetch } = countingFetch({ body: { ...doc(), id: 'did:web:evil.com' } })
    await expect(resolveDidDocument(did, net(fetch))).rejects.toThrow(/does not match/)
  })

  it('issues no second request while a stored document is fresh', async () => {
    const store = createDidDocumentStore()
    const { fetch, state } = countingFetch()
    const options = { ...net(fetch), documentStore: store }

    const first = await resolveDidDocument(did, options)
    const second = await resolveDidDocument(did, options)

    expect(state.calls).toBe(1)
    expect(first.source).toBe('network')
    expect(second.source).toBe('store')
    // The hit keeps the ORIGINAL fetch time, so a caller can judge staleness.
    expect(second.fetchedAt).toBe(first.fetchedAt)
    expect(second.document).toEqual(first.document)
  })

  it('re-fetches once a stored document is past its TTL', async () => {
    const store = createDidDocumentStore()
    const { fetch, state } = countingFetch()
    const options = { ...net(fetch), documentStore: store, cacheTtlMs: -1 }

    await resolveDidDocument(did, options)
    await resolveDidDocument(did, options)
    expect(state.calls).toBe(2)
  })

  it('does not cache by default', async () => {
    const { fetch, state } = countingFetch()
    await resolveDidDocument(did, net(fetch))
    await resolveDidDocument(did, net(fetch))
    expect(state.calls).toBe(2)
  })

  it('never stores a deactivated document', async () => {
    const store = createDidDocumentStore()
    const { fetch, state } = countingFetch({ body: { ...doc(), deactivated: true } })
    const options = { ...net(fetch), documentStore: store }

    await resolveDidDocument(did, options)
    expect(await store.get(did)).toBeUndefined()
    // ...and the next call therefore goes to the network again.
    await resolveDidDocument(did, options)
    expect(state.calls).toBe(2)
  })

  it('never stores a document that names a successor DID', async () => {
    const store = createDidDocumentStore()
    const { fetch } = countingFetch({ body: { ...doc(), successorDid: 'did:web:example.com:new' } })
    await resolveDidDocument(did, { ...net(fetch), documentStore: store })
    expect(await store.get(did)).toBeUndefined()
  })

  it('does not serve a stored document that has since become superseded', async () => {
    // The update hole: a copy fetched while the DID was live must not keep being
    // served after the DID has moved on — the TTL is about staleness, not identity.
    const store = createDidDocumentStore()
    const { fetch, state } = countingFetch()
    const options = { ...net(fetch), documentStore: store }
    await resolveDidDocument(did, options)

    await store.set({ ...(await store.get(did))!, document: { ...doc(), deactivated: true } })
    const again = await resolveDidDocument(did, options)

    expect(state.calls).toBe(2)
    expect(again.source).toBe('network')
  })

  it('shares the store with resolveVerificationKey', async () => {
    // Both entry points must go through the same fetch path, or a key resolution
    // would silently bypass a cache the caller configured.
    const store = createDidDocumentStore()
    const { fetch, state } = countingFetch()
    const options = { ...net(fetch), documentStore: store }

    await resolveDidDocument(did, options)
    await resolveVerificationKey(keyid, undefined, options)
    expect(state.calls).toBe(1)
  })

  it('works with a caller-supplied store, including its delete hook', async () => {
    const entries = new Map<string, unknown>()
    const deleted: string[] = []
    const store = {
      get: (k: string) => entries.get(k) as never,
      set: (entry: { did: string }) => {
        entries.set(entry.did, entry)
      },
      delete: (k: string) => {
        deleted.push(k)
        entries.delete(k)
      },
    }
    const { fetch, state } = countingFetch()
    const options = { ...net(fetch), documentStore: store }

    await resolveDidDocument(did, options)
    expect(entries.has(did)).toBe(true)
    expect(await store.delete(did)).toBeUndefined()
    expect(deleted).toEqual([did])

    await resolveDidDocument(did, options)
    expect(state.calls).toBe(2)
  })
})

// The segments before the `e1_` fingerprint are the subject: they are what survives a key
// update, so they are the form a caller holds when it means "whoever this is NOW" rather
// than "the holder of this key". It is not a DID of its own and cannot be resolved
// independently (§2.2.3 L53) — the document that answers is the full one — but the proof
// is then checked against THAT document's own `id`, which is the identity the subject
// names (§2.2.3 L183).
describe('resolveDidDocument — a stable subject path names a subject, not a key (ANP-03 §2.2.3)', () => {
  const subject = 'did:wba:example.com:user:alice'

  function fixture() {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const did = `${subject}:${didFingerprint('ed25519', pub)}`
    const keyid = `${did}#key-1`
    const doc: Record<string, unknown> = {
      ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(pub) }),
    }
    doc.proof = signDidDocumentProofSync(doc, keyid, priv)
    return { did, doc }
  }

  const serving = (body: unknown) => ({
    allowedHosts: ['example.com'],
    resolveAddresses: async () => ['93.184.216.34'],
    allowUncontrolledFetch: true,
    fetch: async () =>
      new Response(new TextEncoder().encode(JSON.stringify(body)), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  })

  it('answers a subject query with the full DID document and verifies its proof', async () => {
    const { did, doc } = fixture()
    const entry = await resolveDidDocument(subject, serving(doc))
    // The caller asked about a subject and gets the identity that subject currently is:
    // reporting back the string it typed would name nothing anyone can resolve.
    expect(entry.did).toBe(did)
    expect(entry.document.id).toBe(did)
    expect(entry.docUrl).toBe('https://example.com/user/alice/did.json')
  })

  it('does not answer a subject query with a DIFFERENT subject', async () => {
    const { doc } = fixture()
    await expect(resolveDidDocument('did:wba:example.com:user:bob', serving(doc))).rejects.toThrow(/does not match/)
  })

  it('does not widen a fingerprinted query to another key of the same subject', async () => {
    // An `e1_` DID is bound to one key (§2.2.1). Accepting the sibling key's document
    // here would let the fingerprint keep its appearance while naming someone else.
    const { doc } = fixture()
    await expect(
      resolveDidDocument('did:wba:example.com:user:alice:e1_someotherkey', serving(doc)),
    ).rejects.toThrow(/does not match/)
  })
})

// The two opt-outs exist so that a DID server you run YOURSELF (a local dev server,
// an http origin inside your own network) is reachable without the escape hatch whose
// stated semantics — "this caller has no DNS resolver" — would be a lie.
describe('resolveDidDocument — the per-host safety opt-outs (allowPrivateHosts / allowInsecureTransport)', () => {
  it('resolves from a loopback http server with no escape hatch at all', async () => {
    // The strongest form of this test: a real socket, the SDK's own pinned transport,
    // Node's real resolver. Nothing here is faked except the server being local.
    let did = ''
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ id: did }))
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    const port = (server.address() as AddressInfo).port
    did = `did:web:127.0.0.1%3A${port}`
    try {
      const entry = await resolveDidDocument(did, {
        allowedHosts: ['127.0.0.1'],
        allowPrivateHosts: ['127.0.0.1'],
        allowInsecureTransport: ['127.0.0.1'],
      })
      expect(entry.docUrl).toBe(`http://127.0.0.1:${port}/.well-known/did.json`)
      expect(entry.source).toBe('network')
      expect(entry.document.id).toBe(did)
    } finally {
      await new Promise<void>((r) => server.close(() => r()))
    }
  }, 5000)

  it('does not let allowInsecureTransport past the private-address gate', async () => {
    // The two opt-outs are independent: naming a host for the transport relaxation
    // never implies the address relaxation.
    await expect(
      resolveDidDocument('did:web:127.0.0.1%3A9', {
        allowedHosts: ['127.0.0.1'],
        allowInsecureTransport: ['127.0.0.1'],
      }),
    ).rejects.toThrow(/private|loopback/)
  })

  it('still fetches https for a host that is only in allowPrivateHosts', async () => {
    // private-address exemption ≠ transport downgrade. A plain-http server therefore
    // fails TLS, proving the URL stayed https.
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end('{"id":"x"}')
    })
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
    const port = (server.address() as AddressInfo).port
    try {
      await expect(
        resolveDidDocument(`did:web:127.0.0.1%3A${port}`, {
          allowedHosts: ['127.0.0.1'],
          allowPrivateHosts: ['127.0.0.1'],
        }),
      ).rejects.toMatchObject({ code: 'did_resolve_failed' })
    } finally {
      await new Promise<void>((r) => server.close(() => r()))
    }
  }, 5000)

  it('refuses a redirect that downgrades to http on a host not opted in', async () => {
    await expect(
      resolveDidDocument('did:web:example.com', {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowRedirects: true,
        allowUncontrolledFetch: true,
        fetch: async () => new Response(null, { status: 302, headers: { location: 'http://evil.test/did.json' } }),
      }),
    ).rejects.toThrow(/not https/)
  })
})
