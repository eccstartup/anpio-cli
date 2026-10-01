// @vitest-environment node
import { describe, it, expect, vi, afterEach } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createAnpIdentity } from './signer'
import { verifyHttpMessageSignature, verifyHttpMessageSignatureDetailed, createNonceStore } from './verify'
import type { NonceStore, VerifyFailure } from './verify'
import { resolveVerificationKey } from './resolveDid'
import {
  ANP_COMPONENTS,
  buildContentDigestValue,
  buildSignatureBase,
  serializeSignatureParams,
  signatureBaseBytes,
} from './signatureBase'
import { bytesToBase64, utf8 } from './encoding'
import type { ResolvedKey } from './resolveDid'

// Negative security tests: the verifier must REJECT malformed / tampered / stale
// signatures, not merely accept well-formed ones. We build a real ANP-02 proof
// (via the same primitives the signer uses) and then break one thing at a time.

const host = 'localhost:3000'
const url = `http://${host}/api/login/anp/verify`
const method = 'POST'

const identity = createAnpIdentity(host)
const keyPromise = resolveVerificationKey(identity.keyid, identity.didDocument)
const NOW = Math.floor(Date.now() / 1000)
// A fresh, in-window timestamp pair for tests that focus on components/tampering.
const FRESH = { created: NOW, expires: NOW + 300 }

// Sign a login request over an arbitrary component set + params, so we can probe
// the verifier's required-set and freshness gates independently of signature validity.
async function signCustom(
  key: ResolvedKey,
  opts: {
    components: string[]
    params: { created?: number; expires?: number; nonce?: string; keyid?: string }
    nonce?: string
    contentDigest?: string
    targetUri?: string
    /** Sign over this body instead of the default login payload. `''` signs a
     *  bodyless request, which is the only shape allowed to skip `content-digest`. */
    body?: string
  },
): Promise<{ body: string; headers: Record<string, string> }> {
  const nonce = opts.nonce ?? 'n1'
  const body = opts.body ?? JSON.stringify({ nonce, did: identity.did, didDocument: identity.didDocument })
  const params = {
    created: opts.params.created,
    expires: opts.params.expires,
    nonce,
    keyid: opts.params.keyid ?? identity.keyid,
  }
  const sigParams = serializeSignatureParams(opts.components, params)
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-digest': opts.contentDigest ?? (await buildContentDigestValue(utf8(body))),
  }
  const base = buildSignatureBase({
    method,
    path: new URL(url).pathname,
    authority: new URL(url).host,
    targetUri: opts.targetUri ?? url,
    headers,
    components: opts.components,
    signatureParams: sigParams,
  })
  const sig = bytesToBase64(ed25519.sign(signatureBaseBytes(base), identity.priv))
  return {
    body,
    headers: { ...headers, 'signature-input': `sig1=${sigParams}`, signature: `sig1=:${sig}:` },
  }
}

function verifyInput(
  key: ResolvedKey,
  proof: { body: string; headers: Record<string, string> },
  overrides: Partial<{
    method: string
    path: string
    authority: string
    targetUri: string
    search: string
    body: string
    mode: 'strict' | 'legacy'
    expectedNonce: string
    nonceStore: NonceStore
  }> = {},
) {
  return {
    method: overrides.method ?? method,
    path: overrides.path ?? new URL(url).pathname,
    authority: overrides.authority ?? new URL(url).host,
    targetUri: overrides.targetUri ?? url,
    headers: proof.headers,
    body: overrides.body ?? proof.body,
    key,
    ...(overrides.mode !== undefined ? { mode: overrides.mode } : {}),
    ...(overrides.search !== undefined ? { search: overrides.search } : {}),
    ...(overrides.expectedNonce !== undefined ? { expectedNonce: overrides.expectedNonce } : {}),
    ...(overrides.nonceStore !== undefined ? { nonceStore: overrides.nonceStore } : {}),
  }
}

// Sign the LEGACY browser-shim shape: it covered `@method @path @authority
// content-digest` and DID NOT append the `@signature-params` line to the signed
// base (only @target-uri clients do). The Signature-Input header still carries
// created/expires/nonce/keyid so freshness + keyid checks remain meaningful.
async function signLegacy(
  key: ResolvedKey,
): Promise<{ body: string; headers: Record<string, string> }> {
  const nonce = 'n1'
  const body = JSON.stringify({ nonce, did: identity.did, didDocument: identity.didDocument })
  const components = ['@method', '@path', '@authority', 'content-digest']
  const params = { created: FRESH.created, expires: FRESH.expires, nonce, keyid: identity.keyid }
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-digest': await buildContentDigestValue(utf8(body)),
  }
  const base = buildSignatureBase({
    method,
    path: new URL(url).pathname,
    authority: new URL(url).host,
    targetUri: url,
    headers,
    components,
  })
  const sig = bytesToBase64(ed25519.sign(signatureBaseBytes(base), identity.priv))
  const sigParams = serializeSignatureParams(components, params)
  return {
    body,
    headers: { ...headers, 'signature-input': `sig1=${sigParams}`, signature: `sig1=:${sig}:` },
  }
}

describe('verifyHttpMessageSignature — negative security', () => {
  it('accepts a well-formed ANP-02 proof', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(true)
  })

  describe('required covered components (3.1)', () => {
    it('rejects a proof that omits content-digest', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS.filter((c) => c !== 'content-digest'), params: FRESH })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('rejects a proof that omits @method', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS.filter((c) => c !== '@method'), params: FRESH })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('allows covering MORE than the minimum: @authority is recommended, not required', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS.filter((c) => c !== '@authority'), params: FRESH })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(true)
    })

    it('rejects a bodyless proof replayed with an attacker-chosen body', async () => {
      // The downgrade guard that actually matters. Omitting `content-digest` is only
      // acceptable because there is NO body to bind; the moment a body is attached,
      // the digest must be covered — otherwise a captured bodyless proof could be
      // replayed carrying whatever content the attacker likes.
      const key = await keyPromise
      const components = ANP_COMPONENTS.filter((c) => c !== 'content-digest')
      const proof = await signCustom(key, { components, params: FRESH, body: '' })
      // Legitimate as signed: the request has no body.
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, { body: '' }))).toBe(true)
      // Replayed with a body: rejected.
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, { body: '{"did":"did:web:evil"}' }))).toBe(false)
    })

    it('rejects a proof that covers neither @target-uri nor @path', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ['@method', '@authority', 'content-digest'],
        params: {},
      })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })
  })

  describe('freshness (3.2)', () => {
    const now = Math.floor(Date.now() / 1000)

    it('rejects a proof with no created', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: { expires: now + 300 } })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    // `expires` is a SHOULD in the ANP-02 §3.1.1 param table, so omitting it is legal:
    // such a proof is bounded by `created` alone (the created-age cap).
    it('accepts a proof with no expires', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: { created: now } })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(true)
    })

    it('still rejects a no-expires proof whose created is too old', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: { created: now - 7200 } })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('rejects a proof created in the future beyond the skew', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: { created: now + 3600, expires: now + 4000 },
      })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('rejects a proof created too far in the past', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: { created: now - 7200, expires: now + 300 },
      })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('rejects a proof with an unbounded TTL', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: { created: now, expires: now + 100_000 },
      })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('rejects an expired proof', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: { created: now - 100, expires: now - 50 },
      })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })
  })

  describe('tampering (2)', () => {
    it('rejects a proof whose body was swapped after signing', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const tampered =
        { body: JSON.stringify({ nonce: 'n1', did: identity.did, didDocument: identity.didDocument, attacker: true }) }
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, tampered))).toBe(false)
    })

    it('rejects a proof whose content-digest header was edited', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = { ...proof.headers, 'content-digest': 'sha-256=:AAAA:' }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })

    it('rejects a proof whose signature-input component set was edited', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = { ...proof.headers, 'signature-input': proof.headers['signature-input'].replace('@method', '@path') }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })

    it('rejects a proof whose keyid param was edited after signing', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = {
        ...proof.headers,
        'signature-input': proof.headers['signature-input'].replace(identity.keyid, `${identity.did}#other`),
      }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })

    it('rejects a proof signed for a different method', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, { method: 'PUT' }))).toBe(false)
    })
  })

  describe('nonce anti-replay (3.1)', () => {
    it('consumes a nonce via the store and rejects a replayed (second) submission', async () => {
      const key = await keyPromise
      const store = createNonceStore()
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      // First use: nonce matches the expected challenge and is consumed.
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { nonceStore: store, expectedNonce: 'n1' })),
      ).toBe(true)
      // Second use of the same nonce: already consumed, so it is rejected.
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { nonceStore: store, expectedNonce: 'n1' })),
      ).toBe(false)
    })

    it('rejects when the Signature-Input nonce differs from the expected challenge', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH }) // nonce 'n1'
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, { expectedNonce: 'n2' }))).toBe(false)
    })

    it('awaits an async store, so a shared/DB-backed nonce set can be used', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      // Stands in for a database row delete: every call is a pending promise, and
      // the first call is the winner. A sync-only interface could not express this
      // — the caller would have to pre-resolve, reintroducing the race the atomic
      // consume exists to close.
      const spent = new Set<string>()
      const store: NonceStore = {
        async consume(keyid, nonce) {
          await Promise.resolve()
          const pair = `${keyid} ${nonce}`
          if (spent.has(pair)) return false
          spent.add(pair)
          return true
        },
      }
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { nonceStore: store, expectedNonce: 'n1' })),
      ).toBe(true)
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { nonceStore: store, expectedNonce: 'n1' })),
      ).toBe(false)
      expect(spent.size).toBe(1)
    })

    it('fails closed when the store rejects (a broken store must not authenticate)', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const store: NonceStore = {
        consume: () => Promise.reject(new Error('store unavailable')),
      }
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { nonceStore: store, expectedNonce: 'n1' })),
      ).toBe(false)
    })
  })

  describe('strict vs legacy component mode (3.2)', () => {
    it('default (strict) rejects a signature that covers @path but not @target-uri', async () => {
      const key = await keyPromise
      const proof = await signLegacy(key)
      expect(await verifyHttpMessageSignature(verifyInput(key, proof))).toBe(false)
    })

    it('explicit legacy mode accepts the @path component set', async () => {
      const key = await keyPromise
      const proof = await signLegacy(key)
      expect(await verifyHttpMessageSignature(verifyInput(key, proof, { mode: 'legacy' }))).toBe(true)
    })
  })

  describe('strict targetUri binding (3.1)', () => {
    it('rejects a proof when targetUri is missing (cannot fall back to the path)', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const input = verifyInput(key, proof)
      const { targetUri: _omit, ...noTarget } = input
      expect(await verifyHttpMessageSignature(noTarget)).toBe(false)
    })

    it('rejects a relative targetUri (not an absolute URL)', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { targetUri: '/api/login/anp/verify' })),
      ).toBe(false)
    })

    it('rejects a targetUri whose authority does not match the request authority', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      expect(
        await verifyHttpMessageSignature(
          verifyInput(key, proof, { targetUri: 'https://evil.example/api/login/anp/verify' }),
        ),
      ).toBe(false)
    })

    it('rejects a targetUri whose path does not match the request path', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { targetUri: `${url}/other` })),
      ).toBe(false)
    })
  })

  describe('strict targetUri query binding (3.3)', () => {
    it('rejects when the targetUri query differs from the actual search', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: FRESH,
        targetUri: `${url}?tenant=alpha`,
      })
      expect(
        await verifyHttpMessageSignature(
          verifyInput(key, proof, { targetUri: `${url}?tenant=alpha`, search: '?tenant=beta' }),
        ),
      ).toBe(false)
    })

    it('rejects when the targetUri carries a query but no actual search is provided', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: FRESH,
        targetUri: `${url}?tenant=alpha`,
      })
      expect(
        await verifyHttpMessageSignature(verifyInput(key, proof, { targetUri: `${url}?tenant=alpha` })),
      ).toBe(false)
    })

    it('accepts when the targetUri query matches the actual search', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, {
        components: ANP_COMPONENTS,
        params: FRESH,
        targetUri: `${url}?tenant=alpha`,
      })
      expect(
        await verifyHttpMessageSignature(
          verifyInput(key, proof, { targetUri: `${url}?tenant=alpha`, search: '?tenant=alpha' }),
        ),
      ).toBe(true)
    })
  })

  describe('label correlation + param strictness (3.3 / 3.4)', () => {
    it('rejects when the Signature label differs from the Signature-Input label', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = { ...proof.headers, signature: proof.headers.signature.replace('sig1=', 'sig2=') }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })

    it('rejects a Signature-Input header with an unrecognized param', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = {
        ...proof.headers,
        'signature-input': `${proof.headers['signature-input']};foo=bar`,
      }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })

    it('rejects a Signature-Input header with a duplicate param', async () => {
      const key = await keyPromise
      const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
      const headers = {
        ...proof.headers,
        'signature-input': `${proof.headers['signature-input']};keyid="did:x#dup"`,
      }
      expect(await verifyHttpMessageSignature(verifyInput(key, { ...proof, headers }))).toBe(false)
    })
  })
})

describe('verifyHttpMessageSignatureDetailed — naming the failed check', () => {
  // The boolean form proves the verifier REJECTS. This block proves it can say WHY,
  // which is what lets a server answer with a usable ANP-02 error value instead of
  // one generic failure. Each case breaks exactly one thing in an otherwise valid proof.
  const reasonOf = async (
    input: Parameters<typeof verifyHttpMessageSignatureDetailed>[0],
  ): Promise<VerifyFailure | undefined> => {
    const outcome = await verifyHttpMessageSignatureDetailed(input)
    return outcome.ok ? undefined : outcome.reason
  }

  it('reports ok for a well-formed proof, and the boolean form agrees', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    const input = verifyInput(key, proof)
    expect(await verifyHttpMessageSignatureDetailed(input)).toEqual({ ok: true })
    expect(await verifyHttpMessageSignature(input)).toBe(true)
  })

  it('names a missing envelope as request_malformed', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    expect(await reasonOf(verifyInput(key, { ...proof, headers: {} }))).toBe('request_malformed')
  })

  it('names an unparsable Signature-Input as request_malformed, not a bad signature', async () => {
    // The parser throws; without its own frame that throw would land in the blanket
    // catch and be reported as `signature_invalid`, blaming the peer for our envelope.
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    expect(await reasonOf(verifyInput(key, { ...proof, headers: { 'signature-input': 'sig1=(%ZZ', signature: 'x' } }))).toBe(
      'request_malformed',
    )
  })

  it('names a covered set below the ANP-02 minimum as request_malformed', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, {
      components: ['@target-uri', 'content-digest'],
      params: FRESH,
    })
    expect(await reasonOf(verifyInput(key, proof))).toBe('request_malformed')
  })

  it('names a body that does not match its digest as content_digest_mismatch', async () => {
    // Sign over a DIFFERENT digest than the body hashes to: the covered set is fine
    // and the signature is genuine, so only the digest can explain the rejection.
    const key = await keyPromise
    const wrong = await buildContentDigestValue(utf8('{"other":true}'))
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH, contentDigest: wrong })
    expect(await reasonOf(verifyInput(key, proof))).toBe('content_digest_mismatch')
  })

  it('names a stale window as timestamp_invalid', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, {
      components: ANP_COMPONENTS,
      params: { created: NOW - 7200, expires: NOW - 3600 },
    })
    expect(await reasonOf(verifyInput(key, proof))).toBe('timestamp_invalid')
  })

  it('names a challenge the proof did not carry as nonce_mismatch', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    expect(await reasonOf(verifyInput(key, proof, { expectedNonce: 'a-different-challenge' }))).toBe(
      'nonce_mismatch',
    )
  })

  it('names a spent challenge as nonce_consumed', async () => {
    const key = await keyPromise
    const store = createNonceStore()
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    const input = verifyInput(key, proof, { expectedNonce: 'n1', nonceStore: store })
    expect(await reasonOf(input)).toBeUndefined() // first use spends the challenge
    expect(await reasonOf(input)).toBe('nonce_consumed')
  })

  it('names a mutilated signature as signature_invalid', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    const [, sigValue] = proof.headers.signature.split('=')
    const flipped = sigValue.startsWith(':A') ? `:B${sigValue.slice(2)}` : `:A${sigValue.slice(1)}`
    expect(await reasonOf(verifyInput(key, { ...proof, headers: { ...proof.headers, signature: `sig1=${flipped}` } }))).toBe(
      'signature_invalid',
    )
  })

  it('names a Signature label that disagrees with Signature-Input as signature_invalid', async () => {
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    const value = proof.headers.signature.slice('sig1='.length)
    expect(await reasonOf(verifyInput(key, { ...proof, headers: { ...proof.headers, signature: `sig2=${value}` } }))).toBe(
      'signature_invalid',
    )
  })

  it('names a throwing nonce store as store_failed, and keeps the cause for the log', async () => {
    // Our dependency is down. Calling that `signature_invalid` would tell the peer to
    // re-sign, which cannot help — the caller needs to be able to tell them apart.
    const key = await keyPromise
    const proof = await signCustom(key, { components: ANP_COMPONENTS, params: FRESH })
    const outcome = await verifyHttpMessageSignatureDetailed(
      verifyInput(key, proof, {
        expectedNonce: 'n1',
        nonceStore: {
          consume() {
            throw new Error('redis is unreachable')
          },
        },
      }),
    )
    expect(outcome.ok).toBe(false)
    expect(outcome.ok === false && outcome.reason).toBe('store_failed')
    expect(outcome.ok === false && outcome.cause).toBeInstanceOf(Error)
    // Fail-closed either way: the boolean form must not accept a proof it could not
    // finish checking.
    expect(await verifyHttpMessageSignature(verifyInput(key, proof, { expectedNonce: 'n1' }))).toBe(true)
  })

  it('never throws, whatever the input', async () => {
    const key = await keyPromise
    const hostile = {
      method,
      path: new URL(url).pathname,
      authority: new URL(url).host,
      targetUri: url,
      headers: { 'signature-input': 'sig1=(%ZZ', signature: 'not-a-signature' },
      body: '{}',
      key,
    }
    await expect(verifyHttpMessageSignatureDetailed(hostile)).resolves.toMatchObject({ ok: false })
  })
})

describe('createNonceStore — bounded + fail-closed (3.1 / 3.2)', () => {
  afterEach(() => vi.useRealTimers())

  // The store is keyed by the PAIR (keyid, nonce): a nonce is only unique per
  // signer, so keying on it alone would let one DID burn another's challenge.
  const didA = 'did:wba:example.com:user:a#key-1'
  const didB = 'did:wba:example.com:user:b#key-1'

  it('consumes each (keyid, nonce) pair once within its TTL', () => {
    const store = createNonceStore()
    expect(store.consume(didA, 'n1')).toBe(true)
    expect(store.consume(didA, 'n1')).toBe(false)
  })

  it('does not let one DID burn another DID challenge with the same nonce value', () => {
    const store = createNonceStore()
    expect(store.consume(didA, 'n1')).toBe(true)
    // A different signer reusing the same nonce string must still be admitted.
    expect(store.consume(didB, 'n1')).toBe(true)
    expect(store.consume(didA, 'n1')).toBe(false)
    expect(store.consume(didB, 'n1')).toBe(false)
  })

  it('forgets a pair once its TTL passes, so expired entries do not live forever', () => {
    vi.useFakeTimers()
    const store = createNonceStore({ ttlMs: 1000 })
    expect(store.consume(didA, 'n1')).toBe(true)
    expect(store.consume(didA, 'n1')).toBe(false)
    vi.advanceTimersByTime(1001)
    expect(store.consume(didA, 'n1')).toBe(true) // stale, so re-armed
  })

  it('is bounded to maxSize — fail-closed once full of live nonces', () => {
    const store = createNonceStore({ maxSize: 5 })
    for (const n of ['a', 'b', 'c', 'd', 'e']) expect(store.consume(didA, n)).toBe(true)
    // At capacity with live nonces: a new one is rejected and the older ones are
    // NOT evicted, so a replay of a still-valid signature stays blocked.
    expect(store.consume(didA, 'f')).toBe(false)
    expect(store.consume(didA, 'a')).toBe(false) // still remembered → anti-replay holds
  })

  it('reclaims space from expired nonces before failing closed', () => {
    vi.useFakeTimers()
    const store = createNonceStore({ maxSize: 2, ttlMs: 1000 })
    expect(store.consume(didA, 'a')).toBe(true)
    expect(store.consume(didA, 'b')).toBe(true)
    expect(store.consume(didA, 'c')).toBe(false) // full of live nonces → fail closed
    vi.advanceTimersByTime(1001)
    expect(store.consume(didA, 'c')).toBe(true) // 'a' and 'b' expired, so space is reclaimed
  })

  it('rejects NaN / Infinity / fractional / zero / negative options instead of disabling the bounds', () => {
    expect(() => createNonceStore({ maxSize: NaN })).toThrowError(/positive integer/)
    expect(() => createNonceStore({ ttlMs: NaN })).toThrowError(/positive integer/)
    expect(() => createNonceStore({ maxSize: Infinity })).toThrowError(/positive integer/)
    expect(() => createNonceStore({ maxSize: 0 })).toThrowError(/positive integer/)
    expect(() => createNonceStore({ maxSize: -1 })).toThrowError(/positive integer/)
    expect(() => createNonceStore({ ttlMs: 1.5 })).toThrowError(/positive integer/)
  })
})
