// ANP-02 §4 (JSON 认证信息承载): the JSON envelope carries §3's proof fields, and
// `contentDigest` binds the PAYLOAD rather than the whole message. The sign/verify
// pair lives in two files (`jsonAuth.ts` / `verify.ts`), so these tests are the
// thing that holds them to the same rule for "which bytes get hashed".

import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createAnpIdentity } from './signer'
import { signAnpJsonAuthRequest } from './jsonAuth'
import {
  verifyAnpJsonAuthRequest,
  verifyAnpJsonAuthRequestDetailed,
  createNonceStore,
} from './verify'
import { buildContentDigestValue } from './signatureBase'
import { jcsCanonicalize } from './fingerprint'
import { utf8 } from './encoding'
import type { AnpSigningIdentity } from '../types'
import type { ResolvedKey } from './resolveDid'

const HOST = 'api.example.com'
const TARGET = `https://${HOST}/agent/invoke`
const NOW = () => Math.floor(Date.now() / 1000)

function keyOf(identity: AnpSigningIdentity): ResolvedKey {
  return { curve: 'ed25519', bytes: ed25519.getPublicKey(identity.priv) }
}

const identity = createAnpIdentity(HOST)
const key = keyOf(identity)

/** The §4.1.1 recommended format, over an HTTP-shaped target. */
const sign = (over: Partial<Parameters<typeof signAnpJsonAuthRequest>[0]> = {}) =>
  signAnpJsonAuthRequest({
    identity,
    nonce: 'n-1',
    method: 'POST',
    targetUri: TARGET,
    authority: HOST,
    payload: { orderId: '12345', action: 'create' },
    ...over,
  })

const verify = (envelope: unknown, over: Partial<Parameters<typeof verifyAnpJsonAuthRequest>[0]> = {}) =>
  verifyAnpJsonAuthRequest({ envelope, method: 'POST', targetUri: TARGET, authority: HOST, key, ...over })

const verifyDetailed = (
  envelope: unknown,
  over: Partial<Parameters<typeof verifyAnpJsonAuthRequest>[0]> = {},
) => verifyAnpJsonAuthRequestDetailed({ envelope, method: 'POST', targetUri: TARGET, authority: HOST, key, ...over })

describe('signAnpJsonAuthRequest / verifyAnpJsonAuthRequest', () => {
  it('round-trips the §4.1.1 format', async () => {
    const envelope = await sign()
    expect(Object.keys(envelope.auth).sort()).toEqual(['contentDigest', 'signature', 'signatureInput'])
    expect(envelope.payload).toEqual({ orderId: '12345', action: 'create' })
    // The three fields are the §3 values under §4's names, not HTTP header names.
    expect(envelope.auth.contentDigest).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/)
    expect(envelope.auth.signatureInput).toContain('("@method" "@target-uri" "@authority" "content-digest")')
    expect(envelope.auth.signature).toMatch(/^sig1=:[A-Za-z0-9+/=]+:$/)
    await expect(verify(envelope)).resolves.toBe(true)
  })

  it('binds the payload, NOT the envelope that carries `auth`', async () => {
    const envelope = await sign()
    // §4.1.1: "`contentDigest` 绑定的是 payload 部分，而不是包含 `auth` 在内的整个封装
    // 对象" — so the digest over the serialized wrapper must be a DIFFERENT string.
    // If these ever collapse, the profile has silently become a second §3.
    const overWrapper = await buildContentDigestValue(utf8(JSON.stringify(envelope)))
    expect(envelope.auth.contentDigest).not.toBe(overWrapper)

    // The observable consequence: re-serializing the envelope (any key order, any
    // JSON serializer's whitespace) must not disturb verification, because `auth`
    // is outer metadata that never enters the digest.
    const reserialized = JSON.parse(JSON.stringify({ auth: envelope.auth, payload: envelope.payload })) as {
      auth: Record<string, string>
      payload: unknown
    }
    const reordered = {
      auth: { signature: reserialized.auth.signature, contentDigest: reserialized.auth.contentDigest, signatureInput: reserialized.auth.signatureInput },
      payload: reserialized.payload,
    }
    await expect(verify(reordered)).resolves.toBe(true)
  })

  it('canonicalizes the payload with JCS, so key order is not a wire concern', async () => {
    // §4.1.1 recommends RFC 8785 for object payloads. Two peers that agree on the
    // rule agree on the digest no matter how each one's JSON happened to order keys.
    const envelope = await sign({ payload: { orderId: '12345', action: 'create' } })
    expect(jcsCanonicalize({ orderId: '12345', action: 'create' })).toBe('{"action":"create","orderId":"12345"}')
    await expect(
      verify({ auth: envelope.auth, payload: { action: 'create', orderId: '12345' } }),
    ).resolves.toBe(true)
  })

  it('treats a null payload as present, and digests it as `null`', async () => {
    const envelope = await sign({ payload: null })
    await expect(verify(envelope)).resolves.toBe(true)
    // Omitting the field is a different statement from sending `null`: there would be
    // a covered `content-digest` binding nothing.
    await expect(verifyDetailed({ auth: envelope.auth })).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
  })

  it('rejects a mutated payload', async () => {
    const envelope = await sign()
    await expect(
      verifyDetailed({ auth: envelope.auth, payload: { orderId: '12345', action: 'delete' } }),
    ).resolves.toMatchObject({ ok: false, reason: 'content_digest_mismatch' })
  })

  it('rejects a proof signed over a different target or method', async () => {
    const envelope = await sign()
    // The variant is inside the covered set, so a mismatch shows up as a failed
    // signature rather than as one of the earlier structural checks.
    await expect(verifyDetailed(envelope, { method: 'GET' })).resolves.toMatchObject({
      ok: false,
      reason: 'signature_invalid',
    })
    await expect(
      verifyDetailed(envelope, { targetUri: `https://${HOST}/agent/other` }),
    ).resolves.toMatchObject({ ok: false, reason: 'signature_invalid' })
  })

  it('rejects a proof verified under the wrong key', async () => {
    const envelope = await sign()
    const other = keyOf(createAnpIdentity(HOST))
    await expect(verifyDetailed(envelope, { key: other })).resolves.toMatchObject({
      ok: false,
      reason: 'signature_invalid',
    })
  })
})

describe('§4 carries @authority only when the carrier can check it', () => {
  it('drops the component when there is no authority, and still verifies', async () => {
    const envelope = await sign({ authority: undefined, targetUri: 'wss://bus.example.com/inbox' })
    // §4.1.2 item 3 leaves the equivalent of `@method` / `@target-uri` to the carrying
    // protocol, so a `wss:` target is legitimate — and with no authority to name, the
    // component is simply absent rather than covered-but-uncheckable.
    expect(envelope.auth.signatureInput).toContain('("@method" "@target-uri" "content-digest")')
    await expect(
      verifyAnpJsonAuthRequest({
        envelope,
        method: 'POST',
        targetUri: 'wss://bus.example.com/inbox',
        key,
      }),
    ).resolves.toBe(true)
  })

  it('rejects a covered @authority the caller cannot corroborate', async () => {
    const envelope = await sign()
    await expect(
      verifyDetailed(envelope, { authority: undefined }),
    ).resolves.toMatchObject({ ok: false, reason: 'request_malformed' })
  })

  it('rejects an authority the caller supplies but the proof does not cover', async () => {
    const envelope = await sign({ authority: undefined, targetUri: 'wss://bus.example.com/inbox' })
    await expect(
      verifyDetailed(envelope, { targetUri: 'wss://bus.example.com/inbox' }),
    ).resolves.toMatchObject({ ok: false, reason: 'request_malformed' })
  })

  it('rejects an authority that disagrees with the target', async () => {
    const envelope = await sign()
    await expect(verifyDetailed(envelope, { authority: 'other.example.com' })).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
  })

  it('rejects a relative target URI', async () => {
    const envelope = await sign()
    await expect(verifyDetailed(envelope, { targetUri: '/agent/invoke' })).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
  })
})

describe('§4 freshness and replay', () => {
  it('rejects an expired proof', async () => {
    const envelope = await sign({ ttlSeconds: -10 })
    await expect(verifyDetailed(envelope)).resolves.toMatchObject({ ok: false, reason: 'timestamp_invalid' })
  })

  it('pins the issued challenge through the signature params alone', async () => {
    const envelope = await sign({ nonce: 'n-issued' })
    await expect(verify(envelope, { expectedNonce: 'n-issued' })).resolves.toBe(true)
    await expect(verifyDetailed(envelope, { expectedNonce: 'n-other' })).resolves.toMatchObject({
      ok: false,
      reason: 'nonce_mismatch',
    })
    // Deliberately NOT the HTTP path's rule: there, `expectedNonce` must also appear
    // in the body because the §3 login flow puts the challenge in the signed payload.
    // §4's payload is business data (§4.1.1's example carries no nonce), so demanding
    // one would reject conforming traffic. The params are signed, so the binding holds.
    expect((envelope.payload as Record<string, unknown>).nonce).toBeUndefined()
  })

  it('consumes the nonce once', async () => {
    const nonceStore = createNonceStore()
    const envelope = await sign({ nonce: 'n-once' })
    await expect(verify(envelope, { nonceStore })).resolves.toBe(true)
    await expect(verifyDetailed(envelope, { nonceStore })).resolves.toMatchObject({
      ok: false,
      reason: 'nonce_consumed',
    })
  })
})

describe('§4 envelope shape', () => {
  const cases: Record<string, unknown> = {
    'not an object': 'nope',
    'an array': [],
    'a missing auth block': { payload: { a: 1 } },
    'a non-object auth block': { auth: 'nope', payload: null },
    'a missing contentDigest': { auth: { signatureInput: 'sig1=()', signature: 'sig1=:x:' }, payload: null },
    'a missing signatureInput': { auth: { contentDigest: 'sha-256=:x:', signature: 'sig1=:x:' }, payload: null },
    'a missing signature': { auth: { contentDigest: 'sha-256=:x:', signatureInput: 'sig1=()' }, payload: null },
  }

  for (const [name, envelope] of Object.entries(cases)) {
    it(`rejects ${name}`, async () => {
      await expect(verifyDetailed(envelope)).resolves.toMatchObject({ ok: false, reason: 'request_malformed' })
    })
  }

  it('rejects a covered set below the §3 minimum', async () => {
    const envelope = await sign()
    // Hand-build the two structural failures the builder cannot produce: the spec's
    // covered-set floor is `@method` + `@target-uri` + the payload digest, and §4
    // does not lower it (§4.1.2 says the flow is §3.1.2's, only the carrier differs).
    const without = (component: string) => ({
      auth: {
        ...envelope.auth,
        // Trailing space optional: `content-digest` is the last component, so it has
        // none after it.
        signatureInput: envelope.auth.signatureInput.replace(new RegExp(`"${component}" ?`), ''),
      },
      payload: envelope.payload,
    })
    await expect(verifyDetailed(without('@method'))).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
    await expect(verifyDetailed(without('@target-uri'))).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
    await expect(verifyDetailed(without('content-digest'))).resolves.toMatchObject({
      ok: false,
      reason: 'request_malformed',
    })
  })

  it('rejects a payload the canonicalizer cannot express', async () => {
    const envelope = await sign()
    // Not reachable through `JSON.parse`, but a caller may hand-build the envelope.
    await expect(
      verifyDetailed({ auth: envelope.auth, payload: { fn: () => undefined } }),
    ).resolves.toMatchObject({ ok: false, reason: 'request_malformed' })
  })
})

describe('signAnpJsonAuthRequest input guards', () => {
  it('refuses to build a proof over an empty component', async () => {
    await expect(sign({ method: '' })).rejects.toMatchObject({ code: 'invalid_argument' })
    await expect(sign({ targetUri: '' })).rejects.toMatchObject({ code: 'invalid_argument' })
    // An empty authority is a claim with no content: omit it instead, which drops the
    // component from the covered set entirely.
    await expect(sign({ authority: '' })).rejects.toMatchObject({ code: 'invalid_argument' })
  })
})
