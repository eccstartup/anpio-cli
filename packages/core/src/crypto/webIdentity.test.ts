import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createWebIdentity } from './webIdentity'
import { createAnpIdentity, signAnpLoginRequest } from './signer'
import { didToUrl, resolveDidDocument, resolveVerificationKey } from './resolveDid'
import { verifyAnpLoginRequest, type VerifyAnpLoginInput } from './serverAuth'
import { createNonceStore } from './verify'
import { decodeMultibaseKey } from './multicodec'
import { handleService } from './wns'
import {
  ANP_COMPONENTS,
  buildContentDigestValue,
  buildSignatureBase,
  serializeSignatureParams,
  signatureBaseBytes,
} from './signatureBase'
import { bytesToBase64, utf8 } from './encoding'

const HOST = 'identity.example'
const DOC_URL = `https://${HOST}/.well-known/did.json`

const LOGIN_URL = `https://${HOST}/api/login/anp/verify`
const LOGIN_PATH = '/api/login/anp/verify'

// Deterministic and offline: nothing here opens a socket.
function opts(extra: Record<string, unknown> = {}) {
  return {
    allowedHosts: [HOST],
    resolveAddresses: async () => ['93.184.216.34'],
    allowUncontrolledFetch: true,
    ...extra,
  }
}

/** A stub that answers exactly `docUrl` with `doc`, and records every URL fetched. */
function servingDoc(doc: unknown, docUrl = DOC_URL) {
  const calls: string[] = []
  const fetch = async (url: string): Promise<Response> => {
    calls.push(url)
    if (url === docUrl) {
      return new Response(JSON.stringify(doc), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    return new Response('not found', { status: 404 })
  }
  return { fetch, calls }
}

/** Sign an arbitrary body with an arbitrary keyid — the shape a hostile client sends.
 *  The signature covers the exact body, so the content-digest stays valid; what the
 *  test varies is only which document (if any) the body claims. */
async function craftedLogin(input: { priv: Uint8Array; keyid: string; body: string; nonce: string }): Promise<VerifyAnpLoginInput> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-digest': await buildContentDigestValue(utf8(input.body)),
  }
  const now = Math.floor(Date.now() / 1000)
  const params = serializeSignatureParams(ANP_COMPONENTS, {
    created: now,
    expires: now + 300,
    nonce: input.nonce,
    keyid: input.keyid,
  })
  const base = buildSignatureBase({
    method: 'POST',
    path: LOGIN_PATH,
    authority: HOST,
    targetUri: LOGIN_URL,
    headers,
    components: ANP_COMPONENTS,
    signatureParams: params,
  })
  return {
    method: 'POST',
    authority: HOST,
    path: LOGIN_PATH,
    search: '',
    targetUri: LOGIN_URL,
    headers: {
      ...headers,
      'signature-input': `sig1=${params}`,
      signature: `sig1=:${bytesToBase64(ed25519.sign(signatureBaseBytes(base), input.priv))}:`,
    },
    body: input.body,
    expectedNonce: input.nonce,
    nonceStore: createNonceStore(),
  }
}

describe('createWebIdentity', () => {
  it('produces a did:web identity whose document matches the DID and the key', async () => {
    const identity = createWebIdentity(HOST)
    expect(identity.did).toBe(`did:web:${HOST}`)
    expect(identity.keyid).toBe(`did:web:${HOST}#key-1`)

    // A `did:web` identity is always Ed25519, so its one key representation is
    // `Multikey` + `publicKeyMultibase`.
    const { publicKeyMultibase } = identity.publicKey as { publicKeyMultibase: string }

    const doc = identity.didDocument as Record<string, unknown>
    expect(doc.id).toBe(identity.did)
    expect(doc.verificationMethod).toMatchObject([
      { id: identity.keyid, type: 'Multikey', controller: identity.did, publicKeyMultibase },
    ])
    // ANP-02 §3.1.1 L88: the chosen method MUST be authorized by `authentication`.
    expect(doc.authentication).toEqual([identity.keyid])
    expect(doc.assertionMethod).toEqual([identity.keyid])

    // The published key is the one the private key signs with — not merely a
    // well-formed multibase string.
    const { bytes } = decodeMultibaseKey(publicKeyMultibase)
    expect(bytes).toEqual(ed25519.getPublicKey(identity.priv))
  })

  it('carries NO proof — there is no fingerprint in the identifier to bind one to', () => {
    // Appendix B B.2 L478 lets an implementation verify a proof IF the document has
    // one, under that proof's own profile; producing none is the honest default,
    // because nothing in `did:web:identity.example` commits to a key.
    expect(createWebIdentity(HOST).didDocument).not.toHaveProperty('proof')
  })

  it('uses the same subject rule as `subjectOf`: a did:web DID is already stable', () => {
    const identity = createWebIdentity(HOST, { path: ['users', 'alice'] })
    expect(identity.did).toBe(`did:web:${HOST}:users:alice`)
    expect(identity.subject).toBe(identity.did)
  })

  it('publishes the services it is given, at the path the DID names', () => {
    const identity = createWebIdentity(HOST, {
      path: ['users', 'alice'],
      service: [handleService(`https://${HOST}/.well-known/handle/alice`)],
    })
    expect(didToUrl(identity.did)).toBe(`https://${HOST}/users/alice/did.json`)
    expect(identity.didDocument.service).toEqual([
      { id: expect.any(String), type: 'ANPHandleService', serviceEndpoint: `https://${HOST}/.well-known/handle/alice` },
    ])
  })

  it('round-trips through the resolver once the document is served at its DID URL', async () => {
    const identity = createWebIdentity(HOST)
    const { fetch, calls } = servingDoc(identity.didDocument)
    // `documentProof: 'strict'` is the sharp part: it demands a WBA proof of every
    // did:wba shape, and Appendix B B.1 L476 says a native did:web MUST NOT be held to
    // another method's document proof. So this must pass with no proof at all.
    const resolved = await resolveDidDocument(identity.did, opts({ fetch, documentProof: 'strict' }))
    expect(resolved.document).toEqual(identity.didDocument)
    expect(calls).toEqual([DOC_URL])

    // And the key resolves under the identifier's own `authentication` relationship.
    const key = await resolveVerificationKey(identity.keyid, resolved.document, opts({ fetch }))
    expect(key.curve).toBe('ed25519')
    expect(key.bytes).toEqual(ed25519.getPublicKey(identity.priv))
  })
})

describe('createWebIdentity — login', () => {
  it('does NOT inline the document in a login body, unlike a did:wba identity', async () => {
    const web = createWebIdentity(HOST)
    const wba = createAnpIdentity(HOST)

    const webBody = JSON.parse((await signAnpLoginRequest({ identity: web, nonce: 'n1', method: 'POST', url: LOGIN_URL })).body)
    const wbaBody = JSON.parse((await signAnpLoginRequest({ identity: wba, nonce: 'n1', method: 'POST', url: LOGIN_URL })).body)

    // A path-type did:wba commits to its key inside the identifier, so the copy can be
    // checked against the DID itself — that is the §3 fast path, and it stays.
    expect(wbaBody.didDocument).toEqual(wba.didDocument)
    // A did:web commits to nothing, so a copy could only ever be unauthenticated input:
    // Appendix B B.1 L470 makes resolving from the domain a MUST.
    expect(webBody).toEqual({ nonce: 'n1', did: web.did })
    expect(webBody).not.toHaveProperty('didDocument')
  })

  it('verifies a login end to end, with the document fetched from the DID domain', async () => {
    const identity = createWebIdentity(HOST)
    const { body, headers } = await signAnpLoginRequest({
      identity,
      nonce: 'n-challenge',
      method: 'POST',
      url: LOGIN_URL,
    })
    const { fetch } = servingDoc(identity.didDocument)
    const result = await verifyAnpLoginRequest({
      method: 'POST',
      authority: HOST,
      path: LOGIN_PATH,
      search: '',
      targetUri: LOGIN_URL,
      headers,
      body,
      expectedNonce: 'n-challenge',
      nonceStore: createNonceStore(),
      resolveOptions: opts({ fetch }),
    })
    expect(result).toEqual({
      ok: true,
      identity: { did: identity.did, keyid: identity.keyid, document: identity.didDocument },
    })
  })

  it('ignores an inlined document even when a client sends one — which is why we omit it', async () => {
    // The trap the omission avoids: a reader that took `body.didDocument` at face value
    // would verify against a document of the sender's choosing. Here the body inlines a
    // document with a DIFFERENT key; the login still succeeds, and the returned document
    // is the one served by the DID's own domain.
    const identity = createWebIdentity(HOST)
    const other = createWebIdentity(HOST)
    const nonce = 'n-inline'
    const body = JSON.stringify({ nonce, did: identity.did, didDocument: other.didDocument })
    const input = await craftedLogin({ priv: identity.priv, keyid: identity.keyid, body, nonce })

    const { fetch, calls } = servingDoc(identity.didDocument)
    const result = await verifyAnpLoginRequest({ ...input, resolveOptions: opts({ fetch }) })
    expect(calls).toEqual([DOC_URL])
    expect(result).toEqual({
      ok: true,
      identity: { did: identity.did, keyid: identity.keyid, document: identity.didDocument },
    })
    // The inlined key was never the one verified against: a proof made with `other`'s
    // private key would have to be verified against `other`'s document to succeed.
    expect(result.ok && result.identity.document).not.toEqual(other.didDocument)
  })

  it('rejects a login signed with a key the DID domain does not publish', async () => {
    const identity = createWebIdentity(HOST)
    const attacker = createWebIdentity(HOST)
    const nonce = 'n-attacker'
    const body = JSON.stringify({ nonce, did: identity.did })
    // Signed with the attacker's key but claiming — and keyed to — the victim's DID.
    const input = await craftedLogin({ priv: attacker.priv, keyid: identity.keyid, body, nonce })
    const { fetch } = servingDoc(identity.didDocument)
    expect(await verifyAnpLoginRequest({ ...input, resolveOptions: opts({ fetch }) })).toMatchObject({ ok: false })
  })
})
