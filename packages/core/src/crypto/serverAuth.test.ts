import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import {
  keypairWallet,
  chainWalletConnector,
} from '../protocol/adapters/chain'
import { buildBaseDidDocument } from './didDocument'
import {
  verifyAnpLoginRequest,
  type VerifyAnpLoginInput,
  type AnpLoginResult,
  type AnpLoginFailure,
  type AnpLoginIdentity,
} from './serverAuth'
import { createAnpIdentity, signAnpLoginRequest } from './signer'
import { encodeMultibaseEd25519, encodeMultibaseSecp256k1 } from './multicodec'
import { createNonceStore } from './verify'
import { signDidDocumentProofSync } from './dataIntegrity'
import {
  ANP_COMPONENTS,
  buildSignatureBase,
  buildContentDigestValue,
  serializeSignatureParams,
  signatureBaseBytes,
} from './signatureBase'
import { bytesToBase64, utf8 } from './encoding'
import type { AnpSigningIdentity } from '../types'

// The failure branch is what a server branches on — it decides what to write into
// `WWW-Authenticate` — so the tests below assert the REASON, not merely that it failed.
function reasonOf(result: AnpLoginResult): AnpLoginFailure | undefined {
  return result.ok ? undefined : result.error
}

function identityOf(result: AnpLoginResult): AnpLoginIdentity | undefined {
  return result.ok ? result.identity : undefined
}

const LOGIN_URL = 'http://127.0.0.1:4101/api/login/anp/verify'
const LOGIN_PATH = '/api/login/anp/verify'
const LOGIN_AUTHORITY = '127.0.0.1:4101'

// Sign with the SDK's own client (the real login path) and shape the result like the
// arguments a server handler has in hand. The replay guard is part of the input:
// `verifyAnpLoginRequest` refuses to run without it.
async function signedRequest(
  identity: AnpSigningIdentity,
  nonce = '',
): Promise<VerifyAnpLoginInput> {
  const { body, headers } = await signAnpLoginRequest({ identity, nonce, method: 'POST', url: LOGIN_URL })
  return {
    method: 'POST',
    authority: LOGIN_AUTHORITY,
    path: LOGIN_PATH,
    search: '',
    targetUri: LOGIN_URL,
    headers,
    body,
    expectedNonce: nonce,
    nonceStore: createNonceStore(),
  }
}

// Craft a signed login request with an arbitrary keyid ↔ body.did combination, so we
// can prove the binding rejects proofs the low-level primitives would otherwise
// verify. Signature covers the exact body, so content-digest stays valid.
async function craftedRequest(input: {
  priv: Uint8Array
  keyid: string
  body: string
  nonce?: string
  /** Override the signature's validity window (defaults to now … now + 300s), so a
   *  test can present a proof that is stale or absurdly long-lived. */
  window?: { created: number; expires: number }
}): Promise<VerifyAnpLoginInput> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-digest': await buildContentDigestValue(utf8(input.body)),
  }
  const now = Math.floor(Date.now() / 1000)
  const params = serializeSignatureParams(ANP_COMPONENTS, {
    created: input.window?.created ?? now,
    expires: input.window?.expires ?? now + 300,
    nonce: input.nonce ?? '',
    keyid: input.keyid,
  })
  const base = buildSignatureBase({
    method: 'POST',
    path: LOGIN_PATH,
    authority: LOGIN_AUTHORITY,
    targetUri: LOGIN_URL,
    headers,
    components: ANP_COMPONENTS,
    signatureParams: params,
  })
  headers['signature-input'] = `sig1=${params}`
  headers['signature'] = `sig1=:${bytesToBase64(ed25519.sign(signatureBaseBytes(base), input.priv))}:`
  return {
    method: 'POST',
    authority: LOGIN_AUTHORITY,
    path: LOGIN_PATH,
    search: '',
    targetUri: LOGIN_URL,
    headers,
    body: input.body,
    expectedNonce: input.nonce ?? '',
    nonceStore: createNonceStore(),
  }
}

// A bare `did:wba:<host>` identity: no key fingerprint in the identifier, so an
// inline document is unauthenticated and must not be trusted (see serverAuth.ts).
function bareWbaIdentity() {
  const priv = ed25519.utils.randomSecretKey()
  const pub = ed25519.getPublicKey(priv)
  const did = 'did:wba:example.com'
  const keyid = `${did}#key-1`
  const publicKeyMultibase = encodeMultibaseEd25519(pub)
  const didDocument = {
    id: did,
    verificationMethod: [{ id: keyid, type: 'Multikey', publicKeyMultibase }],
    authentication: [keyid],
  }
  return { priv, pub, did, keyid, publicKeyMultibase, didDocument }
}

describe('verifyAnpLoginRequest', () => {
  it('verifies a well-formed login and returns the bound DID', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const result = await verifyAnpLoginRequest(await signedRequest(identity))
    // The returned document is the one the key was verified against — for a
    // fingerprint-bound `did:wba` path DID that is the request's own inline copy.
    expect(result).toEqual({
      ok: true,
      identity: { did: identity.did, keyid: identity.keyid, document: identity.didDocument },
    })
  })

  it('does not verify twice with the same proof (no stateless fallback)', async () => {
    // Uses only the helper's own guard parameters — the default call path — so this
    // is the shape an integration gets if it does not think about replay at all.
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity, 'challenge-1')
    expect(identityOf(await verifyAnpLoginRequest(input))?.did).toBe(identity.did)
    // The second call is refused because the challenge is SPENT, which is a different
    // answer from "this proof never matched" — the server may say so either way, but
    // it must at least be able to tell its own log apart.
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('invalid_nonce')
  })

  it('rejects a call that omits the challenge nonce, even via a type bypass', async () => {
    // ANP-2026-09-11-R01: a JS caller can strip a field the types require.
    const identity = createAnpIdentity('127.0.0.1')
    const base = await signedRequest(identity, 'challenge-1')
    const stateless = { ...base, expectedNonce: undefined } as unknown as VerifyAnpLoginInput
    await expect(verifyAnpLoginRequest(stateless)).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('rejects a call that omits the nonce store, even via a type bypass', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const base = await signedRequest(identity, 'challenge-1')
    const unguarded = { ...base, nonceStore: undefined } as unknown as VerifyAnpLoginInput
    await expect(verifyAnpLoginRequest(unguarded)).rejects.toThrowError(/nonceStore/)
  })

  it('binds the proof to the issued nonce and consumes it exactly once', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity, 'challenge-1')
    const nonceStore = createNonceStore()

    expect(await verifyAnpLoginRequest({ ...input, expectedNonce: 'challenge-1', nonceStore })).toEqual({
      ok: true,
      identity: { did: identity.did, keyid: identity.keyid, document: identity.didDocument },
    })
    // Replay of the very same proof is refused — the challenge is spent.
    expect(reasonOf(await verifyAnpLoginRequest({ ...input, expectedNonce: 'challenge-1', nonceStore }))).toBe(
      'invalid_nonce',
    )
    // A different expected nonce does not match what the client signed.
    expect(reasonOf(await verifyAnpLoginRequest({ ...input, expectedNonce: 'other' }))).toBe('invalid_nonce')
  })

  it('rejects a forged document that binds the attacker key to the victim DID', async () => {
    // The ANP-2026-09-11-01 PoC: sign with the attacker's key while claiming the
    // victim's fingerprint-bound DID, by inlining a document whose method carries the
    // attacker's key. The keyid/body.did all agree on the victim DID — only the
    // recomputed fingerprint exposes the swap, so the whole request must be refused.
    const victim = createAnpIdentity('example.com')
    const attacker = createAnpIdentity('example.com')
    const forgedDocument = {
      ...victim.didDocument,
      verificationMethod: [
        {
          id: `${victim.did}#key-1`,
          type: 'Multikey',
          publicKeyMultibase: (attacker.publicKey as { publicKeyMultibase: string }).publicKeyMultibase,
        },
      ],
    }
    const forged: AnpSigningIdentity = {
      ...attacker,
      did: victim.did,
      keyid: `${victim.did}#key-1`,
      didDocument: forgedDocument,
    }
    expect(reasonOf(await verifyAnpLoginRequest(await signedRequest(forged)))).toBe('invalid_verification_method')
  })

  it('rejects a valid signature whose body claims a different DID than the keyid', async () => {
    const attacker = createAnpIdentity('example.com')
    const victim = createAnpIdentity('example.com')
    const body = JSON.stringify({
      nonce: '',
      did: victim.did, // body claims the victim…
      didDocument: attacker.didDocument, // …with the attacker's own (valid) document
    })
    const input = await craftedRequest({ priv: attacker.priv, keyid: attacker.keyid, body })
    // The signature is fine and the document is fine — it is the CLAIMED identity that
    // disagrees with the signer, so the DID is what is wrong.
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('invalid_did')
  })

  it('does not trust an inline document for a bare (non-fingerprint) did:wba DID', async () => {
    const identity = bareWbaIdentity()
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    // No allowedHosts ⇒ no network resolution ⇒ the self-asserted inline document is
    // not enough on its own. Reported as unverifiable, NOT as a bad DID: nothing about
    // the peer's proof was shown to be wrong — we simply may not look.
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('unverifiable')
  })

  it('verifies a bare did:wba DID only through allowlisted network resolution', async () => {
    const identity = bareWbaIdentity()
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () =>
          new Response(JSON.stringify(identity.didDocument), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      },
    })
    expect(identityOf(result)).toMatchObject({ did: identity.did })
  })

  it('returns the RESOLVED document, never the request’s inline copy, when the inline copy is untrusted', async () => {
    // A site that keeps the document for later use — locating the agent's `ad.json`,
    // say — must keep the one the key was ACTUALLY verified against. Here the request
    // inlines a document naming a service endpoint the DID's own server does not
    // publish; a site that stored `body.didDocument` would then go and fetch from an
    // endpoint the caller chose, which is the SSRF this option exists to prevent.
    const identity = bareWbaIdentity()
    const served = {
      ...identity.didDocument,
      service: [{ id: '#ad', type: 'AgentDescription', serviceEndpoint: 'https://example.com/ad.json' }],
    }
    const body = JSON.stringify({
      nonce: '',
      did: identity.did,
      didDocument: {
        ...identity.didDocument,
        service: [{ id: '#ad', type: 'AgentDescription', serviceEndpoint: 'https://evil.example/ad.json' }],
      },
    })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () =>
          new Response(JSON.stringify(served), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      },
    })
    expect(identityOf(result)?.document).toEqual(served)
  })

  it('requireResolvedDocument prefers the DID server’s copy over a trusted inline one', async () => {
    // Default: for a fingerprint-bound `did:wba` path DID the inline copy IS the
    // document the key was verified against, so that is what comes back. With the
    // option on, the answer comes from the DID's own host instead — a strictly
    // stronger statement, and the only one that can see what the server publishes.
    //
    // Both documents here are legitimately signed by the SAME key; they differ in what
    // they publish. That is the realistic shape of the attack the option closes: the
    // request is internally consistent, and still not what the DID server says.
    const identity = createAnpIdentity('example.com')
    const served: Record<string, unknown> = {
      ...identity.didDocument,
      service: [{ id: '#ad', type: 'AgentDescription', serviceEndpoint: 'https://example.com/ad.json' }],
    }
    served.proof = signDidDocumentProofSync(served, identity.keyid, identity.priv)

    const input = await signedRequest(identity)
    expect(identityOf(await verifyAnpLoginRequest(input))?.document).toEqual(identity.didDocument)

    const result = await verifyAnpLoginRequest({
      ...input,
      requireResolvedDocument: true,
      nonceStore: createNonceStore(),
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () =>
          new Response(JSON.stringify(served), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      },
    })
    expect(identityOf(result)?.document).toEqual(served)
  })

  it('refuses a deactivated DID even when the request’s proof is entirely genuine', async () => {
    // ANP-03 §3.1.2: a document that sets `deactivated = true` MUST NOT be used for
    // new authentication. Everything else here is sound on purpose — the identifier
    // commits to the key, the key signs this body, the nonce is the server's own
    // challenge. What is wrong is a state of the IDENTITY, not of the proof, so no
    // amount of signature verification can find it.
    const identity = createAnpIdentity('example.com')
    const successor = createAnpIdentity('example.com')
    // A transition document's proof is re-signed over the deactivation markers, the
    // way a DID server publishes one; the document proof is checked during resolution,
    // so a stale copy left as-was would be refused before this rule could apply.
    const deactivated: Record<string, unknown> = {
      ...identity.didDocument,
      deactivated: true,
      successorDid: successor.did,
    }
    deactivated.proof = signDidDocumentProofSync(deactivated, identity.keyid, identity.priv)
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: deactivated })

    const result = await verifyAnpLoginRequest(
      await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body }),
    )
    expect(reasonOf(result)).toBe('did_deactivated')
    // §3.2 carries the successor in the 409 body as an UNVERIFIED hint the client must
    // re-derive, so the verifier echoes it and claims nothing more by doing so.
    expect(result.ok === false ? result.successorDid : undefined).toBe(successor.did)
  })

  it('refuses a DID server’s successorDid document that is not flagged deactivated', async () => {
    // The second of the two continuity markers, and on the other code path: a bare
    // `did:wba` DID has no fingerprint, so its document must come from its own host.
    // ANP-03 §3.1.2 treats a document naming `successorDid` as superseded on its own —
    // a server that forgot to also set `deactivated` does not thereby stay current.
    const identity = bareWbaIdentity()
    const served = { ...identity.didDocument, successorDid: 'did:wba:example.com:e1_Next' }
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () =>
          new Response(JSON.stringify(served), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      },
    })
    expect(reasonOf(result)).toBe('did_deactivated')
    expect(result.ok === false ? result.successorDid : undefined).toBe('did:wba:example.com:e1_Next')
  })

  it('refuses a resolved document that does not list the key for authentication', async () => {    // ANP-02 §3.2.1 step 5. The document is fetched from the allowlisted host (so it
    // is not self-asserted), it names the right key and the right DID — but the key
    // is not in `authentication`, so it may not authenticate a login.
    const identity = bareWbaIdentity()
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () =>
          new Response(JSON.stringify({ ...identity.didDocument, authentication: [] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      },
    })
    expect(reasonOf(result)).toBe('invalid_verification_method')
  })

  it('ignores an inline document that is not a plain object', async () => {
    const identity = createAnpIdentity('example.com')
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: [identity.didDocument] })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('unverifiable')
  })

  // A DID server answering 404 is a DECISION about the DID, not a failure to reach one:
  // it publishes no document for that identifier. Reported as a bad verification method,
  // so a caller that acts on the answer — enrolment writes a durable membership — does
  // not tell the agent to retry something that can only succeed if the DID is published.
  it('reports a 404 for the DID document as an unusable verification method', async () => {
    const identity = bareWbaIdentity()
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () => new Response('{"error":"not_found"}', { status: 404 }),
      },
    })
    expect(reasonOf(result)).toBe('invalid_verification_method')
  })

  // The other side of the same line: a 5xx is the DID server unable to answer, which is
  // OUR inability to look (and retryable), never a bad key.
  it('reports a 5xx for the DID document as unverifiable', async () => {
    const identity = bareWbaIdentity()
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    const result = await verifyAnpLoginRequest({
      ...input,
      resolveOptions: {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () => new Response('upstream down', { status: 503 }),
      },
    })
    expect(reasonOf(result)).toBe('unverifiable')
  })

  it('rejects a document whose id does not match the keyid DID', async () => {
    const identity = createAnpIdentity('example.com')
    const body = JSON.stringify({
      nonce: '',
      did: identity.did,
      didDocument: { ...identity.didDocument, id: 'did:wba:evil.com' },
    })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('invalid_verification_method')
  })

  it('rejects a document whose verification method id is a different DID', async () => {
    const identity = createAnpIdentity('example.com')
    const body = JSON.stringify({
      nonce: '',
      did: identity.did,
      didDocument: {
        ...identity.didDocument,
        verificationMethod: [
          { ...(identity.didDocument.verificationMethod as object[])[0], id: 'did:wba:evil.com#key-1' },
        ],
      },
    })
    const input = await craftedRequest({ priv: identity.priv, keyid: identity.keyid, body })
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('invalid_verification_method')
  })

  it('rejects a tampered body (content-digest no longer matches)', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity)
    const tampered = { ...input, body: input.body.replace('"nonce":""', '"nonce":"x"') }
    // The digest is checked before the signature, so the reason names the digest — the
    // peer's body is what changed, and that is what it should be told.
    expect(reasonOf(await verifyAnpLoginRequest(tampered))).toBe('invalid_content_digest')
  })

  it('rejects a request with no Signature-Input header', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity)
    const headers = { ...input.headers }
    delete headers['signature-input']
    expect(reasonOf(await verifyAnpLoginRequest({ ...input, headers }))).toBe('invalid_request')
  })

  it('never throws — a hostile header value is a rejected login, not an exception', async () => {
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity)
    const result = await verifyAnpLoginRequest({
      ...input,
      headers: { ...input.headers, 'signature-input': 'sig1=(%ZZ' },
    })
    // An unparsable envelope, not "we could not check": the parser rejected it outright.
    expect(reasonOf(result)).toBe('invalid_request')
  })

  it('reports a stale proof as an invalid timestamp, not a bad signature', async () => {
    // This is the distinction the old `null` made unreachable: the signature is
    // perfectly valid, it is the CLOCK that is wrong, and a peer can fix that (re-sign)
    // in a way it cannot fix "your signature is bad".
    const identity = createAnpIdentity('example.com')
    const body = JSON.stringify({ nonce: '', did: identity.did, didDocument: identity.didDocument })
    const now = Math.floor(Date.now() / 1000)
    const input = await craftedRequest({
      priv: identity.priv,
      keyid: identity.keyid,
      body,
      window: { created: now - 7200, expires: now - 3600 },
    })
    expect(reasonOf(await verifyAnpLoginRequest(input))).toBe('invalid_timestamp')
  })

  it('reports a rejecting nonce store as unverifiable, not as a bad proof', async () => {
    // A nonce store that THROWS is our own outage (a database that is down). Calling
    // that `invalid_signature` would tell the peer to re-sign — advice that cannot
    // help, and which hides the real fault from the operator.
    const identity = createAnpIdentity('127.0.0.1')
    const input = await signedRequest(identity, 'challenge-1')
    const result = await verifyAnpLoginRequest({
      ...input,
      nonceStore: {
        consume() {
          throw new Error('postgres is down')
        },
      },
    })
    expect(reasonOf(result)).toBe('unverifiable')
    // The cause is kept for the server's own log — it names our dependency.
    expect(result.ok === false && result.cause).toBeInstanceOf(Error)
  })
})

// A CAIP-10 account id (`eip155:1:0x…`) carries NO fingerprint in its text, so the
// only thing that can make its inline document trustworthy is the address being
// DERIVED from the key the document names (serverAuth.ts `assertAccountBinding`).
// These cases pin both halves of that: a document agreeing with the account id is
// accepted, one naming any other key is refused — the account-id twin of the
// forged-fingerprint PoC above.
describe('CAIP-10 account ids', () => {
  const PRIV = new Uint8Array(Array.from({ length: 32 }, () => 0x22))
  const ADDRESS = '0x1563915e194d8cfba1943570603f7606a3115508'
  const CHAIN_ID = 'eip155:1'
  const ACCOUNT_DID = `${CHAIN_ID}:${ADDRESS}`

  // Sign the ANP base with a wallet key, the way `cryptoWalletProver` does (raw
  // secp256k1 over the canonical base), so the negative cases differ from a valid
  // request in exactly ONE way: which key the inlined document names.
  async function accountRequest(input: {
    priv: Uint8Array
    didDocument: Record<string, unknown>
    nonce?: string
  }): Promise<VerifyAnpLoginInput> {
    const nonce = input.nonce ?? ''
    const body = JSON.stringify({ nonce, did: ACCOUNT_DID, didDocument: input.didDocument })
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'content-digest': await buildContentDigestValue(utf8(body)),
    }
    const now = Math.floor(Date.now() / 1000)
    const params = serializeSignatureParams(ANP_COMPONENTS, {
      created: now,
      expires: now + 300,
      nonce,
      keyid: `${ACCOUNT_DID}#key-1`,
    })
    const base = buildSignatureBase({
      method: 'POST',
      path: LOGIN_PATH,
      authority: LOGIN_AUTHORITY,
      targetUri: LOGIN_URL,
      headers,
      components: ANP_COMPONENTS,
      signatureParams: params,
    })
    headers['signature-input'] = `sig1=${params}`
    headers['signature'] = `sig1=:${bytesToBase64(secp256k1.sign(signatureBaseBytes(base), input.priv))}:`
    return {
      method: 'POST',
      authority: LOGIN_AUTHORITY,
      path: LOGIN_PATH,
      search: '',
      targetUri: LOGIN_URL,
      headers,
      body,
      expectedNonce: nonce,
      nonceStore: createNonceStore(),
    }
  }

  it('accepts an account id signed by the key its address is derived from', async () => {
    // Through the SDK's own client path, so this also proves the two sides agree on
    // the wire: the CLI's `--wallet web3 --chain-id` produces exactly this.
    const connector = chainWalletConnector(keypairWallet(PRIV, { curve: 'secp256k1' }), {
      host: '127.0.0.1:4101',
      chainId: CHAIN_ID,
      address: ADDRESS,
    })
    const signed = await connector.signRequest({ url: LOGIN_URL, method: 'POST', nonce: '' })
    const result = await verifyAnpLoginRequest({
      method: 'POST',
      authority: LOGIN_AUTHORITY,
      path: LOGIN_PATH,
      search: '',
      targetUri: LOGIN_URL,
      headers: signed.headers,
      body: signed.body,
      expectedNonce: '',
      nonceStore: createNonceStore(),
    })
    expect(identityOf(result)?.did).toBe(ACCOUNT_DID)
  })

  it('rejects an inline document that names a key the account id does not commit to', async () => {
    // Sign with the attacker's key while claiming the victim's account id, by inlining
    // a document whose method carries the attacker's key. keyid and body.did both agree
    // on the victim — and there is no fingerprint in the identifier to recompute, so the
    // recovered address is the ONLY thing that can expose the swap.
    const attacker = new Uint8Array(Array.from({ length: 32 }, () => 0x43))
    const keyid = `${ACCOUNT_DID}#key-1`
    const didDocument = buildBaseDidDocument({
      did: ACCOUNT_DID,
      keyid,
      publicKeyMultibase: encodeMultibaseSecp256k1(secp256k1.getPublicKey(attacker, true)),
    })
    const result = await verifyAnpLoginRequest(await accountRequest({ priv: attacker, didDocument }))
    expect(reasonOf(result)).toBe('invalid_verification_method')
    // Assert the REASON, not merely that it failed: a document that resolves to no key
    // at all (or a proof that simply does not verify) would give the same wire error,
    // and neither would prove the account-id binding was what refused the swap.
    const cause = result.ok === false ? (result.cause as Error) : undefined
    expect(cause?.message).toContain('derives')
  })

  it('rejects an account id whose document names a key on the wrong curve', async () => {
    // An address is derived from secp256k1 and nothing else, so an ed25519 key under an
    // account id cannot be the key that address commits to.
    const keyid = `${ACCOUNT_DID}#key-1`
    const didDocument = buildBaseDidDocument({
      did: ACCOUNT_DID,
      keyid,
      publicKeyMultibase: encodeMultibaseEd25519(ed25519.getPublicKey(ed25519.utils.randomSecretKey())),
    })
    const result = await verifyAnpLoginRequest(await accountRequest({ priv: PRIV, didDocument }))
    expect(reasonOf(result)).toBe('invalid_verification_method')
    expect(result.ok === false && (result.cause as Error).message).toContain('secp256k1')
  })
})
