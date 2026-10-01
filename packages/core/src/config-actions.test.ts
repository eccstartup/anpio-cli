import { describe, it, expect, vi } from 'vitest'
import { createConfig, selectWallet } from './config'
import { signRequest, login, register } from './actions'
import { ConnectorUnavailableError } from './types'
import type { AnpConnector, AnpIdentity, SignRequest, SignResult, WalletType } from './types'
import { subjectOf } from './identity'

const IDENTITY: AnpIdentity = {
  subject: subjectOf('did:wba:localhost:3000'),
  did: 'did:wba:localhost:3000',
  keyid: 'did:wba:localhost:3000#key-1',
  publicKey: { publicKeyMultibase: 'zed...' },
  didDocument: { id: 'did:wba:localhost:3000', verificationMethod: [] },
}

function fakeConnector(
  id: string,
  type: WalletType = 'anp-dev-shim',
  opts: { available?: boolean; signResult?: Partial<SignResult> } = {},
): AnpConnector {
  const signSpy = vi.fn(async (req: SignRequest): Promise<SignResult> => {
    // Mirror every real connector: the endpoint-specific fields the caller asked for
    // are IN the signed body (`signAndPost` refuses a body that lost one).
    const body: Record<string, unknown> = { nonce: req.nonce, did: IDENTITY.did }
    if (req.handle != null) body.handle = req.handle
    if (req.successorDid != null) {
      body.successorDid = req.successorDid
      body.successorDocument = req.successorDocument
    }
    return {
      ...IDENTITY,
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json', signature: `sig1=:${req.nonce}:'` },
      ...opts.signResult,
    }
  })
  return {
    id,
    name: id,
    type,
    isAvailable: () => Promise.resolve(opts.available ?? true),
    getIdentity: () => Promise.resolve(IDENTITY),
    signRequest: signSpy,
  }
}

const transport = (response: Response) => async () => response

describe('createConfig', () => {
  it('stores connectors and the default', () => {
    const a = fakeConnector('a')
    const b = fakeConnector('b')
    const config = createConfig([a, b], 'b')
    expect(config.connectors).toHaveLength(2)
    expect(config.defaultConnectorId).toBe('b')
  })

  it('is fine without a default', () => {
    const config = createConfig([fakeConnector('a')])
    expect(config.defaultConnectorId).toBeUndefined()
  })

  it('throws if the default connector is not configured', () => {
    expect(() => createConfig([fakeConnector('a')], 'missing')).toThrow(/does not match any configured connector/)
  })
})

describe('selectWallet', () => {
  const a = fakeConnector('a')
  const b = fakeConnector('b')
  const config = createConfig([a, b], 'b')

  it('selects by explicit id', () => {
    expect(selectWallet(config, 'a').id).toBe('a')
  })

  it('falls back to the default connector', () => {
    expect(selectWallet(config).id).toBe('b')
  })

  it('falls back to the first connector when there is no default', () => {
    const noDefault = createConfig([a, b])
    expect(selectWallet(noDefault).id).toBe('a')
  })

  it('throws when the requested connector is missing', () => {
    expect(() => selectWallet(config, 'missing')).toThrow(/No connector selected/)
  })
})

describe('signRequest', () => {
  it('delegates to the selected connector and returns its result', async () => {
    const c = fakeConnector('a')
    const result = await signRequest(createConfig([c]), 'a', { url: 'http://x/verify', method: 'POST', nonce: 'n' })
    expect(result.did).toBe(IDENTITY.did)
    expect(c.signRequest).toHaveBeenCalledTimes(1)
  })

  it('rejects an unavailable connector', async () => {
    const c = fakeConnector('a', 'anp-dev-shim', { available: false })
    await expect(signRequest(createConfig([c]), 'a', { url: 'http://x', method: 'POST', nonce: '' })).rejects.toBeInstanceOf(
      ConnectorUnavailableError,
    )
  })
})

describe('login', () => {
  it('POSTs the signed body and returns the token + anp method', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ token: 'tok' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok"' },
    })
    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: transport(res),
    })
    expect(outcome.method).toBe('anp')
    expect(outcome.token).toBe('tok')
    expect(outcome.walletType).toBe('anp-dev-shim')
    expect(outcome.did).toBe(IDENTITY.did)
  })

  it('carries the token_type the server named, verbatim (ANP-02 §3.2.3)', async () => {
    const c = fakeConnector('a')
    // The header exactly as §3.2.3 spells it, `token_type` included.
    const res = new Response(JSON.stringify({ token: 'tok' }), {
      status: 200,
      headers: {
        'authentication-info': 'access_token="tok", token_type="DPoP", expires_in=3600, scope="orders.read"',
      },
    })
    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: transport(res),
    })
    // Recorded as sent, NOT normalised to Bearer: the value is what selects how the
    // token has to be presented, so rewriting it would tell the caller it may send
    // this token the one way the server said it may not.
    expect(outcome.token).toBe('tok')
    expect(outcome.tokenType).toBe('DPoP')
  })

  it('leaves token_type undefined when the server names none (the Bearer default)', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ token: 'tok' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok"' },
    })
    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: transport(res),
    })
    // Absent stays absent: §3.2.3 permits defaulting an unnamed type to Bearer, and
    // recording a `tokenType: 'Bearer'` would claim the server said something it did not.
    expect(outcome.tokenType).toBeUndefined()
  })

  it('takes token and token_type from the same source, never pairing across them', async () => {
    const c = fakeConnector('a')
    // The header names a TYPE but returns no access_token, so the token can only come
    // from the body — and the header's type describes a token this response does not
    // contain. Pairing them would type the body token with the header's profile.
    const res = new Response(JSON.stringify({ token: 'body_tok', token_type: 'Bearer' }), {
      status: 200,
      headers: { 'authentication-info': 'token_type="DPoP"' },
    })
    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: transport(res),
    })
    expect(outcome.token).toBe('body_tok')
    expect(outcome.tokenType).toBe('Bearer')
  })

  it('reads token_type from the body alongside a body token', async () => {
    const c = fakeConnector('a')
    // The non-normative body fallback (§4.2 leaves it undefined) carries the type too.
    const res = new Response(JSON.stringify({ token: 'body_tok', token_type: 'DPoP' }), { status: 200 })
    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: transport(res),
    })
    expect(outcome.tokenType).toBe('DPoP')
  })

  it('re-signs when the server returns a 401 challenge and then succeeds', async () => {
    const c = fakeConnector('a')
    const make = (status: number, headers: Record<string, string>) =>
      new Response(JSON.stringify({}), { status, headers })

    let call = 0
    const transport = vi.fn(async () => {
      call += 1
      if (call === 1) return make(401, { 'www-authenticate': 'didwba nonce="fresh-nonce", error="invalid_nonce"' })
      return make(200, { 'authentication-info': 'access_token="tok_e2e"' })
    })

    const outcome = await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'stale',
      targetUri: 'http://x/verify',
      transport,
    })
    expect(outcome.token).toBe('tok_e2e')
    // Signed twice: once with the stale nonce, once with the server's fresh one.
    expect(c.signRequest).toHaveBeenCalledTimes(2)
    expect((c.signRequest as ReturnType<typeof vi.fn>).mock.calls[1][0].nonce).toBe('fresh-nonce')
  })

  it('does not re-sign when the challenge nonce equals our nonce', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ token: 'tok' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok"' },
    })
    const transport = vi.fn(async () => res)
    await login(createConfig([c]), { connectorId: 'a', nonce: 'n', targetUri: 'http://x/verify', transport })
    expect(c.signRequest).toHaveBeenCalledTimes(1)
  })

  it('throws with the server error message on a non-ok response', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ error: 'forbidden' }), { status: 403 })
    await expect(
      login(createConfig([c]), { connectorId: 'a', nonce: 'n', targetUri: 'http://x/verify', transport: transport(res) }),
    ).rejects.toThrow(/forbidden/)
  })

  it('passes redirect: "error" to the transport so the signed proof is not forwarded', async () => {
    const c = fakeConnector('a')
    let captured: RequestInit | undefined
    const res = new Response(JSON.stringify({ token: 'tok' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok"' },
    })
    const spyTransport = vi.fn(async (_url: string, init: RequestInit) => {
      captured = init
      return res
    })
    await login(createConfig([c]), {
      connectorId: 'a',
      nonce: 'n',
      targetUri: 'http://x/verify',
      transport: spyTransport,
    })
    // A 307/308 cross-origin redirect would otherwise forward signature/…/DID doc.
    expect(captured?.redirect).toBe('error')
  })

  it('rejects a success response whose body exceeds the byte cap (streaming)', async () => {
    const c = fakeConnector('a')
    // No Content-Length on purpose: the cap must also catch an unbounded stream.
    const res = new Response('x'.repeat(2 * 1024 * 1024), { status: 200 })
    await expect(
      login(createConfig([c]), { connectorId: 'a', nonce: 'n', targetUri: 'http://x/verify', transport: transport(res) }),
    ).rejects.toMatchObject({ code: 'response_too_large' })
  })

  it('rejects an error response whose declared Content-Length exceeds the cap', async () => {
    const c = fakeConnector('a')
    const res = new Response('x'.repeat(2 * 1024 * 1024), {
      status: 500,
      headers: { 'content-length': String(2 * 1024 * 1024) },
    })
    await expect(
      login(createConfig([c]), { connectorId: 'a', nonce: 'n', targetUri: 'http://x/verify', transport: transport(res) }),
    ).rejects.toMatchObject({ code: 'response_too_large' })
  })

  it('rejects an error response whose streamed body exceeds the cap', async () => {
    const c = fakeConnector('a')
    const res = new Response('x'.repeat(2 * 1024 * 1024), { status: 403 })
    await expect(
      login(createConfig([c]), { connectorId: 'a', nonce: 'n', targetUri: 'http://x/verify', transport: transport(res) }),
    ).rejects.toMatchObject({ code: 'response_too_large' })
  })
})

describe('register', () => {
  it('POSTs a registration request and returns the handle + token', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ token: 'tok_reg' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok_reg"' },
    })
    const outcome = await register(createConfig([c]), {
      connectorId: 'a',
      handle: 'alice',
      targetUri: 'http://x/register',
      nonce: 'n',
      transport: transport(res),
    })
    expect(outcome.did).toBe(IDENTITY.did)
    expect(outcome.handle).toBe('alice')
    expect(outcome.token).toBe('tok_reg')
  })

  it('carries token_type on a registration too', async () => {
    const c = fakeConnector('a')
    const res = new Response(JSON.stringify({ token: 'tok_reg' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="tok_reg", token_type="Bearer"' },
    })
    const outcome = await register(createConfig([c]), {
      connectorId: 'a',
      handle: 'alice',
      targetUri: 'http://x/register',
      nonce: 'n',
      transport: transport(res),
    })
    // A named `Bearer` IS recorded — it is a statement by the server, unlike the
    // absence of one. The two must not collapse: only the absence may default.
    expect(outcome.tokenType).toBe('Bearer')
  })

  it('re-signs on a 401 challenge', async () => {
    const c = fakeConnector('a')
    let call = 0
    const transport = vi.fn(async () => {
      call += 1
      if (call === 1) return new Response(JSON.stringify({}), { status: 401, headers: { 'www-authenticate': 'didwba nonce="fresh"' } })
      return new Response(JSON.stringify({ token: 'ok' }), { status: 200, headers: { 'authentication-info': 'access_token="ok"' } })
    })
    await register(createConfig([c]), { connectorId: 'a', handle: 'bob', targetUri: 'http://x/register', nonce: 'stale', transport })
    expect(c.signRequest).toHaveBeenCalledTimes(2)
  })

  it('passes redirect: "error" to the transport so the signed proof is not forwarded', async () => {
    const c = fakeConnector('a')
    let captured: RequestInit | undefined
    const res = new Response(JSON.stringify({ token: 'ok' }), {
      status: 200,
      headers: { 'authentication-info': 'access_token="ok"' },
    })
    const spyTransport = vi.fn(async (_url: string, init: RequestInit) => {
      captured = init
      return res
    })
    await register(createConfig([c]), {
      connectorId: 'a',
      handle: 'bob',
      targetUri: 'http://x/register',
      nonce: 'n',
      transport: spyTransport,
    })
    expect(captured?.redirect).toBe('error')
  })
})
