// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createConfig } from './config'
import { login, register, update } from './actions'
import { anpCli } from './connectors/anpCli'
import { anpDevShim } from './connectors/anpDevShim'
import type { ParsedKey } from './keys/parse'

// A 2xx is not by itself an answer from an ANP peer. Everything a success outcome needs
// is optional — the token usually rides in a header, the confirmed handle falls back to
// the one we sent, the body may be empty — so a web page answering 200 would be reported
// as a successful exchange, with nothing in the outcome looking wrong. The mistake that
// produces this is a `targetUri` aimed at a site origin instead of the endpoint, and it
// must fail loudly instead of being recorded as a success.

const host = 'localhost:3000'
const registerUri = `http://${host}/api/register/anp`
const loginUri = `http://${host}/api/login/anp/verify`
const updateUri = `https://did.example.com/api/did/update`

const page = (status = 200) =>
  async () =>
    new Response('<!DOCTYPE html><html><body>Agent World</body></html>', {
      status,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    })

async function setup() {
  const connector = anpDevShim(host)
  return { connector, config: createConfig([connector], connector.id) }
}

async function catchError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn()
  } catch (err) {
    return err
  }
  throw new Error('expected rejection')
}

describe('a 2xx that is a web page is refused, not read as an outcome', () => {
  it('register: fails on the site origin instead of reporting a bound handle', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      register(config, {
        connectorId: connector.id,
        handle: 'alice',
        nonce: 'n1',
        targetUri: `http://${host}`,
        transport: page(),
      }),
    )
    expect(err).toMatchObject({ code: 'invalid_argument', status: 200 })
    // The message has to name where the request went: that is the only thing wrong here.
    expect((err as Error).message).toContain(`POST http://${host} answered 200 text/html`)
  })

  it('login: fails the same way', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, { connectorId: connector.id, nonce: 'n1', targetUri: loginUri, transport: page() }),
    )
    expect(err).toMatchObject({ code: 'invalid_argument', status: 200 })
  })

  it('update: fails rather than reporting a delivered hop', async () => {
    const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
    const connector = anpCli(key, { host: 'did.example.com', path: ['user', 'alice'] })
    const successorKey: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
    const successorConnector = anpCli(successorKey, { host: 'did.example.com', path: ['user', 'alice'] })
    const config = createConfig([connector], connector.id)
    const next = await successorConnector.getIdentity()

    const err = await catchError(() =>
      update(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: updateUri,
        successorDid: next.did,
        successorDocument: next.didDocument,
        transport: page(),
      }),
    )
    expect(err).toMatchObject({ code: 'invalid_argument', status: 200 })
  })

  it('refuses XHTML as well (same thing, one spelling over)', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      register(config, {
        connectorId: connector.id,
        handle: 'alice',
        nonce: 'n1',
        targetUri: registerUri,
        transport: async () =>
          new Response('<html/>', { status: 200, headers: { 'content-type': 'application/xhtml+xml' } }),
      }),
    )
    expect(err).toMatchObject({ code: 'invalid_argument' })
  })

  // The body is genuinely optional, so the two shapes below must keep succeeding. A
  // stricter rule ("a success must carry JSON") would break peers that answer 204 or
  // hand back the token in a header only — which is why only HTML is refused.
  it('still accepts a non-JSON body from a peer (token in a header)', async () => {
    const { connector, config } = await setup()
    const outcome = await register(config, {
      connectorId: connector.id,
      handle: 'alice',
      nonce: 'n1',
      targetUri: registerUri,
      transport: async () =>
        new Response('ok', {
          status: 200,
          headers: {
            'content-type': 'text/plain',
            'authentication-info': 'access_token="tok_header", token_type="Bearer"',
          },
        }),
    })
    expect(outcome.token).toBe('tok_header')
    expect(outcome.tokenType).toBe('Bearer')
    expect(outcome.handle).toBe('alice')
  })

  it('still accepts an empty body', async () => {
    const { connector, config } = await setup()
    const outcome = await login(config, {
      connectorId: connector.id,
      nonce: 'n1',
      targetUri: loginUri,
      transport: async () => new Response(null, { status: 204 }),
    })
    expect(outcome.token).toBeUndefined()
  })
})
