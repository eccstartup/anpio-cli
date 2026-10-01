// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { createConfig } from './config'
import { register } from './actions'
import { anpDevShim } from './connectors/anpDevShim'
import { resolveVerificationKey } from './crypto/resolveDid'
import { verifyHttpMessageSignature } from './crypto/verify'

// Registration must bind the claimed handle into the signed body, so the
// content-digest covers WHAT handle was requested. Otherwise a MITM could swap the
// handle after signing, and the register endpoint would accept an unbound name.

const host = 'localhost:3000'
const targetUri = `http://${host}/api/register/anp`

async function hookedTransport() {
  const connector = anpDevShim(host)
  const config = createConfig([connector], connector.id)
  const identity = await connector.getIdentity()
  const key = await resolveVerificationKey(identity.keyid, identity.didDocument)

  let captured: { url: string; init: RequestInit } | undefined
  const transport = async (url: string, init: RequestInit): Promise<Response> => {
    captured = { url, init }
    return new Response(JSON.stringify({ handle: 'server-confirmed' }), { status: 200 })
  }
  return { connector, config, key, transport, captured: () => captured }
}

function verifyInput(
  key: Awaited<ReturnType<typeof resolveVerificationKey>>,
  captured: { url: string; init: RequestInit },
) {
  const url = new URL(captured.url)
  return {
    method: 'POST',
    path: url.pathname,
    authority: url.host,
    targetUri: captured.url,
    headers: (captured.init.headers ?? {}) as Record<string, string>,
    body: captured.init.body as string,
    key,
  }
}

describe('register — binds the claimed handle (3.3)', () => {
  it('embeds handle in the signed body so content-digest covers it', async () => {
    const { config, transport, captured } = await hookedTransport()
    const outcome = await register(config, { handle: 'alice', targetUri, nonce: 'n1', transport })
    expect(outcome.handle).toBe('server-confirmed')

    const c = captured()!
    const body = JSON.parse(c.init.body as string) as Record<string, unknown>
    expect(body.handle).toBe('alice')
    // The signature verified over the exact body that carries handle.
    expect(c.init.headers).toBeDefined()
  })

  it('signature for the register request verifies over the handle-bearing body', async () => {
    const { config, key, transport, captured } = await hookedTransport()
    await register(config, { handle: 'alice', targetUri, nonce: 'n1', transport })
    const c = captured()!
    expect(await verifyHttpMessageSignature(verifyInput(key, c))).toBe(true)
  })

  it('fails if the handle is swapped after signing (tamper)', async () => {
    const { config, key, transport, captured } = await hookedTransport()
    await register(config, { handle: 'alice', targetUri, nonce: 'n1', transport })
    const c = captured()!
    const tampered = {
      ...c,
      init: {
        ...c.init,
        body: JSON.stringify({ ...JSON.parse(c.init.body as string), handle: 'mallory' }),
      },
    }
    expect(await verifyHttpMessageSignature(verifyInput(key, tampered))).toBe(false)
  })

  it('prefers the server-confirmed handle over the request value', async () => {
    const { config, connector, transport, captured } = await hookedTransport()
    const outcome = await register(config, { handle: 'alice', targetUri, nonce: 'n1', transport })
    expect(outcome.did).toBe((await connector.getIdentity()).did)
    expect(outcome.handle).toBe('server-confirmed')
    expect(captured()).toBeDefined()
  })
})
