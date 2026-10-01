// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { createConfig } from './config'
import { login, register } from './actions'
import { anpDevShim } from './connectors/anpDevShim'
import { isConnectxError } from './errors'

// A peer's non-2xx body carries two things a caller needs: the HTTP status and the
// server's own machine-readable `code` (agent-on sends `handle_taken` on a duplicate
// handle). The SDK's `code` stays coarse (`register_failed`), so these must ride on
// the error or the caller can only see the generic `error` string.

const host = 'localhost:3000'
const registerUri = `http://${host}/api/register/anp`
const loginUri = `http://${host}/api/login/anp/verify`

async function setup() {
  const connector = anpDevShim(host)
  return { connector, config: createConfig([connector], connector.id) }
}

const respond = (status: number, body: unknown) => async () =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

async function catchError(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn()
  } catch (err) {
    return err
  }
  throw new Error('expected rejection')
}

describe('login/register — peer error surface', () => {
  it('surfaces the peer code + status when register is rejected', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      register(config, {
        connectorId: connector.id,
        handle: 'alice',
        nonce: 'n1',
        targetUri: registerUri,
        transport: respond(409, { error: 'Request failed', code: 'handle_taken' }),
      }),
    )
    expect(isConnectxError(err)).toBe(true)
    expect(err).toMatchObject({ code: 'register_failed', status: 409, serverCode: 'handle_taken' })
  })

  it('classifies a generic 403 as authorization_denied, keeping the peer code', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: loginUri,
        transport: respond(403, { error: 'Forbidden', code: 'agent_blocked' }),
      }),
    )
    expect(err).toMatchObject({ code: 'authorization_denied', status: 403, serverCode: 'agent_blocked' })
  })

  it('maps the ANP-02 §3.2.4.2 forbidden_did 403 to its own code', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: loginUri,
        transport: respond(403, { code: 403, error: 'forbidden_did', error_description: 'DID is not permitted here.' }),
      }),
    )
    // `error_description` is the human message; `forbidden_did` is the machine code.
    expect(err).toMatchObject({ code: 'forbidden_did', status: 403, serverCode: 'forbidden_did', message: 'DID is not permitted here.' })
  })

  it('maps a 409 did_superseded to its own code (and only that 409)', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: loginUri,
        // The ANP 1.2 update signal: the DID offered has been replaced by a
        // successor. The `handle_taken` case above is the negative control — a 409
        // must not be reclassified on status alone.
        transport: respond(409, {
          code: 'did_superseded',
          error: 'DID has been superseded.',
          requestedDid: 'did:wba:example.com:user:alice:e1_old',
          currentDid: 'did:wba:example.com:user:alice:e1_new',
        }),
      }),
    )
    expect(err).toMatchObject({ code: 'did_superseded', status: 409, serverCode: 'did_superseded' })
  })

  it('reads the authoritative WWW-Authenticate challenge, not just the body', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: loginUri,
        // ANP-02 §4.2.2: the header is authoritative; the body may mirror it.
        transport: async () =>
          new Response(JSON.stringify({ message: 'nope' }), {
            status: 401,
            headers: {
              'content-type': 'application/json',
              'www-authenticate':
                'DIDWba realm="api.example.com", error="invalid_signature", error_description="Signature verification failed."',
            },
          }),
      }),
    )
    expect(err).toMatchObject({ code: 'login_failed', status: 401, serverCode: 'invalid_signature', message: 'Signature verification failed.' })
  })

  it('keeps the SDK message and omits serverCode for a non-JSON body', async () => {
    const { connector, config } = await setup()
    const err = await catchError(() =>
      login(config, {
        connectorId: connector.id,
        nonce: 'n1',
        targetUri: loginUri,
        transport: async () => new Response('<html>boom</html>', { status: 500 }),
      }),
    )
    expect(err).toMatchObject({ code: 'login_failed', status: 500, message: 'Request failed (500)' })
    expect((err as { serverCode?: string }).serverCode).toBeUndefined()
  })

  it('re-signs with the nonce the 401 challenge offers', async () => {
    const { connector, config } = await setup()
    const seen: string[] = []
    const transport = async (_url: string, init: RequestInit) => {
      seen.push((init.body as string) ?? '')
      if (seen.length === 1) {
        return new Response('{}', {
          status: 401,
          headers: { 'www-authenticate': 'DIDWba realm="api.example.com", nonce="xyz987"' },
        })
      }
      return new Response(JSON.stringify({ ok: true, token: 't' }), { status: 200 })
    }
    const outcome = await login(config, {
      connectorId: connector.id,
      nonce: 'stale',
      targetUri: loginUri,
      transport: transport as unknown as typeof fetch,
    })
    expect(seen).toHaveLength(2)
    expect(seen[1]).toContain('xyz987')
    expect(outcome.token).toBe('t')
  })
})

describe('login outcome identity (ANP-02)', () => {
  it('reports both the stable subject and the wire DID', async () => {
    const { connector, config } = await setup()
    const outcome = await login(config, {
      connectorId: connector.id,
      nonce: 'n1',
      targetUri: loginUri,
      transport: respond(200, { ok: true }),
    })
    // `did` is the credential actually signed with (it carries a key fingerprint);
    // `subject` is what survives an update.
    expect(outcome.did).toMatch(/^did:wba:/)
    // Same method prefix as the DID, minus the fingerprint segment — which is
    // exactly what makes it a subject and not a DID.
    expect(outcome.subject).not.toMatch(/:e1_/)
    expect(outcome.subject.startsWith('did:wba:')).toBe(true)
    expect(outcome.method).toBe('anp')
  })
})
