// `msg send` decides what a message body is before it decides anything else, and that
// decision is where the Profile's body rules live (P3 §6.2, §6.3). It is also the only
// part of the command a test can reach without a peer: everything past it needs a store,
// a DID document and a live service endpoint.

import { describe, it, expect } from 'vitest'
import { ConnectxError } from '@agentx/core'
import { callExtension, payloadOf, runMsg, type Channel } from './msg'
import type { Values } from './auth'

const TO = 'did:wba:example.com:user:bob:e1_xyz'

/** The error a call throws, or a failure if it throws nothing. */
async function fails(run: () => Promise<void>): Promise<ConnectxError> {
  return run().then(
    () => {
      throw new Error('expected the call to fail')
    },
    (err: unknown) => err as ConnectxError,
  )
}

function body(overrides: Values): Values {
  return { to: TO, ...overrides }
}

describe('payloadOf', () => {
  it('sends text as `text` with the type its shape belongs to', () => {
    expect(payloadOf({ text: 'hello' })).toEqual({
      body: { text: 'hello' },
      contentType: 'text/plain',
    })
  })

  it('sends a JSON object as `payload`, parsed rather than as a string', () => {
    // §6.2.5 L266 forbids sending the object double-serialized: `payload` IS the object.
    expect(payloadOf({ body: '{"kind":"ping","n":2}' })).toEqual({
      body: { payload: { kind: 'ping', n: 2 } },
      contentType: 'application/json',
    })
  })

  it('lets a content type other than the two fixed ones through', () => {
    // The rule is that each fixed type pins its body shape, not that only those two
    // types may be sent. §6.2.4 L262 and §6.2.5 L266 are the two it speaks to.
    expect(payloadOf({ text: '# hi', 'content-type': 'text/markdown' }).contentType).toBe('text/markdown')
    expect(payloadOf({ body: '{}', 'content-type': 'application/vnd.anp.x+json' }).contentType).toBe(
      'application/vnd.anp.x+json',
    )
  })
})

describe('msg send argument validation', () => {
  it('refuses a text body sent as application/json', async () => {
    // application/json has a body shape, and it is `payload`, not `text` (§6.2.5 L266).
    const err = await fails(() => runMsg(body({ text: 'hi', 'content-type': 'application/json' }), 'send', []))
    expect(err.code).toBe('invalid_argument')
    expect(err.message).toContain('--body')
  })

  it('refuses an object body sent as text/plain', async () => {
    // The mirror image: text/plain has a body shape too, and it is `text` (§6.2.4 L262).
    const err = await fails(() => runMsg(body({ body: '{}', 'content-type': 'text/plain' }), 'send', []))
    expect(err.code).toBe('invalid_argument')
    expect(err.message).toContain('--text')
  })

  it('refuses both spellings at once, and neither', async () => {
    // §6.3: exactly ONE of the three body fields. Two spellings of one field is the same
    // violation from the other side.
    expect((await fails(() => runMsg(body({ text: 'hi', body: '{}' }), 'send', []))).code).toBe(
      'invalid_argument',
    )
    expect((await fails(() => runMsg(body({}), 'send', []))).code).toBe('missing_flag')
  })

  it('refuses a --body that is not a JSON object', async () => {
    // `payload` is typed as a JSON object (§6.2.5 L266), so an array or a scalar has
    // nowhere to go: `text` is the field for a bare string.
    for (const raw of ['[1,2]', '"hi"', '3', 'null']) {
      const err = await fails(() => runMsg(body({ body: raw }), 'send', []))
      expect(err.code, raw).toBe('invalid_argument')
    }
  })

  it('refuses an unparsable --body', async () => {
    expect((await fails(() => runMsg(body({ body: '{"a":' }), 'send', []))).code).toBe('invalid_argument')
  })

  it('refuses a send with no recipient', async () => {
    const err = await fails(() => runMsg({ text: 'hi' }, 'send', []))
    expect(err.code).toBe('missing_flag')
    expect(err.message).toContain('--to')
  })

  it('checks the body before it reaches for an identity', async () => {
    // Ordering, asserted rather than assumed: `payloadOf` runs second, so a refused body
    // is reported as a refusal even on a machine with no identity stored and no network.
    // Were the identity resolved first, this would come back as a store error instead.
    const err = await fails(() => runMsg(body({ text: 'hi', body: '{}' }), 'send', []))
    expect(err.code).toBe('invalid_argument')
  })
})

describe('msg caps argument validation', () => {
  it('refuses a probe with no DID', async () => {
    expect((await fails(() => runMsg({}, 'caps', []))).code).toBe('missing_flag')
    expect((await fails(() => runMsg({}, 'caps', ['']))).code).toBe('missing_flag')
  })

  it('refuses an account id as the thing to probe, and says why', async () => {
    // TODO1 B7. The refusal belongs to the locator: an account id names no service
    // endpoint anywhere, which is a different fact from "this DID document has no
    // ANPMessageService in it", and it is answered before any fetch is attempted. The
    // command layer never asks what kind of identifier it is holding.
    const err = await fails(() => runMsg({}, 'caps', ['eip155:1:0x0000000000000000000000000000000000000001']))
    expect(err.code).toBe('caip10_has_no_ingress')
  })
})

describe('msg show argument validation', () => {
  it('refuses a show with no id', async () => {
    const err = await fails(() => runMsg({}, 'show', []))
    expect(err.code).toBe('missing_flag')
    expect(err.message).toContain('message_id')
  })
})

describe('msg inbox argument validation', () => {
  it('refuses a --limit that is not a positive integer', async () => {
    // Checked before the identity is resolved, so this is a refusal on a machine with no
    // store rather than a store error — the same ordering `payloadOf` is asserted to have.
    for (const limit of ['0', '-1', 'abc', '1.5', '']) {
      const err = await fails(() => runMsg({ limit }, 'inbox', []))
      expect(err.code, limit).toBe('invalid_argument')
    }
  })
})

describe('msg read argument validation', () => {
  it('refuses an id and --all together, and neither', async () => {
    // Both spellings name the same set, so passing both is a contradiction rather than a
    // superset — and passing neither names nothing at all.
    const both = await fails(() => runMsg({ all: true }, 'read', ['msg-1']))
    expect(both.code).toBe('invalid_argument')
    expect(both.message).toContain('--all')
    const neither = await fails(() => runMsg({}, 'read', []))
    expect(neither.code).toBe('missing_flag')
    expect(neither.message).toContain('--all')
  })
})

describe('msg dispatch', () => {
  it('refuses a subcommand it does not have', async () => {
    await expect(runMsg({}, 'fetch', [])).rejects.toThrow(/No subcommand "fetch"/)
  })
})

// Every extension command (`inbox`, `show`, `read`) goes through this one call, so pinning
// the envelope here pins all three. The regression it guards was real: the commands shipped
// without `meta.target` and would have been rejected by any conforming service, because a
// method carrying `origin_proof` MUST name its target (P1 附录 A.4 L1068).

const DID = 'did:wba:example.com:user:alice:e1_key'

function extensionChannel(): Channel {
  return {
    sender: {
      did: DID,
      signer: { keyid: `${DID}#key-1`, sign: () => new Uint8Array(64) },
      agent: 'claude-code',
      profile: 'default',
    },
    target: {
      identity: DID,
      serviceId: 'anp-message-service',
      endpoint: 'https://agentx.example/anp-im/rpc',
      serviceDid: 'did:wba:agentx.example',
      hintedProfiles: [],
      hintedSecurityProfiles: [],
    },
    options: { allowedHosts: [] },
  }
}

/** Capture the request `callExtension` puts on the wire, without a service. */
async function sentRequest(method: string, body: Record<string, unknown>) {
  let seen: Record<string, unknown> | undefined
  const result = await callExtension(extensionChannel(), method, body, async (_endpoint, request) => {
    seen = request as unknown as Record<string, unknown>
    return { jsonrpc: '2.0', id: request.id, result: { ok: true } }
  })
  if (seen === undefined) throw new Error('nothing was posted')
  return { request: seen, result }
}

describe('callExtension', () => {
  it('names the mailbox owner as the target of the proof', async () => {
    const { request } = await sentRequest('inbox.get', { limit: 20 })
    const params = request.params as Record<string, unknown>
    expect(params.meta).toMatchObject({
      profile: 'x_agentx.inbox.v1',
      sender_did: DID,
      target: { kind: 'agent', did: DID },
    })
    expect(params.auth).toMatchObject({
      scheme: 'anp-rfc9421-origin-proof-v1',
      origin_proof: { signature: expect.stringMatching(/^sig1=:/) },
    })
    expect(params.body).toEqual({ limit: 20 })
  })

  it('signs over that target, so a service can rebuild @target-uri from it', async () => {
    // The signature base is not this test's to check — core pins it byte for byte. What is
    // pinned here is that the target is not something the service has to guess from the body.
    const { request } = await sentRequest('message.get_batch', { message_ids: ['m-1'] })
    const params = request.params as Record<string, unknown>
    const meta = params.meta as Record<string, unknown>
    const proof = (params.auth as { origin_proof: Record<string, unknown> }).origin_proof
    expect(meta.target).toBeDefined()
    expect(proof.signatureInput).toContain('@target-uri')
  })

  it('returns the result on success and the name of the method on refusal', async () => {
    const { result } = await sentRequest('inbox.get', {})
    expect(result).toEqual({ ok: true })

    const refusal = await callExtension(extensionChannel(), 'inbox.get', {}, async (_endpoint, request) => ({
      jsonrpc: '2.0',
      id: request.id,
      error: { code: -32601, message: 'no such method' },
    })).then(
      () => {
        throw new Error('expected the call to fail')
      },
      (err: unknown) => err as ConnectxError,
    )
    expect(refusal.code).toBe('unsupported_extension')
    expect(refusal.message).toContain('inbox.get')
  })
})
