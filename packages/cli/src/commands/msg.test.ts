// `msg send` decides what a message body is before it decides anything else, and that
// decision is where the Profile's body rules live (P3 §6.2, §6.3). It is also the only
// part of the command a test can reach without a peer: everything past it needs a store,
// a DID document and a live service endpoint.

import { describe, it, expect, vi } from 'vitest'
import { ConnectxError } from '@agentx/core'
import { callExtension, payloadOf, type Channel } from './channel'
import { runMsg, type ExtensionCaller } from './msg'
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

// ---- the read commands, against a fake service --------------------------------
//
// `runMsg` takes an optional caller for `inbox` / `show` / `read`, so what those three
// print can be pinned without a keystore or a peer — the same reason `payloadOf` is
// exported: the decision belongs to the command, and everything past it needs a store, a
// DID document and a live endpoint.
//
// The behaviour first under test is the unread test. §9.3 gives a row a `read_at` and
// leaves it null for one direction; a client that treats null as "unread" for both
// directions counts every message the user ever SENT into the unread tally.

/** One row as §9.3 defines it, overridable field by field. */
function row(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    message_id: 'm-1',
    sender_did: 'did:wba:peer.example:user:bob:e1_bbb',
    recipient_did: DID,
    content_type: 'text/plain',
    direction: 'incoming',
    created_at: '2026-10-01T12:00:00.000Z',
    read_at: null,
    body: { text: 'hello' },
    ...overrides,
  }
}

interface Fake {
  caller: ExtensionCaller
  calls: { method: string; body: Record<string, unknown> }[]
}

/** A service that answers method by method, recording what it was asked. A method with
 *  no answer throws rather than returning an empty result: a command calling a method the
 *  test did not expect is the finding, and an empty object would hide it. */
function service(answers: Record<string, (body: Record<string, unknown>) => Record<string, unknown>>): Fake {
  const calls: Fake['calls'] = []
  const caller: ExtensionCaller = async (method, body) => {
    calls.push({ method, body })
    const answer = answers[method]
    if (answer === undefined) throw new Error(`${method} was called, which this fake does not answer`)
    return answer(body)
  }
  return { caller, calls }
}

/** The lines a command printed, one `console.log` per entry. */
async function printed(run: () => Promise<void>): Promise<string[]> {
  const lines: string[] = []
  const spy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => String(arg)).join(' '))
  })
  try {
    await run()
  } finally {
    spy.mockRestore()
  }
  return lines
}

/** The value half of a `field()` line, which pads its label to 20 columns. */
function fieldOf(lines: string[], label: string): string | undefined {
  return lines.find((line) => line.startsWith(label))?.slice(label.length).trim()
}

describe('msg inbox rendering', () => {
  it('does not count an outgoing row as unread, however its read_at reads', async () => {
    const { caller } = service({
      'inbox.get': () => ({
        messages: [
          row({ message_id: 'out-1', direction: 'outgoing', sender_did: DID, read_at: null }),
          row({ message_id: 'in-1' }),
        ],
        total: 2,
        has_more: false,
      }),
    })

    const lines = await printed(() => runMsg({ 'include-read': true }, 'inbox', [], caller))

    expect(lines[0]).toBe('2 messages, 1 unread')
    // The service has no timestamp to give for an outgoing row — nobody read it, the owner
    // wrote it — so the field is null and the client must not read that as "unread".
    const outgoing = lines.find((line) => line.includes('outgoing'))
    expect(outgoing?.startsWith('  read')).toBe(true)
    expect(lines.find((line) => line.includes('incoming'))?.startsWith('  unread')).toBe(true)
  })

  it('counts a read incoming row out of the tally and keeps it out of the unread paging', async () => {
    const read = row({ message_id: 'read-1', read_at: '2026-10-01T12:05:00.000Z' })
    const { caller, calls } = service({
      // The fake filters the way the service does, so the tally and the walk are answering
      // two different questions rather than the same one twice.
      'inbox.get': (body) => ({
        messages: body.include_read === true ? [read] : [],
        total: 1,
        has_more: false,
      }),
      'inbox.mark_read': (body) => ({ updated_count: (body.message_ids as string[]).length, read_at: '2026-10-01T12:30:00.000Z', message_ids: body.message_ids }),
    })

    const lines = await printed(() => runMsg({ 'include-read': true }, 'inbox', [], caller))

    expect(lines[0]).toBe('1 message, 0 unread')
    // `--all` walks the unread side, so a row already read is not in the set it marks — the
    // point of `include_read: false` on that walk rather than a client-side filter.
    const all = await printed(() => runMsg({ all: true }, 'read', [], caller))
    expect(all).toEqual(['nothing unread'])
    expect(calls.filter((call) => call.method === 'inbox.get').at(-1)?.body.include_read).toBe(false)
  })

  it('says which way to look when the unread list is empty', async () => {
    const { caller } = service({ 'inbox.get': () => ({ messages: [], total: 0, has_more: false }) })
    expect(await printed(() => runMsg({}, 'inbox', [], caller))).toEqual([
      'no unread messages; pass --include-read to see the rest',
    ])
    expect(await printed(() => runMsg({ 'include-read': true }, 'inbox', [], caller))).toEqual(['no messages'])
  })

  it('asks for the offset it was given, not for a page it then discards', async () => {
    const { caller, calls } = service({ 'inbox.get': () => ({ messages: [], total: 0, has_more: false }) })
    await printed(() => runMsg({ limit: '5', 'include-read': true }, 'inbox', [], caller))
    expect(calls).toEqual([{ method: 'inbox.get', body: { limit: 5, include_read: true } }])
  })
})

describe('msg show rendering', () => {
  it('prints the batch item the service returned', async () => {
    const { caller, calls } = service({
      'message.get_batch': () => ({ items: [{ message_id: 'm-1', message: row({ message_id: 'm-1' }) }], unavailable: [] }),
    })

    const lines = await printed(() => runMsg({}, 'show', ['m-1'], caller))

    expect(calls).toEqual([{ method: 'message.get_batch', body: { message_ids: ['m-1'] } }])
    expect(lines.join('\n')).toContain('hello')
    expect(lines.join('\n')).toContain('id m-1')
  })

  it('reports a message it could not resolve rather than an empty screen', async () => {
    // `unavailable` is the peer's own list, and it is the difference between "no such
    // message" and "your command asked for something that is not there".
    const { caller } = service({ 'message.get_batch': () => ({ items: [], unavailable: ['m-9'] }) })
    const err = await fails(() => runMsg({}, 'show', ['m-9'], caller))
    expect(err.code).toBe('message_not_found')
    expect(err.message).toContain('m-9')
  })
})

describe('msg read --all paging', () => {
  it('marks the ids it listed, and asks for the next page by offset', async () => {
    const pages: Record<string, unknown>[] = [
      { messages: [row({ message_id: 'a' }), row({ message_id: 'b' })], total: 3, has_more: true },
      { messages: [row({ message_id: 'c' })], total: 3, has_more: false },
    ]
    const { caller, calls } = service({
      'inbox.get': () => pages.shift() ?? { messages: [], total: 0, has_more: false },
      'inbox.mark_read': (body) => ({
        updated_count: (body.message_ids as string[]).length,
        message_ids: body.message_ids,
        read_at: '2026-10-01T12:30:00.000Z',
      }),
    })

    const lines = await printed(() => runMsg({ all: true }, 'read', [], caller))

    expect(calls.filter((call) => call.method === 'inbox.get').map((call) => call.body.skip)).toEqual([0, 2])
    // The ids LISTED, then marked — a message arriving between the two calls is left
    // unread rather than being swallowed (§9.3).
    expect(calls.at(-1)).toEqual({ method: 'inbox.mark_read', body: { message_ids: ['a', 'b', 'c'] } })
    expect(fieldOf(lines, 'marked read:')).toBe('3')
  })

  it('marks an id given on the command line without listing first', async () => {
    const { caller, calls } = service({
      'inbox.mark_read': (body) => ({ updated_count: 1, message_ids: body.message_ids, read_at: '2026-10-01T12:30:00.000Z' }),
    })
    const lines = await printed(() => runMsg({}, 'read', ['m-1', 'm-2'], caller))
    expect(calls).toEqual([{ method: 'inbox.mark_read', body: { message_ids: ['m-1', 'm-2'] } }])
    expect(fieldOf(lines, 'read at:')).toBe('2026-10-01T12:30:00.000Z')
  })
})
