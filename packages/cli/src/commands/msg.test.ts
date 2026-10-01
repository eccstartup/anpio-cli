// `msg send` decides what a message body is before it decides anything else, and that
// decision is where the Profile's body rules live (P3 §6.2, §6.3). It is also the only
// part of the command a test can reach without a peer: everything past it needs a store,
// a DID document and a live service endpoint.

import { describe, it, expect } from 'vitest'
import { ConnectxError } from '@agentx/core'
import { payloadOf, runMsg } from './msg'
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
    const err = await fails(() => runMsg(body({ text: 'hi', 'content-type': 'application/json' }), 'send', undefined))
    expect(err.code).toBe('invalid_argument')
    expect(err.message).toContain('--body')
  })

  it('refuses an object body sent as text/plain', async () => {
    // The mirror image: text/plain has a body shape too, and it is `text` (§6.2.4 L262).
    const err = await fails(() => runMsg(body({ body: '{}', 'content-type': 'text/plain' }), 'send', undefined))
    expect(err.code).toBe('invalid_argument')
    expect(err.message).toContain('--text')
  })

  it('refuses both spellings at once, and neither', async () => {
    // §6.3: exactly ONE of the three body fields. Two spellings of one field is the same
    // violation from the other side.
    expect((await fails(() => runMsg(body({ text: 'hi', body: '{}' }), 'send', undefined))).code).toBe(
      'invalid_argument',
    )
    expect((await fails(() => runMsg(body({}), 'send', undefined))).code).toBe('missing_flag')
  })

  it('refuses a --body that is not a JSON object', async () => {
    // `payload` is typed as a JSON object (§6.2.5 L266), so an array or a scalar has
    // nowhere to go: `text` is the field for a bare string.
    for (const raw of ['[1,2]', '"hi"', '3', 'null']) {
      const err = await fails(() => runMsg(body({ body: raw }), 'send', undefined))
      expect(err.code, raw).toBe('invalid_argument')
    }
  })

  it('refuses an unparsable --body', async () => {
    expect((await fails(() => runMsg(body({ body: '{"a":' }), 'send', undefined))).code).toBe('invalid_argument')
  })

  it('refuses a send with no recipient', async () => {
    const err = await fails(() => runMsg({ text: 'hi' }, 'send', undefined))
    expect(err.code).toBe('missing_flag')
    expect(err.message).toContain('--to')
  })

  it('checks the body before it reaches for an identity', async () => {
    // Ordering, asserted rather than assumed: `payloadOf` runs second, so a refused body
    // is reported as a refusal even on a machine with no identity stored and no network.
    // Were the identity resolved first, this would come back as a store error instead.
    const err = await fails(() => runMsg(body({ text: 'hi', body: '{}' }), 'send', undefined))
    expect(err.code).toBe('invalid_argument')
  })
})

describe('msg caps argument validation', () => {
  it('refuses a probe with no DID', async () => {
    expect((await fails(() => runMsg({}, 'caps', undefined))).code).toBe('missing_flag')
    expect((await fails(() => runMsg({}, 'caps', ''))).code).toBe('missing_flag')
  })

  it('refuses an account id as the thing to probe, and says why', async () => {
    // TODO1 B7. The refusal belongs to the locator: an account id names no service
    // endpoint anywhere, which is a different fact from "this DID document has no
    // ANPMessageService in it", and it is answered before any fetch is attempted. The
    // command layer never asks what kind of identifier it is holding.
    const err = await fails(() => runMsg({}, 'caps', 'eip155:1:0x0000000000000000000000000000000000000001'))
    expect(err.code).toBe('caip10_has_no_ingress')
  })
})

describe('msg dispatch', () => {
  it('refuses a subcommand it does not have', async () => {
    await expect(runMsg({}, 'inbox', undefined)).rejects.toThrow(/No subcommand "inbox"/)
  })
})
