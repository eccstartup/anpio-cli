import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { idempotencyKey } from '@agentx/core'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import { acceptOperation } from './accept'

let storage: Storage

beforeEach(() => {
  storage = openStorage({ path: ':memory:' })
})

afterEach(() => {
  storage.close()
})

const SENDER = 'did:web:sender.example'
const TARGET = 'did:web:receiver.example'

/** The key a Direct send produces. `target_scope` is the method table's business (C5);
 *  here it is just a value that makes the key. */
function keyFor(operationId: string, sender = SENDER): string {
  return idempotencyKey({
    senderDid: sender,
    targetScope: TARGET,
    method: 'direct.send',
    operationId,
  })
}

/** A message row plus a delivery, i.e. the two writes §8.1 puts in one transaction. The
 *  delivery goes through an accessor that opens a transaction of its own, which is what
 *  makes this a re-entrancy test as much as an atomicity one. */
function writeMessage(messageId: string): Record<string, unknown> {
  storage.insertMessage({
    messageId,
    senderDid: SENDER,
    targetDid: TARGET,
    profile: 'anp.direct.base.v1',
    securityProfile: 'transport-protected',
    contentType: 'text/plain',
    bodyJson: '{"text":"hi"}',
    acceptedAt: '2026-10-01T00:00:00Z',
  })
  storage.appendDelivery({
    ownerDid: TARGET,
    messageId,
    method: 'direct.incoming',
    paramsJson: '{"body":{}}',
    acceptedAt: '2026-10-01T00:00:00Z',
  })
  return { accepted: true, message_id: messageId }
}

const RESULT = { accepted: true, message_id: 'm-1' }

describe('acceptOperation', () => {
  it('runs the operation on the first call and records its result', () => {
    const perform = vi.fn(() => RESULT)
    const outcome = acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-1', perform })

    expect(outcome.kind).toBe('new')
    if (outcome.kind === 'conflict') return
    expect(outcome.response).toEqual(RESULT)
    expect(perform).toHaveBeenCalledTimes(1)
    expect(storage.idempotentRow(keyFor('op-1'))?.responseJson).toBe(JSON.stringify(RESULT))
  })

  it('returns the recorded result for a repeat and does not run the operation again', () => {
    acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-1', perform: () => RESULT })

    const perform = vi.fn(() => ({ accepted: true, message_id: 'm-different' }))
    const outcome = acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-1', perform })

    expect(outcome.kind).toBe('replay')
    if (outcome.kind === 'conflict') return
    expect(outcome.response).toEqual(RESULT)
    // §9.1 L630: the same result, and no second delivery — `perform` is where delivery
    // happens, so not calling it is the whole mechanism.
    expect(perform).not.toHaveBeenCalled()
  })

  it('reports a conflict when the same key carries a different payload', () => {
    acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-1', perform: () => RESULT })

    const perform = vi.fn(() => RESULT)
    const outcome = acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-2', perform })

    expect(outcome.kind).toBe('conflict')
    if (outcome.kind !== 'conflict') return
    // §10.3 L709. Profile-less, so it is P1's own code and not a Profile segment.
    expect(outcome.error.code).toBe(1008)
    expect(outcome.error.anpCode).toBe('anp.idempotency_conflict')
    expect(outcome.error.retryable).toBe(false)
    expect(perform).not.toHaveBeenCalled()
  })

  it('keeps different keys independent', () => {
    acceptOperation({ storage, key: keyFor('op-1'), fingerprint: 'fp-1', perform: () => RESULT })
    const outcome = acceptOperation({
      storage,
      key: keyFor('op-2'),
      fingerprint: 'fp-1',
      perform: () => ({ accepted: true, message_id: 'm-2' }),
    })
    expect(outcome.kind).toBe('new')
  })

  it('writes a message and its delivery inside the operation transaction', () => {
    const outcome = acceptOperation({
      storage,
      key: keyFor('op-1'),
      fingerprint: 'fp-1',
      perform: () => writeMessage('m-1'),
    })

    expect(outcome.kind).toBe('new')
    expect(storage.message('m-1')).toBeDefined()
    // The delivery accessor runs a transaction of its own; if it had not joined the
    // enclosing one, the row would still be here — but see the rollback test below,
    // which is what actually distinguishes the two.
    expect(storage.headSeq(TARGET)).toBe(1)
  })

  it('leaves nothing behind when the operation fails', () => {
    // The mid-operation failure, which is the case §8.1's "one transaction" exists for:
    // a message row without its delivery, or an idempotency record for an operation that
    // never completed, would make a retry answer wrongly.
    expect(() =>
      acceptOperation({
        storage,
        key: keyFor('op-1'),
        fingerprint: 'fp-1',
        perform: () => {
          writeMessage('m-1')
          throw new Error('delivery target refused')
        },
      }),
    ).toThrow('delivery target refused')

    expect(storage.message('m-1')).toBeUndefined()
    expect(storage.headSeq(TARGET)).toBe(0)
    expect(storage.idempotentRow(keyFor('op-1'))).toBeUndefined()
  })

  it('can be used again after a failed operation, because nothing was recorded', () => {
    const key = keyFor('op-1')
    expect(() =>
      acceptOperation({
        storage,
        key,
        fingerprint: 'fp-1',
        perform: () => {
          throw new Error('nope')
        },
      }),
    ).toThrow()

    const outcome = acceptOperation({ storage, key, fingerprint: 'fp-1', perform: () => RESULT })
    expect(outcome.kind).toBe('new')
  })

  it('replays an old DID request instead of letting a supersession check refuse it', () => {
    // §9.1 L641: a receiver that would refuse with "DID superseded" MUST first look for the
    // exact record under the OLD DID and return the original result if it is there. The
    // ordering is structural — `perform` is only reached on a miss — so an operation that
    // refuses by throwing inside `perform` cannot pre-empt the lookup.
    const key = keyFor('op-1')
    acceptOperation({ storage, key, fingerprint: 'fp-1', perform: () => RESULT })

    const perform = vi.fn(() => {
      throw new Error('anp.did_superseded')
    })
    const outcome = acceptOperation({ storage, key, fingerprint: 'fp-1', perform })

    expect(outcome.kind).toBe('replay')
    if (outcome.kind === 'conflict') return
    expect(outcome.response).toEqual(RESULT)
    expect(perform).not.toHaveBeenCalled()
  })

  it('does not treat a successor DID as an exact replay of the old one', () => {
    // §9.1 L641's second half: a request signed by the successor DID is NOT an exact replay
    // of an old-DID request. The key carries the DID the request names, so the two cannot
    // collide — which is exactly why the key must never be recomputed under the successor
    // before the lookup.
    const oldKey = keyFor('op-1', 'did:web:old.example')
    const newKey = keyFor('op-1', 'did:web:new.example')
    expect(newKey).not.toBe(oldKey)

    acceptOperation({ storage, key: oldKey, fingerprint: 'fp-1', perform: () => RESULT })
    const outcome = acceptOperation({
      storage,
      key: newKey,
      fingerprint: 'fp-1',
      perform: () => ({ accepted: true, message_id: 'm-from-successor' }),
    })
    expect(outcome.kind).toBe('new')
  })

  it('stamps the record from the injected clock', () => {
    acceptOperation({
      storage,
      key: keyFor('op-1'),
      fingerprint: 'fp-1',
      perform: () => RESULT,
      now: () => '2026-10-01T12:00:00Z',
    })
    expect(storage.idempotentRow(keyFor('op-1'))?.createdAt).toBe('2026-10-01T12:00:00Z')
  })

  it('re-throws rather than storing a response when the operation throws', () => {
    const boom = new Error('boom')
    expect(() =>
      acceptOperation({
        storage,
        key: keyFor('op-1'),
        fingerprint: 'fp-1',
        perform: () => {
          throw boom
        },
      }),
    ).toThrow(boom)
    expect(storage.idempotentRow(keyFor('op-1'))).toBeUndefined()
  })
})
