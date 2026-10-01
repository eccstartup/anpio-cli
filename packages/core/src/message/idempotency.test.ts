import { describe, it, expect } from 'vitest'
import type { AnpMeta } from './envelope'
import {
  idempotencyKey,
  idempotencyScopeFromMeta,
  idempotencyVerdict,
  type IdempotencyRecord,
} from './idempotency'

const scope = {
  senderDid: 'did:wba:alice.example:user:alice:e1_a',
  targetScope: 'did:wba:bob.example:user:bob:e1_b',
  method: 'direct.send',
  operationId: 'op-1',
}

describe('idempotencyKey', () => {
  it('is stable for the same scope', () => {
    expect(idempotencyKey(scope)).toBe(idempotencyKey({ ...scope }))
  })

  it('changes when any component changes', () => {
    const base = idempotencyKey(scope)
    expect(idempotencyKey({ ...scope, senderDid: 'did:wba:x' })).not.toBe(base)
    expect(idempotencyKey({ ...scope, targetScope: 'did:wba:y' })).not.toBe(base)
    expect(idempotencyKey({ ...scope, method: 'group.send' })).not.toBe(base)
    expect(idempotencyKey({ ...scope, operationId: 'op-2' })).not.toBe(base)
  })

  it('cannot be forged by moving a separator between fields', () => {
    // Plain `join('|')` would collide these two. A collision here means a NEW request
    // is answered with a REPLAY's response.
    const a = idempotencyKey({ ...scope, senderDid: 'a|b', targetScope: 'c' })
    const b = idempotencyKey({ ...scope, senderDid: 'a', targetScope: 'b|c' })
    expect(a).not.toBe(b)
  })

  it('excludes device selectors for base operations but includes them for E2EE', () => {
    const base = idempotencyKey(scope)
    expect(idempotencyKey({ ...scope, deviceSelectors: [] })).toBe(base)
    expect(idempotencyKey({ ...scope, deviceSelectors: ['dev-1'] })).not.toBe(base)
  })

  it('treats the same device set in a different order as the same key', () => {
    expect(idempotencyKey({ ...scope, deviceSelectors: ['b', 'a'] })).toBe(
      idempotencyKey({ ...scope, deviceSelectors: ['a', 'b'] }),
    )
  })

  it('refuses an empty operation_id', () => {
    expect(() => idempotencyKey({ ...scope, operationId: '' })).toThrow(/operation_id is required/)
  })
})

describe('idempotencyVerdict', () => {
  const record: IdempotencyRecord = {
    key: 'k',
    fingerprint: 'sha-256=:aaa:',
    response: { accepted: true },
    createdAt: '2026-10-01T00:00:00Z',
  }

  it('is new when there is no record', () => {
    expect(idempotencyVerdict(undefined, 'sha-256=:bbb:')).toEqual({ kind: 'new' })
  })

  it('replays the stored response for an equivalent retry', () => {
    expect(idempotencyVerdict(record, 'sha-256=:aaa:')).toEqual({
      kind: 'replay',
      response: { accepted: true },
    })
  })

  it('conflicts when the same key carries different semantics', () => {
    expect(idempotencyVerdict(record, 'sha-256=:bbb:')).toEqual({
      kind: 'conflict',
      code: 'anp.idempotency_conflict',
    })
  })
})

describe('idempotencyScopeFromMeta', () => {
  const meta: AnpMeta = {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: 'did:wba:alice.example:user:alice:e1_a',
    operation_id: 'op-1',
  }

  it('builds a scope from the request as written', () => {
    expect(idempotencyScopeFromMeta({ meta, targetScope: 'did:wba:bob', method: 'direct.send' })).toEqual({
      senderDid: 'did:wba:alice.example:user:alice:e1_a',
      targetScope: 'did:wba:bob',
      method: 'direct.send',
      operationId: 'op-1',
    })
  })

  it('refuses a missing sender_did or operation_id', () => {
    const noSender = { ...meta }
    delete noSender.sender_did
    expect(() => idempotencyScopeFromMeta({ meta: noSender, targetScope: 'x', method: 'm' })).toThrow(
      /sender_did is required/,
    )

    const noOp = { ...meta }
    delete noOp.operation_id
    expect(() => idempotencyScopeFromMeta({ meta: noOp, targetScope: 'x', method: 'm' })).toThrow(
      /operation_id is required/,
    )
  })
})
