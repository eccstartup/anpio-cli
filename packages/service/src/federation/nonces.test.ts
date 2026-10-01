import { describe, expect, it } from 'vitest'
import { openStorage } from '../storage/sqlite'
import { createHttpNonceStore } from './nonces'

describe('createHttpNonceStore', () => {
  it('consumes a pair once and refuses the second attempt', () => {
    const s = openStorage({ path: ':memory:' })
    const store = createHttpNonceStore(s, { now: () => new Date('2026-10-01T12:00:00Z') })
    expect(store.consume('did:web:a.example#k1', 'n-1')).toBe(true)
    expect(store.consume('did:web:a.example#k1', 'n-1')).toBe(false)
    s.close()
  })

  it('keeps two DIDs apart: one replay never burns another DID challenge', () => {
    const s = openStorage({ path: ':memory:' })
    const store = createHttpNonceStore(s, { now: () => new Date('2026-10-01T12:00:00Z') })
    expect(store.consume('did:web:a.example#k1', 'shared')).toBe(true)
    // 同一个 nonce、另一个 keyid：这是另一对，不构成重放。拿裸 nonce 当键就会在这里
    // 错误地返回 false——那等于 a 域能把 b 域从没用过的挑战烧掉。
    expect(store.consume('did:web:b.example#k1', 'shared')).toBe(true)
    s.close()
  })

  it('forgets a pair once its window has passed', () => {
    const s = openStorage({ path: ':memory:' })
    let at = new Date('2026-10-01T12:00:00Z')
    const store = createHttpNonceStore(s, { ttlMs: 1_000, now: () => at })
    expect(store.consume('did:web:a.example#k1', 'n-1')).toBe(true)
    expect(store.consume('did:web:a.example#k1', 'n-1')).toBe(false)
    at = new Date(at.getTime() + 2_000)
    // 过期之后这一对不再代表任何事：签名能被重放的窗口早就过去了，所以它能被重新兑。
    expect(store.consume('did:web:a.example#k1', 'n-1')).toBe(true)
    s.close()
  })
})
