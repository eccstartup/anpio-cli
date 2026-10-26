import { describe, expect, it } from 'vitest'
import { createRateLimiter } from './rateLimit'

describe('token refill accounting', () => {
  it('does not mint extra tokens during repeated denied retries', () => {
    const limiter = createRateLimiter({ burst: 1, perMinute: 60 })
    expect(limiter.take('caller', 0).allowed).toBe(true)
    for (let at = 10; at < 1000; at += 10) {
      expect(limiter.take('caller', at).allowed, `retry at ${at}ms`).toBe(false)
    }
    expect(limiter.take('caller', 1001).allowed).toBe(true)
    expect(limiter.take('caller', 1001).allowed).toBe(false)
  })

  it('does not refill twice if the wall clock moves backwards', () => {
    const limiter = createRateLimiter({ burst: 1, perMinute: 60 })
    expect(limiter.take('caller', 1000).allowed).toBe(true)
    expect(limiter.take('caller', 1500).allowed).toBe(false)
    expect(limiter.take('caller', 1200).allowed).toBe(false)
    expect(limiter.take('caller', 1500).allowed).toBe(false)
    expect(limiter.take('caller', 2000).allowed).toBe(true)
    expect(limiter.take('other', 1500).allowed).toBe(true)
  })
})
