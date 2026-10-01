// At-rest codec for the session store: round-trip, authentication (wrong password
// / tampering), and read-side caps.

import { describe, it, expect } from 'vitest'
import { sealSecret, openSecret } from './secret'

const PW = 'secret-test-password'

function envelope(env: string): { ciphertext: string; kdfparams: Record<string, unknown> } {
  return JSON.parse(env)
}

describe('sealSecret / openSecret', () => {
  it('round-trips an arbitrary-length string', async () => {
    const plain = JSON.stringify({
      version: 1,
      sessions: { 'localhost:3000': { token: 'a.b.c', did: 'did:wba:x', issuedAt: 'i', expiresAt: 'e' } },
    })
    expect(await openSecret(await sealSecret(plain, PW), PW)).toBe(plain)
  })

  it('wrong password → session_invalid', async () => {
    const env = await sealSecret('hello', PW)
    await expect(openSecret(env, 'nope')).rejects.toMatchObject({ code: 'session_invalid' })
  })

  it('tampered ciphertext → session_invalid', async () => {
    const obj = envelope(await sealSecret('hello', PW))
    obj.ciphertext = (obj.ciphertext.startsWith('00') ? '11' : '00') + obj.ciphertext.slice(2)
    await expect(openSecret(JSON.stringify(obj), PW)).rejects.toMatchObject({ code: 'session_invalid' })
  })

  it('tampered GCM tag → session_invalid', async () => {
    const obj = envelope(await sealSecret('hello', PW))
    const tail = obj.ciphertext.slice(-2)
    obj.ciphertext = obj.ciphertext.slice(0, -2) + (tail === '00' ? '11' : '00')
    await expect(openSecret(JSON.stringify(obj), PW)).rejects.toMatchObject({ code: 'session_invalid' })
  })

  it('rejects a hostile kdf param before doing the work', async () => {
    const obj = envelope(await sealSecret('hello', PW))
    obj.kdfparams.n = 2 ** 30
    await expect(openSecret(JSON.stringify(obj), PW)).rejects.toMatchObject({ code: 'session_invalid' })
  })

  it('rejects non-JSON and unsupported versions', async () => {
    await expect(openSecret('not json', PW)).rejects.toMatchObject({ code: 'session_invalid' })
    await expect(openSecret(JSON.stringify({ version: 2 }), PW)).rejects.toMatchObject({ code: 'session_invalid' })
  })
})
