// At-rest key codec: round-trip both curves, reject the wrong password / tampered
// ciphertext, and prove the secp256k1 output is a *standard* keystore V3 that the
// SDK's own `parseKeystore` can read (that interop test is what keeps this codec
// from drifting away from the core format).

import { describe, it, expect, beforeAll } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { parseKeystore } from '@agentx/core'
import { encryptPrivateKey, decryptPrivateKey } from './keystore'

const PASSWORD = 'correct horse battery staple'

describe('keystore codec', () => {
  it('round-trips an ed25519 key', async () => {
    const key = ed25519.utils.randomSecretKey()
    const sealed = await encryptPrivateKey(key, PASSWORD)
    expect(await decryptPrivateKey(sealed, PASSWORD)).toEqual(key)
  })

  it('round-trips a secp256k1 key', async () => {
    const key = secp256k1.utils.randomSecretKey()
    const sealed = await encryptPrivateKey(key, PASSWORD)
    expect(await decryptPrivateKey(sealed, PASSWORD)).toEqual(key)
  })

  describe('rejects bad input', () => {
    let sealed: string
    let key: Uint8Array

    beforeAll(async () => {
      key = secp256k1.utils.randomSecretKey()
      sealed = await encryptPrivateKey(key, PASSWORD)
    })

    it('wrong password → key_wrong_password', async () => {
      await expect(decryptPrivateKey(sealed, 'not the password')).rejects.toMatchObject({
        code: 'key_wrong_password',
      })
    })

    it('tampered ciphertext → key_wrong_password (MAC catches it)', async () => {
      const obj = JSON.parse(sealed) as { crypto: { ciphertext: string } }
      const ct = obj.crypto.ciphertext
      // Flip the first ciphertext nibble.
      obj.crypto.ciphertext = (ct[0] === '0' ? '1' : '0') + ct.slice(1)
      await expect(decryptPrivateKey(JSON.stringify(obj), PASSWORD)).rejects.toMatchObject({
        code: 'key_wrong_password',
      })
    })

    it('non-JSON → key_invalid', async () => {
      await expect(decryptPrivateKey('not json', PASSWORD)).rejects.toMatchObject({ code: 'key_invalid' })
    })
  })

  it('emits a keystore V3 the SDK can read (secp256k1 interop)', async () => {
    const key = secp256k1.utils.randomSecretKey()
    const sealed = await encryptPrivateKey(key, PASSWORD)
    const parsed = await parseKeystore(sealed, PASSWORD)
    expect(parsed.curve).toBe('secp256k1')
    expect(parsed.privateKey).toEqual(key)
  })
})
