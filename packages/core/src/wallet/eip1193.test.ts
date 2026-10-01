// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { chainWallet, ethPersonalSignHash } from './eip1193'

// Account-switch lifecycle: after a provider emits accountsChanged / chainChanged /
// disconnect, the wallet must NOT keep using the previous account's cached public
// key or address. Otherwise an identity document could describe account A while the
// wallet signs for account B.

const PRIV_A = new Uint8Array(Array.from({ length: 32 }, () => 0x11))
const PRIV_B = new Uint8Array(Array.from({ length: 32 }, () => 0x22))

// The address each private key ACTUALLY derives — not a fabricated string. The
// address-binding check (`ethAddressFromPublicKey`) requires these to be real,
// otherwise every recovered key would fail to match its reported account.
function evmAddress(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false)
  const hash = keccak_256(pub.slice(1))
  return '0x' + Array.from(hash.slice(-20)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

const ADDR_A = evmAddress(PRIV_A)
const ADDR_B = evmAddress(PRIV_B)

function toHex(bytes: Uint8Array): string {
  return '0x' + Buffer.from(bytes).toString('hex')
}

function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.replace(/^0x/i, ''), 'hex'))
}

// Sign a message with a private key, returning the 65-byte recoverable signature.
function signWithKey(priv: Uint8Array, message: Uint8Array): string {
  const hash = ethPersonalSignHash(message)
  const sig = secp256k1.sign(hash, priv, { prehash: false })
  const pub = secp256k1.getPublicKey(priv, false)
  const sigObj = secp256k1.Signature.fromBytes(sig)
  for (const rec of [0, 1]) {
    const point = sigObj.addRecoveryBit(rec).recoverPublicKey(hash)
    if (Buffer.from(point.toBytes(false)).equals(Buffer.from(pub))) {
      const out = new Uint8Array(65)
      out.set(sig, 0)
      out[64] = rec + 27
      return toHex(out)
    }
  }
  throw new Error('could not recover pubkey')
}

// A fake provider holding one private key per address. `personal_sign` signs with
// the key of the requested address, so the recovered pubkey reveals which account
// the wallet actually used — letting us assert the wallet follows account switches.
function fakeProvider() {
  const keys: Record<string, Uint8Array> = { [ADDR_A]: PRIV_A, [ADDR_B]: PRIV_B }
  const listeners: Record<string, ((...args: unknown[]) => void)[]> = {}
  const emit = (event: string, ...args: unknown[]) =>
    (listeners[event] ?? []).forEach((f) => f(...args))

  const provider = {
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      if (method === 'eth_chainId') return '0x1'
      if (method === 'personal_sign') {
        const [msg, addr] = params as [string, string]
        const priv = keys[addr]
        if (!priv) throw new Error(`no key for ${addr}`)
        return signWithKey(priv, fromHex(msg))
      }
      throw new Error(`fake-provider: unhandled method ${method}`)
    },
    on(event: string, fn: (...args: unknown[]) => void) {
      ;(listeners[event] ??= []).push(fn)
    },
    removeListener(event: string, fn: (...args: unknown[]) => void) {
      listeners[event] = (listeners[event] ?? []).filter((f) => f !== fn)
    },
  }
  return { provider, emit }
}

describe('chainWallet — account switch lifecycle (3.4)', () => {
  it('re-recovers the public key after accountsChanged (cache invalidation)', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A, chainId: 'eip155:1' })

    const keyA = await wallet.getPublicKey()
    const accountA = await wallet.getAccount?.()
    expect(accountA?.address).toBe(ADDR_A)

    // Switch account under the same provider.
    emit('accountsChanged', [ADDR_B])

    const keyB = await wallet.getPublicKey()
    expect(Buffer.from(keyB).equals(Buffer.from(keyA))).toBe(false)
    expect((await wallet.getAccount?.())?.address).toBe(ADDR_B)
  })

  it('targets the new account for signatures after a switch', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    await wallet.getPublicKey()

    emit('accountsChanged', [ADDR_B])
    const sig = await wallet.signMessage(new TextEncoder().encode('hello'))
    // The recovered pubkey from this signature must be B's, not A's.
    const recovered = secp256k1.getPublicKey(PRIV_B, true)
    expect(sig).toBeDefined()
    expect((await wallet.getAccount?.())?.address).toBe(ADDR_B)
    // Verify the signature belongs to B's key over the personal-sign hash.
    const pubB = secp256k1.Signature.fromBytes(sig.slice(0, 64))
      .addRecoveryBit(sig[64] - 27)
      .recoverPublicKey(ethPersonalSignHash(new TextEncoder().encode('hello')))
    expect(Buffer.from(pubB.toBytes(true)).equals(Buffer.from(recovered))).toBe(true)
  })

  it('re-recovers the public key after chainChanged', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    const keyA = await wallet.getPublicKey()
    emit('chainChanged', '0x89')
    const keyAfter = await wallet.getPublicKey()
    // Same address but the cache was invalidated — still recovers A's key (identical).
    expect(Buffer.from(keyAfter).equals(Buffer.from(keyA))).toBe(true)
    expect((await wallet.getAccount?.())?.chainId).toBe('0x89')
  })

  it('fails loudly when the provider is disconnected (no active account)', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    await wallet.getPublicKey()
    emit('accountsChanged', [])
    await expect(wallet.getPublicKey()).rejects.toThrow(/not connected/)
  })

  it('rejects an invalid hex signature', async () => {
    const { provider } = fakeProvider()
    // A provider that returns a non-hex signature value.
    const badProvider = {
      ...provider,
      async request({ method }: { method: string }): Promise<unknown> {
        if (method === 'personal_sign') return '0xzzzz'
        throw new Error('unhandled')
      },
    }
    const wallet = chainWallet(badProvider, { address: ADDR_A })
    await expect(wallet.getPublicKey()).rejects.toThrow(/hex/)
  })

  it('uses the FIRST (active) account, not the last, when multiple accounts are reported', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    await wallet.getPublicKey()

    // EIP-1193 lists the active account first; ADDR_B is active here.
    emit('accountsChanged', [ADDR_B, ADDR_A])

    expect((await wallet.getAccount?.())?.address).toBe(ADDR_B)
    const sig = await wallet.signMessage(new TextEncoder().encode('hello'))
    // The signature must belong to B (the active account), not A.
    const recovered = secp256k1.Signature.fromBytes(sig.slice(0, 64))
      .addRecoveryBit(sig[64] - 27)
      .recoverPublicKey(ethPersonalSignHash(new TextEncoder().encode('hello')))
    expect(Buffer.from(recovered.toBytes(true)).equals(Buffer.from(secp256k1.getPublicKey(PRIV_B, true)))).toBe(true)
  })

  it('fails signing after accountsChanged to an empty list (all operations throw)', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    emit('accountsChanged', [])
    await expect(wallet.signMessage(new TextEncoder().encode('hello'))).rejects.toThrow(/not connected/)
  })

  // A provider whose personal_sign does not resolve until the test says so, letting
  // us inject an accountsChanged event DURING the in-flight request (ANP-2026-09-08-02).
  function deferredProvider() {
    let resolveSign!: (v: unknown) => void
    const listeners: Record<string, ((...args: unknown[]) => void)[]> = {}
    const emit = (event: string, ...args: unknown[]) =>
      (listeners[event] ?? []).forEach((f) => f(...args))
    const provider = {
      async request({ method }: { method: string }): Promise<unknown> {
        if (method === 'personal_sign') {
          return new Promise((resolve) => {
            resolveSign = resolve
          })
        }
        throw new Error(`unhandled ${method}`)
      },
      on(event: string, fn: (...args: unknown[]) => void) {
        ;(listeners[event] ??= []).push(fn)
      },
      removeListener() {},
    }
    return { provider, emit, resolveSign: (v: unknown) => resolveSign(v) }
  }

  it('discards the recovered key when the account switches during getPublicKey', async () => {
    const { provider, emit, resolveSign } = deferredProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    const pending = wallet.getPublicKey() // personal_sign is now in-flight
    emit('accountsChanged', [ADDR_B]) // switch account while waiting
    // The probe asked account A to sign; resolve with A's key post-switch.
    resolveSign(signWithKey(PRIV_A, new TextEncoder().encode('connectx:key-recovery')))
    await expect(pending).rejects.toThrow(/changed during signing/)
  })

  it('rejects a signature when the account changes during signMessage', async () => {
    const { provider, emit, resolveSign } = deferredProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    const pending = wallet.signMessage(new TextEncoder().encode('hello'))
    emit('accountsChanged', [ADDR_B])
    resolveSign(signWithKey(PRIV_A, new TextEncoder().encode('hello')))
    await expect(pending).rejects.toThrow(/changed during signing/)
  })
})

describe('chainWallet — address/key binding (3.2)', () => {
  // A provider that reports ADDR_A but signs with ADDR_B's key, ignoring the
  // `address` in personal_sign. A tampering/compromised provider would do this.
  function misbindingProvider(provider: ReturnType<typeof fakeProvider>['provider']) {
    return {
      ...provider,
      async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
        if (method === 'personal_sign') {
          const [msg] = params as [string, string]
          return signWithKey(PRIV_B, fromHex(msg))
        }
        throw new Error('unhandled')
      },
    }
  }

  it('rejects a recovered public key that does not match the reported address', async () => {
    const { provider } = fakeProvider()
    const wallet = chainWallet(misbindingProvider(provider), { address: ADDR_A })
    await expect(wallet.getPublicKey()).rejects.toThrow(/does not match/)
  })

  it('rejects a signMessage signature produced by a different account', async () => {
    const { provider } = fakeProvider()
    const wallet = chainWallet(misbindingProvider(provider), { address: ADDR_A })
    await expect(wallet.signMessage(new TextEncoder().encode('hello'))).rejects.toThrow(
      /different account/,
    )
  })

  it('accepts a signature when the recovered key matches the account', async () => {
    const { provider } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDR_A })
    const sig = await wallet.signMessage(new TextEncoder().encode('hello'))
    expect(sig).toBeDefined()
    expect(sig.length).toBe(65)
  })
})
