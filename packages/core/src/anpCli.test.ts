// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { keypairWallet, chainWalletConnector } from './protocol/adapters/chain'
import { chainWallet } from './wallet/eip1193'
import { anpCli } from './connectors/anpCli'
import { login } from './actions'
import { createConfig } from './config'
import { verifyHttpMessageSignature } from './crypto/verify'
import { decodeMultibaseKey } from './crypto/multicodec'
import { base64UrlToBytes } from './crypto/encoding'
import { ethPersonalSignHash } from './wallet/eip1193'
import type { AnpConnector } from './types'

const HOST = '127.0.0.1'
const FRESH = 'fresh-nonce-e2e'
const PATH = '/api/login/anp/verify'

// Shared deterministic secp256k1 key (matches the CLI e2e).
const PRIV = new Uint8Array(Array.from({ length: 32 }, () => 0x22))
const ADDRESS = '0x1563915e194d8cfba1943570603f7606a3115508'
const CHAIN_ID = 'eip155:1'

function evmAddress(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false)
  const hash = keccak_256(pub.slice(1))
  return '0x' + Array.from(hash.slice(-20)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function toHex(bytes: Uint8Array): string {
  return '0x' + Buffer.from(bytes).toString('hex')
}
function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.replace(/^0x/i, ''), 'hex'))
}

// A fake EIP-1193 provider: holds a private key (so the wallet signs without the
// agent touching it), returns a valid 65-byte recoverable personal_sign, and lets
// the test dispatch `accountsChanged`/`chainChanged`/`disconnect`.
function fakeProvider() {
  const listeners: Record<string, ((...args: unknown[]) => void)[]> = {}
  const emit = (event: string, ...args: unknown[]) =>
    (listeners[event] ?? []).forEach((f) => f(...args))

  function recoverableSig(message: Uint8Array): string {
    const hash = ethPersonalSignHash(message)
    const sig = secp256k1.sign(hash, PRIV, { prehash: false })
    const pub = secp256k1.getPublicKey(PRIV, false)
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
    throw new Error('fake-provider: could not recover pubkey')
  }

  const provider = {
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      if (method === 'eth_chainId') return '0x1'
      if (method === 'eth_requestAccounts') return [ADDRESS]
      if (method === 'personal_sign') return recoverableSig(fromHex(params![0] as string))
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

// The server plays agent-world's /verify: it resolves the key from the inlined
// DID document, verifies the RFC 9421 signature, and re-challenges stale nonces.
function extractHeaders(headers: IncomingMessage['headers']): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) if (typeof v === 'string') out[k.toLowerCase()] = v
  return out
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = ''
    req.on('data', (c) => (data += c))
    req.on('end', () => resolve(data))
  })
}

/** Read the binding key out of a served DID document, in whichever representation that
 *  profile publishes (Appendix A A.4): `Multikey` + multibase for Ed25519, a secp256k1
 *  `publicKeyJwk` for `k1_`. This server stands in for a verifier, so it has to read
 *  what a producer writes — two shapes, one document. */
function keyFromDocument(didDocument: unknown): ReturnType<typeof decodeMultibaseKey> {
  const vm = (didDocument as {
    verificationMethod: Array<{ publicKeyMultibase?: string; publicKeyJwk?: { x: string; y: string } }>
  }).verificationMethod[0]
  if (vm.publicKeyMultibase != null) return decodeMultibaseKey(vm.publicKeyMultibase)
  const { x, y } = vm.publicKeyJwk!
  const uncompressed = new Uint8Array(65)
  uncompressed[0] = 0x04
  uncompressed.set(base64UrlToBytes(x), 1)
  uncompressed.set(base64UrlToBytes(y), 33)
  // The compressed point is what the signature verifier takes (and what the `k1_`
  // fingerprint is computed over).
  return { curve: 'secp256k1', bytes: secp256k1.Point.fromBytes(uncompressed).toBytes(true) }
}

async function startServer(): Promise<{ port: number; targetUri: string; close: () => void }> {
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== 'POST' || req.url !== PATH) {
      res.statusCode = 404
      res.end()
      return
    }
    const port = (server.address() as { port: number }).port
    const authority = `${HOST}:${port}`
    const targetUri = `http://${authority}${PATH}`
    const body = await readBody(req)
    const parsed = JSON.parse(body) as { nonce: string; didDocument: unknown }
    const key = keyFromDocument(parsed.didDocument)

    const ok = await verifyHttpMessageSignature({
      method: 'POST',
      path: PATH,
      authority,
      targetUri,
      headers: extractHeaders(req.headers),
      body,
      key,
    })
    if (!ok) {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'bad_signature' }))
      return
    }
    if (parsed.nonce === FRESH) {
      res.writeHead(200, { 'content-type': 'application/json', 'authentication-info': 'access_token="tok_e2e_cli"' })
      res.end(JSON.stringify({ did: parsed.nonce, token: 'tok_e2e_cli' }))
      return
    }
    res.writeHead(401, { 'www-authenticate': `didwba nonce="${FRESH}", error="invalid_nonce"` })
    res.end(JSON.stringify({ error: 'crypto-required' }))
  })

  await new Promise<void>((resolve) => server.listen(0, HOST, resolve))
  const port = (server.address() as { port: number }).port
  return { port, targetUri: `http://${HOST}:${port}${PATH}`, close: () => server.close() }
}

async function loginThrough(
  connector: AnpConnector,
  targetUri: string,
): Promise<{ token?: string; did: string }> {
  const config = createConfig([connector], connector.id)
  const outcome = await login(config, { connectorId: connector.id, nonce: 'stale', targetUri })
  return { token: outcome.token, did: outcome.did }
}

describe('anpCli login e2e (local key path)', () => {
  it('signs, re-signs on 401, and returns a token + CAIP-10 DID', async () => {
    const { targetUri, close } = await startServer()
    try {
      const wallet = keypairWallet(PRIV, { curve: 'secp256k1' })
      const connector = anpCli(wallet, { host: HOST, chainId: CHAIN_ID, address: ADDRESS })
      const { token, did } = await loginThrough(connector, targetUri)
      expect(token).toBe('tok_e2e_cli')
      expect(did).toBe(`${CHAIN_ID}:${ADDRESS}`)
    } finally {
      close()
    }
  })

  it('forms a CAIP-10 DID when an address + chain id are supplied', async () => {
    const connector = anpCli(
      { privateKey: PRIV, curve: 'secp256k1' },
      { host: HOST, chainId: CHAIN_ID, address: ADDRESS },
    )
    const identity = await connector.getIdentity()
    expect(identity.did).toBe(`${CHAIN_ID}:${ADDRESS}`)
  })
})

describe('chainWallet (web3 path) e2e', () => {
  it('signs via the provider, never touching the key, and returns a token + CAIP-10 DID', async () => {
    const { targetUri, close } = await startServer()
    try {
      const { provider } = fakeProvider()
      const wallet = chainWallet(provider, { address: ADDRESS, chainId: CHAIN_ID })
      const connector = chainWalletConnector(wallet, { host: HOST, chainId: CHAIN_ID, address: ADDRESS })
      const { token, did } = await loginThrough(connector, targetUri)
      expect(token).toBe('tok_e2e_cli')
      expect(did).toBe(`${CHAIN_ID}:${ADDRESS}`)
    } finally {
      close()
    }
  })

  it('bridges the provider accountsChanged event into the wallet emitter', async () => {
    const { provider, emit } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDRESS, chainId: CHAIN_ID })
    const connector = chainWalletConnector(wallet, { host: HOST, chainId: CHAIN_ID, address: ADDRESS })

    const received: { type: string; payload?: unknown }[] = []
    const unsubscribe = connector.events!.on((e) => received.push(e))

    emit('accountsChanged', ['0xNEW'])
    expect(received).toEqual([{ type: 'accountsChanged', payload: ['0xNEW'] }])

    emit('chainChanged', '0x89')
    expect(received[1].type).toBe('chainChanged')
    expect(received[1].payload).toBe('0x89')

    emit('disconnect')
    expect(received[2].type).toBe('disconnect')

    unsubscribe()
    emit('accountsChanged', ['0xOTHER'])
    expect(received).toHaveLength(3)
  })

  it('emits a path-type did:wba identity for a chain wallet with no chain id', async () => {
    const { provider } = fakeProvider()
    const wallet = chainWallet(provider, { address: ADDRESS })
    const connector = chainWalletConnector(wallet, { host: 'localhost' })
    const identity = await connector.getIdentity()
    // No CAIP-10 descriptor → path-type did:wba binding the key. A web3 wallet is
    // secp256k1, so the fingerprint is k1_ (whose document proof is optional).
    expect(identity.did).toMatch(/^did:wba:localhost:user:default:k1_[A-Za-z0-9_-]{43}$/)
    expect(identity.didDocument.proof).toBeUndefined()
  })
})
