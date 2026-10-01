import { describe, it, expect } from 'vitest'
import {
  ConnectxError,
  ConnectorUnavailableError,
  isConnectxError,
  errorCode,
} from './errors'
import { createConfig, selectWallet } from './config'
import { parsePrivateKey } from './keys'
import { didToUrl, decodeMultibaseKey, resolveVerificationKey } from './crypto'
import type { AnpConnector } from './types'
import { subjectOf } from './identity'

const connector = (id: string): AnpConnector =>
  ({
    id,
    name: id,
    type: 'anp-cli',
    isAvailable: () => Promise.resolve(true),
    getIdentity: async () => ({ subject: subjectOf(`did:wba:${id}`), did: `did:wba:${id}`, keyid: `did:wba:${id}#key-1`, publicKey: { publicKeyMultibase: '' }, didDocument: {} }),
    signRequest: async () => ({ did: `did:wba:${id}`, keyid: `did:wba:${id}#key-1`, didDocument: {}, body: '', headers: {} }),
  }) as AnpConnector

describe('error model', () => {
  it('ConnectxError carries a stable code and is an Error', () => {
    const err = new ConnectxError('key_invalid', 'nope')
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(ConnectxError)
    expect(err.code).toBe('key_invalid')
    expect(err.name).toBe('ConnectxError')
    expect(err.message).toBe('nope')
  })

  it('ConnectorUnavailableError stays backwards-compatible and coded', () => {
    const err = new ConnectorUnavailableError('anp-extension')
    expect(err).toBeInstanceOf(ConnectxError)
    expect(err).toBeInstanceOf(Error)
    expect(err.code).toBe('connector_unavailable')
    expect(err.name).toBe('ConnectorUnavailableError')
  })

  it('carries the peer status + server code without disturbing the SDK code', () => {
    const err = new ConnectxError('register_failed', 'Request failed', {
      status: 409,
      serverCode: 'handle_taken',
    })
    expect(err.code).toBe('register_failed')
    expect(err.status).toBe(409)
    expect(err.serverCode).toBe('handle_taken')

    const bare = new ConnectxError('key_invalid', 'nope')
    expect(bare.status).toBeUndefined()
    expect(bare.serverCode).toBeUndefined()
  })

  it('isConnectxError / errorCode narrow unknown values', () => {
    expect(isConnectxError(new ConnectxError('invalid_argument', 'x'))).toBe(true)
    expect(isConnectxError(new Error('plain'))).toBe(false)
    expect(errorCode(new ConnectorUnavailableError('a'))).toBe('connector_unavailable')
    expect(errorCode(new Error('plain'))).toBeUndefined()
  })

  it('surfaces codes on synchronous public throw paths', () => {
    expect(errorCode(catchErr(() => createConfig([connector('a')], 'missing')))).toBe('invalid_argument')
    expect(errorCode(catchErr(() => selectWallet(createConfig([connector('a')]), 'missing')))).toBe('no_connector_selected')
    expect(errorCode(catchErr(() => parsePrivateKey('zz'.repeat(32))))).toBe('key_invalid')
    expect(errorCode(catchErr(() => didToUrl('did:web:')))).toBe('invalid_did')
    expect(errorCode(catchErr(() => decodeMultibaseKey('m-not-base58')))).toBe('key_invalid')
  })

  it('distinguishes the security-relevant DID codes', async () => {
    // No allowlist → blocked (security policy), before any network is touched.
    await expect(resolveVerificationKey('did:web:example.com#key-1')).rejects.toMatchObject({
      code: 'did_resolve_blocked',
    })
    // Allowlisted but the document fetch fails → failed (transient), retryable.
    await expect(
      resolveVerificationKey('did:web:example.com#key-1', undefined, {
        allowedHosts: ['example.com'],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async () => new Response('', { status: 404 }),
      }),
    ).rejects.toMatchObject({ code: 'did_resolve_failed' })
  })
})

function catchErr(fn: () => unknown): unknown {
  try {
    fn()
  } catch (err) {
    return err
  }
  throw new Error('expected fn to throw')
}
