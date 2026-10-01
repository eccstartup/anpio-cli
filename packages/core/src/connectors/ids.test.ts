// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { anpDevShim } from './anpDevShim'
import { anpCli } from './anpCli'
import { chainWalletConnector, keypairWallet } from '../protocol/adapters/chain'
import { createConfig, selectWallet } from '../config'

// A deterministic 32-byte key — only the `.id` field is asserted here, so the
// wallet is never asked to sign; keypairWallet still derives a pubkey at
// construction, so give it a real (non-degenerate) secret.
const KEY = new Uint8Array(32).fill(0x22)

describe('connector id override', () => {
  it('each connector factory defaults to its stable id', () => {
    expect(anpDevShim('localhost').id).toBe('anp-dev-shim')
    expect(anpCli(keypairWallet(KEY), { host: 'localhost' }).id).toBe('anp-cli')
    expect(chainWalletConnector(keypairWallet(KEY), { host: 'localhost' }).id).toBe('chain')
  })

  it('each connector factory honors a caller-supplied id', () => {
    expect(anpDevShim('localhost', { id: 'dev-a' }).id).toBe('dev-a')
    expect(anpCli(keypairWallet(KEY), { host: 'localhost', id: 'cli-a' }).id).toBe('cli-a')
    expect(chainWalletConnector(keypairWallet(KEY), { host: 'localhost', id: 'chain-a' }).id).toBe('chain-a')
  })

  it('two same-type connectors with distinct ids can coexist in one config', () => {
    const a = anpDevShim('a.localhost', { id: 'dev-a' })
    const b = anpDevShim('b.localhost', { id: 'dev-b' })
    const config = createConfig([a, b], 'dev-a')
    expect(selectWallet(config, 'dev-a').id).toBe('dev-a')
    expect(selectWallet(config, 'dev-b').id).toBe('dev-b')
    expect(selectWallet(config).id).toBe('dev-a') // default
  })
})
