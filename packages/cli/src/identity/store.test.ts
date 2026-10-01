// Store behaviour: the on-disk layout, permissions, the identity sidecar, and
// the no-implicit-creation rule. Runs against a temp `$CONNECTX_HOME` so it never
// touches the real `~/.connectx`.

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { mkdtempSync, rmSync, statSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { anpCli } from '@agentx/core'
import type { DidPublicKey } from '@agentx/core/advanced'
import { storeLocation } from './paths'
import {
  initIdentity,
  loadStoredKey,
  readIdentity,
  hasStoredKey,
  listIdentities,
  warnIfPermissive,
  ensureDir,
  recordRegistration,
  readDidDocumentCopy,
  writeDidDocumentCopy,
} from './store'
import { decryptPrivateKey } from './keystore'

const PASSWORD = 'store-test-password'

let home: string
const prevHome = process.env.CONNECTX_HOME

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'connectx-store-'))
  process.env.CONNECTX_HOME = home
})

afterAll(() => {
  if (prevHome === undefined) delete process.env.CONNECTX_HOME
  else process.env.CONNECTX_HOME = prevHome
  rmSync(home, { recursive: true, force: true })
})

const loc = (agent: string, profile = 'default') => storeLocation(agent, profile)

/** The `Multikey` representation's multibase — what every Ed25519 identity here holds. */
function multibaseOf(publicKey: DidPublicKey): string {
  if (!('publicKeyMultibase' in publicKey)) throw new Error('expected a Multikey public key')
  return publicKey.publicKeyMultibase
}

describe('initIdentity', () => {
  it('creates an encrypted key + identity.json with locked-down permissions', async () => {
    const location = loc('claude-code')
    const { publicKey } = await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })

    expect(existsSync(location.keyFile)).toBe(true)
    expect(existsSync(location.identityFile)).toBe(true)
    expect(hasStoredKey(location)).toBe(true)
    // ed25519 -> multicodec 0xed01, base58btc, `z…`.
    expect(multibaseOf(publicKey)).toMatch(/^z6Mk[A-Za-z0-9]{44}$/)

    // 0700 dir, 0600 files.
    expect(statSync(location.dir).mode & 0o777).toBe(0o700)
    expect(statSync(location.keyFile).mode & 0o777).toBe(0o600)
    expect(statSync(location.identityFile).mode & 0o777).toBe(0o600)

    const meta = readIdentity(location)
    expect(meta).toMatchObject({
      version: 4,
      curve: 'ed25519',
      registered: false,
      publicKey,
    })
    expect(typeof meta?.createdAt).toBe('string')
    expect(multibaseOf(meta!.publicKey)).not.toMatch(/^0x/)
  })

  it('records no DID, no host and no subject: those arrive with the registration', async () => {
    // The whole point of the shape: a `did:wba` DID is `did:wba:<host>:<path>`, and the
    // host belongs to the DID server that hosts the document. Guessing one here would
    // write a claim no server has agreed to, so the fields are absent rather than empty.
    const location = loc('unregistered')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })

    const onDisk = JSON.parse(readFileSync(location.identityFile, 'utf8')) as Record<string, unknown>
    expect(Object.keys(onDisk).sort()).toEqual(['createdAt', 'curve', 'publicKey', 'registered', 'version'])
    expect(onDisk.registered).toBe(false)
  })

  it('refuses to overwrite without --force, then overwrites with it', async () => {
    const location = loc('codex')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })

    await expect(initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })).rejects.toMatchObject({
      code: 'identity_exists',
    })

    const before = await decryptPrivateKey(readFileSync(location.keyFile, 'utf8'), PASSWORD)
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: true })
    const after = await decryptPrivateKey(readFileSync(location.keyFile, 'utf8'), PASSWORD)
    expect(after).not.toEqual(before) // --force mints a genuinely new key
  })

  it('stores the curve and honours it on load (secp256k1)', async () => {
    const location = loc('agent', 'evm')
    const { publicKey } = await initIdentity({ location, curve: 'secp256k1', password: PASSWORD, force: false })
    const parsed = await loadStoredKey(location, PASSWORD)
    expect(parsed.curve).toBe('secp256k1')
    expect(parsed.privateKey.length).toBe(32)
    // Appendix A A.4: a secp256k1 binding key is published as `publicKeyJwk`. The v3
    // record wrote a secp256k1 MULTIBASE, a shape ANP defines for no curve but Ed25519.
    expect(Object.keys(publicKey)).toEqual(['publicKeyJwk'])
    expect(publicKey).toMatchObject({
      publicKeyJwk: {
        kty: 'EC',
        crv: 'secp256k1',
        x: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        y: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      },
    })
  })

  it('stores the public key the signing path derives, byte for byte', async () => {
    // The store composes nothing, so the public identity has to be derived the same way
    // the connector derives it — otherwise a DID composed later at registration would
    // commit to a key id that no signature of this key can satisfy.
    const location = loc('no-drift')
    const { publicKey } = await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })

    const parsed = await loadStoredKey(location, PASSWORD)
    const derived = await anpCli(parsed, { host: 'localhost', path: ['user', 'no-drift'] }).getIdentity()
    expect(derived.publicKey).toEqual(publicKey)
  })
})

// v1/v2 recorded a host and a DID at create time, under a host no server had agreed to;
// that claim is what v3 removes. v3 in turn wrote a secp256k1 key as a multibase, a
// representation no other implementation reads. Either way an older file is refused
// rather than upgraded: the store's reader must never be the one that re-asserts what
// the current schema dropped.
describe('readIdentity — an older schema is refused, not migrated', () => {
  function writeOlder(location: ReturnType<typeof storeLocation>, version: 1 | 2 | 3): void {
    ensureDir(location.dir)
    writeFileSync(
      location.identityFile,
      JSON.stringify(
        {
          version,
          curve: 'ed25519',
          publicKeyMultibase: 'zed...',
          createdAt: '2026-01-01T00:00:00.000Z',
          host: 'localhost',
          registered: true,
          subject: 'did:wba:localhost:user:x',
          lastDid: 'did:wba:localhost:user:x:e1_WWpn_pfHui9YKR4CZtQsDGMu7_Gch2zYChfSvnxgtPk',
        },
        null,
        2,
      ),
      { mode: 0o600 },
    )
  }

  for (const version of [1, 2, 3] as const) {
    it(`rejects a v${version} file`, () => {
      const location = loc(`older-v${version}`)
      writeOlder(location, version)
      expect(() => readIdentity(location)).toThrow(
        new RegExp(`Unsupported identity\\.json \\(version ${version}, curve ed25519\\)`),
      )
    })
  }

  it('rejects a version from the future', () => {
    const location = loc('legacy-future')
    ensureDir(location.dir)
    writeFileSync(location.identityFile, JSON.stringify({ version: 99, curve: 'ed25519' }), { mode: 0o600 })
    expect(() => readIdentity(location)).toThrow(/Unsupported identity\.json/)
  })

  it('rejects an unknown curve', () => {
    const location = loc('bad-curve')
    ensureDir(location.dir)
    writeFileSync(location.identityFile, JSON.stringify({ version: 4, curve: 'p256' }), { mode: 0o600 })
    expect(() => readIdentity(location)).toThrow(/Unsupported identity\.json/)
  })
})

describe('loadStoredKey', () => {
  it('returns the same key the store sealed, and the public half it recorded', async () => {
    const location = loc('load-check')
    const { publicKey } = await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })

    const parsed = await loadStoredKey(location, PASSWORD)
    const sealed = await decryptPrivateKey(readFileSync(location.keyFile, 'utf8'), PASSWORD)
    expect(parsed.privateKey).toEqual(sealed)

    const derived = await anpCli(parsed, { host: 'localhost', path: ['user', 'load-check'] }).getIdentity()
    expect(derived.publicKey).toEqual(publicKey)
  })

  it('wrong password → key_wrong_password', async () => {
    const location = loc('wrong-pw')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    await expect(loadStoredKey(location, 'nope')).rejects.toMatchObject({ code: 'key_wrong_password' })
  })
})

describe('listIdentities', () => {
  it('lists every stored (agent, profile), with what is known about each', async () => {
    const all = listIdentities()
    const ids = all.map((i) => `${i.agent}/${i.profile}`)
    expect(ids).toContain('claude-code/default')
    expect(ids).toContain('codex/default')
    expect(ids).toContain('agent/evm')
    const evm = all.find((i) => i.agent === 'agent' && i.profile === 'evm')
    expect(evm?.curve).toBe('secp256k1')
    // Nothing here is registered: `initIdentity` never writes a host or a DID.
    expect(evm?.registered).toBe(false)
    expect(evm?.lastDid).toBeUndefined()
    expect(evm?.handle).toBeUndefined()
  })
})

// R2.4: registering is the moment the local sidecar gains a host, a handle and a DID.
describe('recordRegistration', () => {
  it('records the host, the accepted handle, the DID and the subject it implies', async () => {
    const location = loc('registered')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    expect(readIdentity(location)?.registered).toBe(false)

    const did = 'did:wba:did.example.com:user:registered:e1_WWpn_pfHui9YKR4CZtQsDGMu7_Gch2zYChfSvnxgtPk'
    expect(recordRegistration({ location, host: 'did.example.com', handle: 'alice', did })).toBe(true)

    const meta = readIdentity(location)
    expect(meta).toMatchObject({
      registered: true,
      host: 'did.example.com',
      handle: 'alice',
      lastDid: did,
      // Derived from the DID, not taken from the caller: one copy, so the two can never
      // disagree. The subject is the DID minus its key fingerprint.
      subject: 'did:wba:did.example.com:user:registered',
    })
    // Read-modify-write: the fields this path never sees must survive it.
    expect(meta).toMatchObject({ version: 4, curve: 'ed25519' })
    expect(multibaseOf(meta!.publicKey)).toMatch(/^z6Mk/)
    expect(meta?.createdAt).toBe(readIdentity(location)?.createdAt)
  })

  it('leaves an unconfirmed handle unrecorded but still flips `registered`', async () => {
    const location = loc('registered', 'no-handle')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    expect(
      recordRegistration({ location, host: 'localhost', handle: '', did: 'did:wba:localhost:user:x' }),
    ).toBe(true)
    expect(readIdentity(location)?.registered).toBe(true)
    expect(readIdentity(location)?.handle).toBeUndefined()
  })

  it('is a no-op when there is no sidecar to annotate', () => {
    // The --key / $ANP_PRIVATE_KEY case: the key lives outside the store, so there is
    // no local record — and inventing one would claim a key we do not hold.
    const location = loc('never-stored')
    expect(recordRegistration({ location, host: 'localhost', handle: 'nobody' })).toBe(false)
    expect(existsSync(location.identityFile)).toBe(false)
  })

  it('does not lose a re-registration of the same identity', async () => {
    const location = loc('registered', 'twice')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    recordRegistration({ location, host: 'localhost' })
    recordRegistration({ location, host: 'localhost', handle: 'alice' })
    recordRegistration({ location, host: 'localhost', handle: 'alice-2' })
    expect(readIdentity(location)?.handle).toBe('alice-2')
  })
})

describe('the copy of the DID document as the server has it on file', () => {
  const copy = {
    did: 'did:wba:localhost:user:alice:e1_abc',
    document: { id: 'did:wba:localhost:user:alice:e1_abc', service: [{ id: '#ad', type: 'AgentDescription' }] },
    fetchedAt: 1_700_000_000_000,
  }

  it('round-trips, 0600, and holds no secret', async () => {
    const location = loc('copy', 'roundtrip')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    writeDidDocumentCopy(location, copy)

    // The document is public, but the mode is kept uniform with the rest of the store so
    // `warnIfPermissive` is never a false alarm about this file.
    expect(statSync(location.documentFile).mode & 0o777).toBe(0o600)
    expect(readDidDocumentCopy(location)).toEqual(copy)
    const onDisk = readFileSync(location.documentFile, 'utf8')
    expect(onDisk).not.toContain(PASSWORD)
    expect(onDisk).not.toContain('privateKey')
  })

  it('reads as absent when there is no copy', () => {
    expect(readDidDocumentCopy(loc('copy', 'never'))).toBe(null)
  })

  it('reads as absent — not as an error — when the file is unusable', async () => {
    // It is a cache of someone else's document: a corrupt or half-written copy must never
    // be able to fail a command. The caller then resolves, which is what it would have
    // done with no copy at all.
    const location = loc('copy', 'corrupt')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    const unusable = ['not json at all', '{"did":"did:wba:localhost:user:x:e1_y"}', '{"did":"","document":{}}', '{"did":"did:wba:localhost:user:x:e1_y","document":null}']
    for (const text of unusable) {
      writeFileSync(location.documentFile, text)
      expect(readDidDocumentCopy(location)).toBe(null)
    }
  })
})

describe('warnIfPermissive', () => {
  it('warns (non-fatally) when a store file is group/world-accessible', async () => {
    const location = loc('permissive')
    await initIdentity({ location, curve: 'ed25519', password: PASSWORD, force: false })
    chmodSync(location.keyFile, 0o644)

    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    warnIfPermissive(location.keyFile, 'stored key')
    expect(spy).toHaveBeenCalledOnce()
    expect(String(spy.mock.calls[0][0])).toContain('chmod 600')
    spy.mockRestore()
  })
})
