import { describe, it, expect, vi } from 'vitest'
import { anpDevShim } from './anpDevShim'
import { agentDescriptionService } from '../crypto/agentDescription'
import { createAnpIdentity } from '../crypto/signer'
import { bytesToBase64 } from '../crypto/encoding'
import { verifyDidDocument } from '../crypto/resolveDid'

// The shim derives the DID document from stored key material instead of persisting
// the document itself, which is what lets `service` change between runs without
// minting a new DID. These cover both halves of that: the entry reaches the signed
// document, and an identity stored before `service` existed still loads.

// `test:node` runs without a DOM. Node 22+ does expose a `localStorage` global, but
// without `--localstorage-file` it is not usable — so probe for one that actually
// round-trips rather than testing for absence, and supply the interface when there is
// none: the load path is the whole point of two of these tests. Both environments then
// exercise the same code instead of one of them being skipped.
function usableLocalStorage(): Storage | null {
  try {
    const probe = '__anp_probe__'
    globalThis.localStorage?.setItem(probe, probe)
    const ok = globalThis.localStorage?.getItem(probe) === probe
    globalThis.localStorage?.removeItem(probe)
    return ok ? globalThis.localStorage : null
  } catch {
    return null
  }
}

if (usableLocalStorage() == null) {
  const store = new Map<string, string>()
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
      key: (i: number) => [...store.keys()][i] ?? null,
      get length() {
        return store.size
      },
    } satisfies Storage,
  })
}
const storage = globalThis.localStorage

const ENTRY_URL = 'https://example.com/agents/alice/ad.json'

function storageKey(host: string): string {
  return `anp_sdk_dev_identity:${host}\0`
}

async function identityOf(host: string, opts: Record<string, unknown> = {}) {
  return anpDevShim(host, opts).getIdentity()
}

describe('anpDevShim service entries', () => {
  it('publishes the configured service in the signed document', async () => {
    const identity = await identityOf('service.localhost', {
      service: [agentDescriptionService(ENTRY_URL)],
    })
    const doc = identity.didDocument as { service: unknown[] }
    expect(doc.service).toEqual([agentDescriptionService(ENTRY_URL)])
    expect(() => verifyDidDocument(identity.didDocument, identity.did)).not.toThrow()
  })

  it('builds the entry from the DID, which only exists after the key does', async () => {
    const identity = await identityOf('factory.localhost', {
      service: (did: string) => [agentDescriptionService(`${ENTRY_URL}/${did}`, did)],
    })
    const doc = identity.didDocument as { service: Array<{ serviceEndpoint: string }> }
    expect(doc.service[0].serviceEndpoint).toBe(`${ENTRY_URL}/${identity.did}`)
  })

  it('omits `service` entirely when none is configured', async () => {
    const identity = await identityOf('plain.localhost')
    expect(identity.didDocument).not.toHaveProperty('service')
  })

  it('loads a record stored before documents were derived, and honours a NEW service option', async () => {
    // A record in the old shape: key material plus a document that predates the
    // entry. It must load (the DID and key survive) and pick the entry up.
    const legacy = createAnpIdentity('legacy.localhost')
    storage.setItem(
      storageKey('legacy.localhost'),
      JSON.stringify({
        privB64: bytesToBase64(legacy.priv),
        did: legacy.did,
        keyid: legacy.keyid,
        publicKeyMultibase: (legacy.publicKey as { publicKeyMultibase: string }).publicKeyMultibase,
        didDocument: legacy.didDocument, // ignored on load; kept here to prove it is
      }),
    )

    const identity = await identityOf('legacy.localhost', {
      persist: true,
      service: [agentDescriptionService(ENTRY_URL)],
    })
    expect(identity.did).toBe(legacy.did) // same identity, not a fresh one
    expect((identity.didDocument as { service: unknown[] }).service).toEqual([
      agentDescriptionService(ENTRY_URL),
    ])
    expect(() => verifyDidDocument(identity.didDocument, identity.did)).not.toThrow()

    // Loading it also rewrites it: the stale document copy is dropped, so storage no
    // longer holds a document that disagrees with the one being signed.
    const stored = JSON.parse(storage.getItem(storageKey('legacy.localhost'))!)
    expect(stored).not.toHaveProperty('didDocument')
    expect(Object.keys(stored)).toEqual(['privB64', 'did', 'keyid', 'publicKeyMultibase'])
  })

  it('leaves a current-shape record untouched', async () => {
    const expected = createAnpIdentity('fresh.localhost')
    // Written pretty-printed on purpose: the shim re-serializes compactly, so byte
    // equality is evidence the load path did not rewrite what it found.
    const original = JSON.stringify(
      {
        privB64: bytesToBase64(expected.priv),
        did: expected.did,
        keyid: expected.keyid,
        publicKeyMultibase: (expected.publicKey as { publicKeyMultibase: string }).publicKeyMultibase,
      },
      null,
      4,
    )
    storage.setItem(storageKey('fresh.localhost'), original)

    // Reset the module so the in-memory cache misses and the load path actually runs;
    // otherwise the call would be served from cache and prove nothing.
    vi.resetModules()
    const { anpDevShim: reloaded } = await import('./anpDevShim')
    const identity = await reloaded('fresh.localhost', { persist: true }).getIdentity()

    expect(identity.did).toBe(expected.did)
    expect(storage.getItem(storageKey('fresh.localhost'))).toBe(original)
  })
})
