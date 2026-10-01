import { createAnpIdentity } from '../crypto/signer'
import { bytesToBase64, base64ToBytes } from '../crypto/encoding'
import { buildBaseDidDocument, type DidDocumentServices } from '../crypto/didDocument'
import { signDidDocumentProofSync } from '../crypto/dataIntegrity'
import { subjectOf } from '../identity'
import type { AnpConnector, AnpIdentity, AnpSigningIdentity, SignRequest, SignResult } from '../types'
import type { ProofAdapter } from '../protocol/proof'
import { anpProofAdapter } from '../protocol/anp'

// Local dev identity. It generates (or loads) an Ed25519 key and an inline DID
// document so an agent can sign in against a server that has no reachable
// `.well-known` host. It is a client-side stand-in for a did:wba wallet; in
// production the private key lives in a real wallet, never in storage.
//
// SECURITY: by default the identity lives in memory only. Pass `persist: true`
// to write it to localStorage — that is opt-in and meant for local dev only,
// since a raw private key in localStorage is exfiltrated by any XSS.

const STORAGE_KEY_PREFIX = 'anp_sdk_dev_identity'

interface StoredIdentity {
  privB64: string
  did: string
  keyid: string
  publicKeyMultibase: string
}

// The key material of a dev identity. The DID document is NOT part of it — see
// `withDocument`. A dev identity is always Ed25519 (`createAnpIdentity`), so the one
// representation it has is the `Multikey` one, held here in the flat shape the stored
// record and `buildBaseDidDocument` both use.
type DevKey = Pick<AnpSigningIdentity, 'priv' | 'did' | 'keyid'> & { publicKeyMultibase: string }

// In-memory identity cache, keyed by host+path. Keeps the same identity within a
// session even when `persist` is false, so repeat signRequests use one DID/key.
const memoryStore = new Map<string, DevKey>()

// Derive the DID document from the key material rather than storing it. A dev
// identity is a key plus a host; the document is a pure function of those and the
// requested `service` entries, so deriving it lets `service` change between runs
// without minting a new DID. Ed25519 signing is deterministic, so an identity with
// no services reproduces the very same document (and proof) it always had.
function withDocument(key: DevKey, service?: DidDocumentServices): AnpSigningIdentity {
  const publicKey = { publicKeyMultibase: key.publicKeyMultibase }
  const doc = buildBaseDidDocument({
    did: key.did,
    keyid: key.keyid,
    ...publicKey,
    service,
  })
  doc.proof = signDidDocumentProofSync(doc, key.keyid, key.priv)
  return { subject: subjectOf(key.did), priv: key.priv, did: key.did, keyid: key.keyid, publicKey, didDocument: doc }
}

function identityKey(host: string, path?: string[]): string {
  return `${host}\0${(path ?? []).join('/')}`
}

function storageKeyFor(host: string, path?: string[]): string {
  return `${STORAGE_KEY_PREFIX}:${identityKey(host, path)}`
}

function serialize(key: DevKey): string {
  return JSON.stringify({
    privB64: bytesToBase64(key.priv),
    did: key.did,
    keyid: key.keyid,
    publicKeyMultibase: key.publicKeyMultibase,
  })
}

function loadPersisted(host: string, path?: string[]): DevKey | null {
  try {
    const storageKey = storageKeyFor(host, path)
    const raw = globalThis.localStorage?.getItem(storageKey)
    if (!raw) return null
    const obj = JSON.parse(raw) as StoredIdentity & { didDocument?: unknown }
    const key: DevKey = {
      priv: base64ToBytes(obj.privB64),
      did: obj.did,
      keyid: obj.keyid,
      publicKeyMultibase: obj.publicKeyMultibase,
    }
    // A record written before the document stopped being stored carries a copy that
    // is stale the moment `service` changes — and that nothing reads. Rewrite it once
    // in the current shape so storage does not contradict what the code says it holds.
    if ('didDocument' in obj) globalThis.localStorage?.setItem(storageKey, serialize(key))
    return key
  } catch {
    return null
  }
}

// Load or create the dev identity for a host. The storage key is derived from
// the host (and DID path) so different origins / paths never share a key/DID.
// `persist` controls whether the identity survives a page reload (localStorage)
// or lives in memory only.
export function loadOrCreateDevIdentity(
  host: string,
  persist = false,
  path?: string[],
  service?: DidDocumentServices,
): AnpSigningIdentity {
  const key = identityKey(host, path)
  const cached = memoryStore.get(key)
  if (cached) return withDocument(cached, service)

  if (persist) {
    const persisted = loadPersisted(host, path)
    if (persisted) {
      memoryStore.set(key, persisted)
      return withDocument(persisted, service)
    }
  }

  const created = createAnpIdentity(host, { path })
  const own: DevKey = {
    priv: created.priv,
    did: created.did,
    keyid: created.keyid,
    publicKeyMultibase: (created.publicKey as { publicKeyMultibase: string }).publicKeyMultibase,
  }
  memoryStore.set(key, own)

  if (persist) {
    // Only the key material is stored; the document is derived on load. A record
    // written before this was true still loads — it carries the same four fields.
    globalThis.localStorage?.setItem(storageKeyFor(host, path), serialize(own))
  }
  return withDocument(own, service)
}

export interface AnpDevShimOptions {
  /** Persist the identity to localStorage (default: false — memory only). */
  persist?: boolean
  /** Path segments for the path-type `did:wba` DID before the key fingerprint
   *  (defaults to `['user','default']`). Distinct paths get distinct identities. */
  path?: string[]
  /** Services to publish in this identity's DID document (ANP-03 §service). Pass a
   *  function to build one from the DID — an `agentDescriptionService` endpoint
   *  usually embeds it. Signed into the document, so it cannot be appended later. */
  service?: DidDocumentServices
  /** Proof adapter override; defaults to the official ANP-02 adapter. */
  proof?: ProofAdapter
  /**
   * Connector id. Defaults to `'anp-dev-shim'`. Override it when you configure
   * two dev shims (e.g. two different `host`s) — `createConfig`/`selectWallet`
   * key off `id`, so ids must be unique within a config.
   */
  id?: string
}

// Build the dev-shim connector. The `host` is used to derive the path-type
// `did:wba` DID and the DID document. `persist` opts into localStorage-backed
// identity.
export function anpDevShim(host: string, opts: AnpDevShimOptions = {}): AnpConnector {
  const proof = opts.proof ?? anpProofAdapter
  const persist = opts.persist ?? false
  const path = opts.path
  const service = opts.service
  return {
    id: opts.id ?? 'anp-dev-shim',
    name: 'ANP dev identity',
    type: 'anp-dev-shim',
    isAvailable: () => Promise.resolve(true),
    async getIdentity(): Promise<AnpIdentity> {
      const id = loadOrCreateDevIdentity(host, persist, path, service)
      return { subject: id.subject, did: id.did, keyid: id.keyid, publicKey: id.publicKey, didDocument: id.didDocument }
    },
    async signRequest(req: SignRequest): Promise<SignResult> {
      const identity = loadOrCreateDevIdentity(host, persist, path, service)
      // Body is built by the connector (not the caller) so the signed payload is
      // authoritative — mirrors `signAnpLoginRequest` / `cryptoWalletProver`.
      const payload: Record<string, unknown> = {
        // Endpoint-specific fields first; ANP-02's own names win (see `SignRequest.extraBody`).
        ...(req.extraBody ?? {}),
        nonce: req.nonce,
        did: identity.did,
        didDocument: identity.didDocument,
      }
      if (req.handle != null) payload.handle = req.handle
      const body = JSON.stringify(payload)
      const { body: signedBody, headers } = await proof.sign({
        identity,
        nonce: req.nonce,
        method: req.method,
        path: pathOf(req.url),
        targetUri: req.url,
        authority: host,
        body,
        handle: req.handle,
        // Carried separately because the default adapter rebuilds the body itself rather
        // than signing the `body` above; a custom adapter that does read `body` finds the
        // same members already in it.
        extraBody: req.extraBody,
      })
      return { did: identity.did, keyid: identity.keyid, didDocument: identity.didDocument, body: signedBody, headers }
    },
  }
}

function pathOf(url: string): string {
  return new URL(url).pathname
}

export type { AnpSigningIdentity }
