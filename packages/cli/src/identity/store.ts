// The identity store: one encrypted key + a metadata sidecar per (agent, profile)
// under `~/.connectx/agents/<agent>/<profile>/`. This is what lets an agent say
// "log in as profile X" without ever handling a private-key byte — the CLI reads
// and decrypts the key in-process and hands the parsed pair to the connector.
//
// Files (dir 0700, files 0600, written temp+rename):
//   key            keystore V3 JSON (encrypted; see keystore.ts)
//   identity.json  local metadata (curve, public key, and — once registered —
//                  the host, the handle and the DID; see `StoredIdentity`)
//   key.next       a staged successor key, only while an update is in flight
//   did.json       the DID document as the DID server has it on file (see below)
//
// `identity.json` is PRIVATE and local — it is NOT ANP's public `ad.json`
// discovery document (see ADR-0001 §2.2). `did.json` is the public DID document
// the spec publishes at `didToUrl(did)` (ANP-03 §2.5.3 L409 names the file), kept
// as the evidence a later `did update` bases its retirement document on.

import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keypairWallet, subjectOf, ConnectxError } from '@agentx/core'
import type { AnpConnector, ParsedKey, ParsedKeyCurve } from '@agentx/core'
import { encodeMultibaseEd25519, secp256k1PublicKeyToJwk } from '@agentx/core/advanced'
import type { DidPublicKey } from '@agentx/core/advanced'
import { decryptPrivateKey, encryptPrivateKey } from './keystore'
import { assertAgentId, currentAgentFile, storeRoot, storeLocation, type StoreLocation } from './paths'

type AnpIdentity = Awaited<ReturnType<AnpConnector['getIdentity']>>

const FILE_MODE = 0o600
const DIR_MODE = 0o700

/** Current `identity.json` schema. v4 carries the public key as `publicKey` — the
 *  representation the profile PUBLISHES (`DidPublicKey`): `Multikey` +
 *  `publicKeyMultibase` for Ed25519, `EcdsaSecp256k1VerificationKey2019` +
 *  `publicKeyJwk` for secp256k1 (Appendix A A.4). v3's flat `publicKeyMultibase` wrote
 *  a secp256k1 key as a multibase, which ANP does not define for that curve, so a
 *  record that advertises one can only mislead and is refused like any older version.
 *
 *  Independently, both v3 and v4 record the host, the handle and the DID **only once
 *  the identity is registered**: a DID is `did:wba:<host>:<path>`, so the host is the
 *  DID server's and does not exist before a server has taken the key on. An identity
 *  that has only been created therefore carries key material and nothing else. Older
 *  versions (v1/v2) wrote a host and a DID at creation time, under a host no server had
 *  agreed to — that claim is what v3 removes, and an older reader must not be fed it,
 *  so this file is refused outright rather than upgraded in place. */
export const IDENTITY_SCHEMA_VERSION = 4

/** Local-private identity metadata (`identity.json`). Contains NO secret.
 *
 *  The fields below `createdAt` describe a REGISTRATION, not a key: they are absent
 *  until a DID server has accepted this key, and `registered` is the flag that says
 *  which state the record is in. */
export interface StoredIdentity {
  version: typeof IDENTITY_SCHEMA_VERSION
  /**
   * The stable subject — the identity this agent is known by
   * (`did:wba:<host>:<path…>` / the `did:web:…` DID itself / a CAIP-10 account
   * id). Unlike `lastDid` it SURVIVES a key update, so it is what local state
   * should be keyed on (ADR-0002 §2.2). Recorded explicitly rather than left
   * implicit in `lastDid`, because the DID is the update-varying wire
   * credential and the two must not be conflated.
   */
  subject?: string
  curve: ParsedKeyCurve
  /** CAIP-2; present only when the identity is a chain account. */
  chainId?: string
  /** Chain address; present only with `chainId`. */
  address?: string
  /** The binding key in the representation this identity's profile publishes — the
   *  same value `getIdentity()` reports, so the record and the wire never disagree. */
  publicKey: DidPublicKey
  createdAt: string
  /** The DID server this identity is registered on. Absent until registered: the host
   *  belongs to that server, so there is nothing to record before one accepts the key.
   *  Recorded, never pinned — the DID is recomposed per request. */
  host?: string
  /** Whether a DID server has taken this identity on. Everything below is written at
   *  that moment and only then. */
  registered: boolean
  /** The handle the server bound to this identity, once it accepted one. Written by
   *  `register`; absent means "never registered, or the server bound no handle". */
  handle?: string
  /** The DID the registration produced (display only). This is the WIRE CREDENTIAL: it
   *  carries the key fingerprint and therefore CHANGES when the key changes. */
  lastDid?: string
}

/** Write `content` atomically: temp file in the same dir, then rename. */
export function writeFileAtomic(file: string, content: string, mode: number): void {
  const tmp = `${file}.tmp-${randomBytes(6).toString('hex')}`
  writeFileSync(tmp, content, { mode })
  chmodSync(tmp, mode) // umask may have stripped bits from the create mode
  renameSync(tmp, file)
}

/** Create `dir` (0700) and tighten its parent agent dir. */
export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE })
  chmodSync(dir, DIR_MODE)
  const parent = dirname(dir)
  if (existsSync(parent)) chmodSync(parent, DIR_MODE)
}

/** Warn (stderr, non-fatal) when a store file is readable/writable by group or
 *  other. The file mode is only a speed bump — a co-resident process running as
 *  the same user can still read it — but a loose mode usually means a copy/git
 *  checkout leaked it, which is worth surfacing. */
export function warnIfPermissive(file: string, label: string): void {
  try {
    if ((statSync(file).mode & 0o077) !== 0) {
      console.error(`connectx: warning: ${label} (${file}) is group/world-accessible; run: chmod 600 ${file}`)
    }
  } catch {
    // A stat race (file removed between checks) is not worth failing over.
  }
}

function generatePrivateKey(curve: ParsedKeyCurve): Uint8Array {
  return curve === 'secp256k1' ? secp256k1.utils.randomSecretKey() : ed25519.utils.randomSecretKey()
}

/** The local copy of the DID document as the DID server has it on file. `did` is
 *  recorded alongside it because the DID moves when the key does (§2.5.3 L413), so a
 *  copy only ever describes ONE DID — and that pairing is what makes a stale copy
 *  inert instead of dangerous (see `runDidUpdate`). */
export interface DidDocumentCopy {
  did: string
  document: Record<string, unknown>
  /** Epoch ms of the fetch that produced this copy — the same field, and the same
   *  meaning, as `ResolvedDidDocument.fetchedAt`. */
  fetchedAt: number
}

/** Read the copy, or `null` when there is none or it is unusable. Deliberately
 *  tolerant: this is a CACHE of someone else's document, so a corrupt or half-written
 *  file must never be able to fail a command — the caller falls back to resolving,
 *  which is what it would have done with no copy at all. */
export function readDidDocumentCopy(location: StoreLocation): DidDocumentCopy | null {
  if (!existsSync(location.documentFile)) return null
  try {
    const obj = JSON.parse(readFileSync(location.documentFile, 'utf8')) as DidDocumentCopy
    if (typeof obj?.did !== 'string' || obj.did === '') return null
    if (typeof obj.document !== 'object' || obj.document === null) return null
    return obj
  } catch {
    return null
  }
}

/** Write the copy. The document itself is public, so the mode is not a secret-keeping
 *  measure — it keeps one mode across the store directory, so `warnIfPermissive` is
 *  never a false alarm about this file. */
export function writeDidDocumentCopy(location: StoreLocation, copy: DidDocumentCopy): void {
  ensureDir(location.dir)
  writeFileAtomic(location.documentFile, `${JSON.stringify(copy, null, 2)}\n`, FILE_MODE)
}

/** Read + validate `identity.json`, or `null` if absent. Only the current schema
 *  is read: an older file describes a host and a DID that no server had agreed to,
 *  and that claim is exactly what this version stopped recording. */
export function readIdentity(location: StoreLocation): StoredIdentity | null {
  if (!existsSync(location.identityFile)) return null
  let obj: StoredIdentity
  try {
    obj = JSON.parse(readFileSync(location.identityFile, 'utf8')) as StoredIdentity
  } catch (err) {
    throw new ConnectxError('key_invalid', `identity.json is not valid JSON (${location.identityFile})`, { cause: err })
  }
  // Read the two discriminants through `unknown` locals: `version` is a literal
  // type, so comparing it directly narrows `obj` to `never` in the failure branch
  // and the fields in the message below would not resolve.
  const version: unknown = obj.version
  const curve: unknown = obj.curve
  if (version !== IDENTITY_SCHEMA_VERSION) {
    throw new ConnectxError(
      'key_invalid',
      `Unsupported identity.json (version ${String(version)}, curve ${String(curve)}) at ${location.identityFile}`,
    )
  }
  if (curve !== 'ed25519' && curve !== 'secp256k1') {
    throw new ConnectxError(
      'key_invalid',
      `Unsupported identity.json (version ${String(version)}, curve ${String(curve)}) at ${location.identityFile}`,
    )
  }
  return obj
}

/** Does this (agent, profile) have a stored key? */
export function hasStoredKey(location: StoreLocation): boolean {
  return existsSync(location.keyFile)
}

export interface InitIdentityOptions {
  location: StoreLocation
  curve: ParsedKeyCurve
  /** At-rest password. `''` = encrypted with an empty password (warned by caller). */
  password: string
  /** Overwrite an existing identity. Without it, an existing one raises `identity_exists`. */
  force: boolean
}

/** Create a NEW identity for `(agent, profile)`: an independent random key (never
 *  derived from a shared mnemonic — that is what makes agents separable), sealed
 *  in the store. Returns the public half of the key it generated.
 *
 *  No DID comes out of this, and none is recorded: a `did:wba` DID is
 *  `did:wba:<host>:<path>`, and the host belongs to the DID server that takes the
 *  key on. Before `did register` does that there is no host to compose under, and
 *  writing one would record a claim no server has agreed to. */
export async function initIdentity(opts: InitIdentityOptions): Promise<{ publicKey: DidPublicKey }> {
  const { location, curve, password, force } = opts
  if (!force && (hasStoredKey(location) || existsSync(location.identityFile))) {
    throw new ConnectxError(
      'identity_exists',
      `An identity already exists for agent "${location.agent}" profile "${location.profile}" (${location.dir}). Pass --force to overwrite.`,
    )
  }

  if (curve !== 'ed25519' && curve !== 'secp256k1') {
    throw new ConnectxError('invalid_argument', `Unsupported curve "${String(curve)}" (expected ed25519 | secp256k1)`)
  }

  const privateKey = generatePrivateKey(curve)
  // Derive the public half through the SAME wallet the signing path builds, so the
  // stored public key can never drift from what a signature later verifies against —
  // and publish it in the representation that curve's profile uses (Appendix A A.4).
  const publicKey = await keypairWallet(privateKey, { curve }).getPublicKey()
  const published: DidPublicKey =
    curve === 'ed25519'
      ? { publicKeyMultibase: encodeMultibaseEd25519(publicKey) }
      : { publicKeyJwk: secp256k1PublicKeyToJwk(publicKey) }

  const encrypted = await encryptPrivateKey(privateKey, password)
  const meta: StoredIdentity = {
    version: IDENTITY_SCHEMA_VERSION,
    curve,
    publicKey: published,
    createdAt: new Date().toISOString(),
    registered: false,
  }

  ensureDir(location.dir)
  writeFileAtomic(location.keyFile, encrypted, FILE_MODE)
  writeFileAtomic(location.identityFile, JSON.stringify(meta, null, 2) + '\n', FILE_MODE)
  return { publicKey: published }
}

/** Load the stored key as a `ParsedKey`. The curve comes from `identity.json`
 *  (the keystore itself is curve-agnostic). */
export async function loadStoredKey(location: StoreLocation, password: string): Promise<ParsedKey> {
  warnIfPermissive(location.keyFile, 'stored key')
  const raw = readFileSync(location.keyFile, 'utf8')
  const privateKey = await decryptPrivateKey(raw, password)
  const stored = readIdentity(location)
  return { privateKey, curve: stored?.curve ?? 'ed25519' }
}

export interface RecordRegistrationOptions {
  location: StoreLocation
  /** The DID server that accepted the key. Recorded here, and only here: a
   *  `did:wba` DID is composed under this host on every later request, so the host
   *  is the DID server's to name. */
  host: string
  /** The handle the server ACCEPTED — omit when it bound none, so an unconfirmed
   *  handle is never recorded as if it were. */
  handle?: string
  /** The DID used for the registration, to refresh `lastDid` / `subject`. */
  did?: string
}

/** Record that this identity is now registered on its host — the moment it acquires
 *  a host, a DID and (usually) a handle.
 *
 *  Read-modify-write rather than a blind overwrite: the sidecar holds fields the
 *  registration path never sees (curve, public key, createdAt), and a `register`
 *  that rewrote the file from its own knowledge would drop them.
 *
 *  Returns `false` — a no-op, not an error — when there is no sidecar. That is the
 *  `--key` / `$ANP_PRIVATE_KEY` case: the key lives outside the store, so there is no
 *  local record to annotate and creating one would claim a key we do not hold. */
export function recordRegistration(opts: RecordRegistrationOptions): boolean {
  const { location, host, handle, did } = opts
  const current = readIdentity(location)
  if (current === null) return false
  const next: StoredIdentity = { ...current, registered: true, host }
  if (handle !== undefined && handle !== '') next.handle = handle
  if (did !== undefined && did !== '') {
    next.lastDid = did
    // Derived rather than taken from the caller: the subject is a pure function of
    // the DID, so a second copy could only ever disagree with it.
    next.subject = subjectOf(did)
  }
  ensureDir(location.dir)
  writeFileAtomic(location.identityFile, JSON.stringify(next, null, 2) + '\n', FILE_MODE)
  return true
}

export interface StoredIdentitySummary {
  agent: string
  profile: string
  dir: string
  curve?: ParsedKeyCurve
  /** Whether a DID server has taken this identity on. `false` also covers a sidecar
   *  that is missing or malformed — the key is still stored, so the entry is still
   *  listed either way. */
  registered: boolean
  /** The handle the DID server confirmed. Absent when none was bound. */
  handle?: string
  /** The stable subject recorded beside the key. Present only once registered. */
  subject?: string
  /** The DID the registration produced, refreshed by each update. This is the wire
   *  credential, not the stable subject. */
  lastDid?: string
}

/** List every stored identity (`agents/<agent>/<profile>` with a `key` file). */
export function listIdentities(): StoredIdentitySummary[] {
  const agentsDir = join(storeRoot(), 'agents')
  if (!existsSync(agentsDir)) return []
  const out: StoredIdentitySummary[] = []
  for (const agent of safeReaddir(agentsDir)) {
    const agentDir = join(agentsDir, agent)
    for (const profile of safeReaddir(agentDir)) {
      const dir = join(agentDir, profile)
      if (!existsSync(join(dir, 'key'))) continue
      // Composed through `storeLocation` rather than spelled out again, so this
      // cannot drift from the layout the rest of the CLI uses.
      const location = storeLocation(agent, profile)
      let recorded: StoredIdentity | null = null
      try {
        recorded = readIdentity(location)
      } catch {
        recorded = null // a malformed sidecar must not hide the key from the list
      }
      out.push({
        agent,
        profile,
        dir,
        curve: recorded?.curve,
        registered: recorded?.registered === true,
        handle: recorded?.handle,
        subject: recorded?.subject,
        lastDid: recorded?.lastDid,
      })
    }
  }
  return out.sort((a, b) => (a.agent + '/' + a.profile).localeCompare(b.agent + '/' + b.profile))
}

// ---- Successor keys (update) -------------------------------------------------
//
// An update REPLACES the key behind a stable subject (`subject` survives, `lastDid`
// moves). The new key is generated locally, but it only becomes the stored key once
// the DID server has accepted the hop — so it needs a place to exist in between.
// That is `key.next`: written before the delivery is attempted, consumed on
// acceptance, and left in place when the outcome is unknown.
//
// Staging is not a convenience. Without it, a crash between "the server accepted" and
// "the store was updated" loses the ONLY copy of the successor's private key, and the
// DID has been superseded to a key nobody holds — an identity that can never sign again.
// With it, the worst case is a `key.next` file the operator still has.

/** Generate a fresh key for an update successor. Same curve as the key it replaces,
 *  so `identity.json`'s `curve` stays true and nothing downstream has to re-detect it. */
export function generateSuccessorKey(curve: ParsedKeyCurve): ParsedKey {
  return { privateKey: generatePrivateKey(curve), curve }
}

export interface StageSuccessorOptions {
  location: StoreLocation
  password: string
  privateKey: Uint8Array
}

/** Write the successor key to `key.next` (0600) BEFORE the delivery is attempted.
 *  Overwrites any previous staged key: a second update attempt supersedes the first,
 *  and the first one's key is worthless (its hop was never delivered, or was delivered
 *  and then replaced). */
export async function stageSuccessorKey(opts: StageSuccessorOptions): Promise<void> {
  const { location, password, privateKey } = opts
  const encrypted = await encryptPrivateKey(privateKey, password)
  ensureDir(location.dir)
  writeFileAtomic(location.stagedKeyFile, encrypted, FILE_MODE)
}

/** Drop a staged successor. Called when the delivery FAILED for certain — nothing was
 *  superseded, so the key has no identity to belong to. Never called on an ambiguous
 *  outcome: see `runDidUpdate`. */
export function discardStagedSuccessor(location: StoreLocation): boolean {
  try {
    unlinkSync(location.stagedKeyFile)
    return true
  } catch {
    return false // already gone, or never staged
  }
}

/** Is there an update in flight whose outcome nobody has settled yet? */
export function hasStagedSuccessor(location: StoreLocation): boolean {
  return existsSync(location.stagedKeyFile)
}

/** Read `key.next` back as a `ParsedKey` — the resume path's only way in, since the
 *  process that generated the key is long gone. Curve comes from `identity.json`, as
 *  in `loadStoredKey`: the keystore carries no curve. */
export async function loadStagedSuccessorKey(
  location: StoreLocation,
  password: string,
): Promise<ParsedKey> {
  warnIfPermissive(location.stagedKeyFile, 'staged successor key')
  const raw = readFileSync(location.stagedKeyFile, 'utf8')
  const privateKey = await decryptPrivateKey(raw, password)
  const stored = readIdentity(location)
  return { privateKey, curve: stored?.curve ?? 'ed25519' }
}

export interface InstallSuccessorOptions {
  location: StoreLocation
  password: string
  /** The successor's private key — still in the caller's memory, so it never has to be
   *  read back out of `key.next`. */
  privateKey: Uint8Array
  /** The successor's public identity, as built by the same connector the login path
   *  uses. Its `subject` is necessarily the one already on file: the SDK refuses a hop
   *  whose successor leaves the stable subject path (ANP-03 §2.5.3). */
  identity: AnpIdentity
}

/** Make the successor the STORED identity: seal its key as `key`, update the sidecar,
 *  and consume `key.next`.
 *
 *  What is CARRIED OVER is the point of the whole exercise — `subject` (the identity
 *  the agent is known by), `registered`, `handle`, `createdAt` — so from the inside a
 *  update looks like the same agent with a new key, not a new agent. What MOVES is
 *  the key material and every field derived from it.
 *
 *  Writing the key BEFORE the sidecar is deliberate: the DID is recomposed from the key
 *  on every request, so the moment `key` is in place the store already signs as the
 *  successor. A crash in between therefore leaves metadata that is merely STALE
 *  (`lastDid` / `publicKey` are display fields), never a key that cannot be
 *  used. The reverse order would leave a sidecar advertising a DID its key cannot
 *  produce. */
export async function installSuccessor(opts: InstallSuccessorOptions): Promise<StoredIdentity> {
  const { location, password, privateKey, identity } = opts
  const current = readIdentity(location)
  if (current === null) {
    throw new ConnectxError(
      'identity_not_found',
      `No identity for agent "${location.agent}" profile "${location.profile}" (${location.dir}). An update replaces the key of an identity already on file — there is nothing here to change.`,
    )
  }
  const next: StoredIdentity = {
    ...current,
    // Taken from the successor's own DID rather than copied from `current`, so the two
    // can never disagree: the SDK has already refused a hop that would move it.
    subject: identity.subject,
    curve: current.curve,
    publicKey: identity.publicKey,
    lastDid: identity.did,
  }

  ensureDir(location.dir)
  writeFileAtomic(location.keyFile, await encryptPrivateKey(privateKey, password), FILE_MODE)
  writeFileAtomic(location.identityFile, JSON.stringify(next, null, 2) + '\n', FILE_MODE)
  discardStagedSuccessor(location)
  return next
}

// ---- The current agent --------------------------------------------------------
//
// One pointer at the store root: the agent every later command acts as when neither
// `--agent` nor `$CONNECTX_AGENT` names one. It is written temp+rename like everything
// else here, so a crash cannot leave half an id behind — a truncated one would be
// refused by every later command until someone found this file.
//
// The reader is `readCurrentAgent` in `./paths`, because the precedence chain that
// consumes it lives there and cannot import this module back.

/** Point the store at `agent`. An id with no identity stored is accepted: selecting an
 *  agent and then creating its key is the order a new agent is born in. */
export function setCurrentAgent(agent: string): void {
  const file = currentAgentFile()
  // Not `ensureDir`: that also tightens the PARENT of the directory it makes, and the
  // parent of the store root is the user's home. mkdir applies the mode to directories
  // it creates and leaves existing ones alone.
  mkdirSync(dirname(file), { recursive: true, mode: DIR_MODE })
  writeFileAtomic(file, `${assertAgentId(agent)}\n`, FILE_MODE)
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
  } catch {
    return []
  }
}
