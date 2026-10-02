// The agent commands (`did` / `anp`) — a thin shell over the connectx SDK.
// Parse-free: the caller (cli.ts) hands us parsed `values`; here we pick a wallet
// (web3 interface / local key) and let the SAME `login()` / `sign()` operations run.
// No business logic; an agent gets the identical ANP-02 proof whether it logged in
// from this CLI or a browser.
//
// Two layers, split by the party on the other end:
//   did   the DID server. Its pages are DID-protocol only, so none of them carries
//         `--wallet web3`: a wallet yields a CAIP-10 account id, which is not a DID.
//   anp   the application server. Its pages take either source, because an ANP peer
//         verifies a signature, and both paths produce one.
//
// Wallet modes (anp only):
//   --wallet web3  Agent never holds a key — signs via an EIP-1193 provider
//                  injected as `--provider <module>` (private key stays in the wallet).
//   --wallet cli   Local-key path. The key comes from, in order: `--key` (explicit),
//                  the identity store (`--agent`/`--profile`), or `$ANP_PRIVATE_KEY`.
//                  With the store the agent names an identity and never sees a key
//                  byte; an unknown identity is an error, never created implicitly.

import { isAbsolute, resolve } from 'node:path'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import {
  createConfig,
  signRequest,
  login,
  register,
  registerViaJsonRpc,
  discoverDidServer,
  anpCli,
  chainWallet,
  chainWalletConnector,
  keypairWallet,
  ConnectxError,
} from '@agentx/core'
import type {
  AnpConfig,
  AnpIdentity,
  Eip1193Provider,
  AnpConnector,
  DidChainOptions,
  DidDocumentServices,
  IWallet,
  ParsedKey,
  ParsedKeyCurve,
  RegisterOutcome,
} from '@agentx/core'
import { readKeyArg, loadKeyMaterial, detectFormat } from '../key'
import { storeLocation, resolveAgentId, resolveProfileName, type StoreLocation } from '../identity/paths'
import {
  initIdentity,
  loadStoredKey,
  hasStoredKey,
  listIdentities,
  readIdentity,
  recordRegistration,
} from '../identity/store'
import type { StoredIdentity } from '../identity/store'
import { saveSessionToken, parseTtlSeconds } from '../identity/session'
import { didHost, recordDidDocumentOnFile, registerCommandHint, relaxedHosts } from './did'
import {
  askApproval,
  describeSession,
  renderCard,
  renderSummary,
  writeEvent,
  type KeyLocation,
  type LoginEvent,
  type SessionWrite,
} from './login-view'

export type Values = Record<string, string | boolean | undefined>

/** An error whose `code` is this CLI's own, not the SDK's ANP-02 vocabulary — an
 *  operator declining at the card is not something a peer said. cli.ts prints the
 *  code on both channels, so a script can branch on it without --json. */
export function cliError(code: string, message: string): Error {
  const err = new Error(message) as Error & { code?: string }
  err.code = code
  return err
}

export interface Resolved {
  config: AnpConfig
  connector: AnpConnector
  /** The same wallet the connector signs with, handed out so a caller can sign
   *  something the connector's `signRequest` does not model — the ANP-09 origin proof
   *  is one (`walletOriginProofSigner`). A connector seals its signing behind
   *  `getIdentity` / `signRequest`, so without this a command would have to build a
   *  second wallet from the key material and get the curve wrong on its own. */
  wallet: IWallet
  /** Target host — also the key this session is stored under. */
  host: string
  /** On-disk location of this (agent, profile); `session.json` lives here too. */
  location: StoreLocation
  /** The at-rest password, resolved ONCE. `--password-stdin` can only be read a
   *  single time, so both the key load and the session write must share it. */
  password: string
  /** Where the signing key lives — for the card to say out loud, never the key. */
  key: KeyLocation
}

/** `connectx did create|show|list|register` — the half of `did` `cli.ts` calls
 *  directly, with no reporting of its own. All four throw, so the top-level handler
 *  prints the SDK's error `code` on the human line. `did resolve` / `did update` /
 *  `did restore` live in `did.ts` and own their exit codes instead (`did resolve`
 *  exits 2 for a superseded DID, which is a conclusion rather than a failure).
 *
 *  `did register` is here for that reason rather than for being local: a taken handle
 *  arrives as `register_failed` carrying the peer's own `serverCode`, and that code has
 *  to survive on the line a script reads. Routing it through `runDid`'s own catch would
 *  drop it from every failure.
 *
 *  These were one command reached two ways (`identity` and `identity --init`), which made
 *  "create an identity" a flag on a command whose bare form printed one. A subcommand says
 *  which one, and the help has a page for each. */
export async function runDidStore(v: Values, sub: string | undefined): Promise<void> {
  switch (sub) {
    case 'show':
      return runDidShow(v)
    case 'create':
      return runDidCreate(v)
    case 'list':
      return runDidList(v)
    case 'register':
      return runDidRegister(v)
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx did\``)
  }
}

/** `connectx anp show|login|sign` — the half of `did`'s sibling that talks to an
 *  application. Same contract as `runDidStore`: every page here may sign, so every
 *  failure belongs on the top-level handler with its `code`.
 *
 *  The three share one wallet resolution (`buildConnector`), which is what makes
 *  `--wallet web3` a choice of SOURCE rather than a second command: the ANP layer
 *  verifies a signature, and a wallet produces one just as a stored key does. */
export async function runAnp(v: Values, sub: string | undefined): Promise<void> {
  switch (sub) {
    case 'show':
      return runAnpShow(v)
    case 'login':
      return runLogin(v)
    case 'sign':
      return runSign(v)
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx anp\``)
  }
}

/** Where the stored key for this (agent, profile) is, whether it is there, and with
 *  which mode. Stats the path only: no key byte is ever read to answer this. */
function keyLocationFacts(location: StoreLocation): {
  keyFile: string
  keyExists: boolean
  keyMode?: string
} {
  const keyExists = existsSync(location.keyFile)
  const keyMode = keyExists
    ? (statSync(location.keyFile).mode & 0o777).toString(8).padStart(3, '0')
    : undefined
  return { keyFile: location.keyFile, keyExists, keyMode }
}

/** The label/value a binding key prints as — in the representation the profile
 *  publishes, which is the one the DID document carries (`DidPublicKey`): a `Multikey`
 *  Ed25519 key shows its multibase, a secp256k1 key shows its JWK (Appendix A A.4). */
function publicKeyField(publicKey: AnpIdentity['publicKey']): [string, string] {
  return 'publicKeyMultibase' in publicKey
    ? ['publicKeyMultibase:', publicKey.publicKeyMultibase]
    : ['publicKeyJwk:', JSON.stringify(publicKey.publicKeyJwk)]
}

/** Print a stored identity that no DID server has taken on yet: the public half of the
 *  key, the files, and the fact that there is no DID. The absence is the answer, so it
 *  is printed as one — a host filled in here would be this machine's guess at a server
 *  that never agreed to host the document. */
function printUnregisteredIdentity(ctx: { location: StoreLocation; stored: StoredIdentity; json: boolean }): void {
  const { location, stored } = ctx
  const facts = keyLocationFacts(location)
  if (ctx.json) {
    console.log(
      JSON.stringify({ ...stored, agent: location.agent, profile: location.profile, ...facts }, null, 2),
    )
    return
  }
  const field = (label: string, value: string) => console.log(`${label.padEnd(20)} ${value}`)
  field('agent:', `${location.agent}/${location.profile}`)
  field('curve:', stored.curve)
  field(...publicKeyField(stored.publicKey))
  field('key file:', `${facts.keyFile} (${facts.keyExists ? `mode ${facts.keyMode}` : 'missing'})`)
  console.log()
  console.log('not registered: no DID server has taken this key on, so there is no host')
  console.log('and no DID. Run:')
  console.log(`  ${registerCommandHint(location)}`)
}

/** The identity location `--agent` / `--profile` name. One place, so the commands that
 *  read the store directly and the ones that go through `buildConnector` cannot end up
 *  looking at two different directories. */
function currentLocation(v: Values): StoreLocation {
  return storeLocation(
    resolveAgentId(v.agent as string | undefined),
    resolveProfileName(v.profile as string | undefined),
  )
}

/** Print a resolved identity. Both readers of a DID server's answer — `did show` and the
 *  local-key half of `anp show` — render through here, so they cannot describe one
 *  identity two ways.
 *
 *  `document` says whether this identity has a document a peer could fetch, which decides
 *  both the identifier's label and whether the document is printed at all (nothing is
 *  published at a resolvable URL for an account id, so printing one there would assert a
 *  wire object no peer can fetch). It is the CALLER's to state, from what it already
 *  knows about the identity it built — the CLI must not re-derive an identifier's kind
 *  from its string ([vendored-core.md] §6.3: that judgment lives in the locator, and
 *  copying it here is what closes the gate for identities of other kinds).
 *
 *  The document is printed indented, on its own, the same way `did resolve` prints the
 *  one it fetches: it is a nested structure with a long `id`, and inlining it produces
 *  one line the reader has to parse by eye.
 *
 *  The key file line appears only when the key really came from the store: with a wallet
 *  the identity being shown is not the stored one, and naming a file that is not in use
 *  would be a false statement about where the key lives. */
function printIdentity(ctx: {
  identity: AnpIdentity
  location: StoreLocation
  key: KeyLocation
  json: boolean
  document: boolean
}): void {
  const { identity, location, key, document } = ctx
  const fromStore = key.source === 'store'
  const field = (label: string, value: string) => console.log(`${label.padEnd(20)} ${value}`)

  if (ctx.json) {
    console.log(
      JSON.stringify(
        {
          ...identity,
          agent: location.agent,
          profile: location.profile,
          keySource: key.source,
          ...(fromStore ? keyLocationFacts(location) : {}),
        },
        null,
        2,
      ),
    )
    return
  }

  field('agent:', `${location.agent}/${location.profile}`)
  field('subject:', identity.subject)
  field(document ? 'did:' : 'account:', identity.did)
  field('keyid:', identity.keyid)
  field(...publicKeyField(identity.publicKey))
  if (fromStore) {
    const facts = keyLocationFacts(location)
    const state = facts.keyExists ? `mode ${facts.keyMode}` : 'missing'
    field('key file:', `${facts.keyFile} (${state})`)
  } else {
    field('key source:', `${key.source}, so no store file is in use`)
  }
  console.log()
  if (document) {
    console.log('subject is the stable identity and survives a key update; did is the')
    console.log('current wire credential and changes with the key.')
    console.log()
    console.log(JSON.stringify(identity.didDocument, null, 2))
    return
  }
  console.log('subject is the stable identity and survives a key update; the account id')
  console.log('is what a peer sees, and it changes with the wallet.')
}

/** `connectx did show` / `connectx anp show` (store path) — print the identity already
 *  stored for this (agent, profile). Reads the store; contacts nothing.
 *
 *  An identity that has only been created has no DID to print: a `did:wba` DID names
 *  the server hosting it, and until `did register` picks one there is nothing to name.
 *  That state is reported as itself rather than filled in with a placeholder host. */
async function runShowStored(v: Values, document: boolean): Promise<void> {
  const location = currentLocation(v)
  const stored = readIdentity(location)
  if (stored === null) {
    throw new ConnectxError(
      'identity_not_found',
      `No identity for agent "${location.agent}" profile "${location.profile}" (${location.dir}). Run: connectx did create`,
    )
  }
  const json = v.json === true
  if (!stored.registered) {
    printUnregisteredIdentity({ location, stored, json })
    return
  }
  const { connector, key } = await buildConnector(v)
  const identity = await connector.getIdentity()
  printIdentity({ identity, location, key, json, document })
}

/** `connectx did show` — the DID layer's view: DID protocol only, so the identifier is
 *  always a DID and always has a document. */
async function runDidShow(v: Values): Promise<void> {
  await runShowStored(v, true)
}

/** `connectx anp show` — the application layer's view, which accepts either source of
 *  signature. A web3 wallet is where an account id comes from, so that path is read
 *  here: it is the ANP layer that has one. A local-key identity is the same stored
 *  record `did show` prints, so both pages read it through the same code. */
async function runAnpShow(v: Values): Promise<void> {
  if (((v.wallet as string | undefined) ?? 'cli') === 'web3') {
    const { connector, location, key } = await buildConnector(v)
    const identity = await connector.getIdentity()
    printIdentity({
      identity,
      location,
      key,
      json: v.json === true,
      // The chain path's contract, not a reading of the string: `--wallet web3`
      // requires `--address`/`--chain-id` (see `buildConnector`), so this identity is a
      // CAIP-10 account id and nothing is published for a peer to fetch.
      document: false,
    })
    return
  }
  await runShowStored(v, true)
}

/** `connectx did list` — every agent profile with a key under the store root. Reads
 *  the store; contacts nothing.
 *
 *  This is the answer to "which ids may `--agent` take": an id is whatever a caller
 *  picked, and this is the set of those that exist on this machine. */
async function runDidList(v: Values): Promise<void> {
  const identities = listIdentities()
  if (v.json) {
    console.log(JSON.stringify(identities, null, 2))
    return
  }
  if (identities.length === 0) {
    console.log('No agents are stored. Run: connectx did create')
    return
  }
  for (const i of identities) {
    const named = i.registered ? (i.lastDid ?? i.subject ?? '-') : 'not registered'
    console.log(`${i.agent}/${i.profile}  ${named}  ${i.curve ?? '?'}  ${i.dir}`)
  }
}

/** `connectx did create` — generate an independent random key for this (agent, profile)
 *  and seal it in the store. The public half of the key is what comes back out.
 *
 *  No DID is produced and none is recorded: the host half of a `did:wba` DID belongs to
 *  the DID server that hosts the document, so it arrives with `did register`, together
 *  with the handle. Until then the identity is a key and nothing else. */
async function runDidCreate(v: Values): Promise<void> {
  const location = currentLocation(v)
  const curve = ((v.curve as string | undefined) ?? 'ed25519') as ParsedKeyCurve
  const password = await resolvePassword(v)

  const { publicKey } = await initIdentity({
    location,
    curve,
    password,
    force: v.force === true,
  })

  if (v.json) {
    console.log(
      JSON.stringify(
        {
          agent: location.agent,
          profile: location.profile,
          curve,
          publicKey,
          registered: false,
          keyFile: location.keyFile,
          identityFile: location.identityFile,
        },
        null,
        2,
      ),
    )
  } else {
    const [keyLabel, keyValue] = publicKeyField(publicKey)
    console.log(`created identity for ${location.agent}/${location.profile}`)
    console.log(`curve:               ${curve}`)
    console.log(`${keyLabel.padEnd(21)}${keyValue}`)
    console.log(`key file:            ${location.keyFile}`)
    console.log(`identity:            ${location.identityFile}`)
    console.log()
    console.log('There is no DID yet. A did:wba DID names the server that hosts it, so the')
    console.log('host arrives with the registration. Run:')
    console.log(`  ${registerCommandHint(location)}`)
  }
  if (password === '') {
    console.error(
      'connectx: warning: stored key is encrypted with an EMPTY password (obfuscation only). Set CONNECTX_KEY_PASSWORD to encrypt at rest.',
    )
  }
}

/** `connectx anp sign` — produce RFC 9421 headers only (no network). */
async function runSign(v: Values): Promise<void> {
  require(v, 'target')
  const { config, connector } = await buildConnector(v, { requireRegistered: true })
  const sig = await signRequest(config, connector.id, {
    url: v.target as string,
    method: (v.method as string) ?? 'POST',
    nonce: (v.nonce as string) ?? '',
  })
  console.log(JSON.stringify(sig, null, 2))
}

/** `connectx anp login` — sign + POST, handle the 401 re-sign loop, print token, and
 *  (unless --no-save-session) cache the token under the target host.
 *
 *  One login, two renderers (Part W). A terminal at both ends gets a card it approves
 *  with ⏎; a pipe, a CI job, or anyone who passed `--json` gets the state stream. Neither
 *  adds a step to the login itself: this is the same `login()` the browser components
 *  call, and the two renderers exist so the agent's side of it is not a screenful of
 *  pretty-printed JSON that a machine has to guess its way through. */
async function runLogin(v: Values): Promise<void> {
  require(v, 'target')
  // Validate the TTL before the network round-trip, so a typo fails fast.
  const ttlSeconds = parseTtlSeconds(v['session-ttl'] as string | undefined)
  const target = v.target as string
  const saveSession = v['no-save-session'] !== true
  // The card is for a terminal reading a terminal. Anything else — a pipe, a redirected
  // file, a CI job — gets the stream, because a prompt nobody can answer is not a prompt.
  // `--json` forces the stream even on a TTY, which is how a person checks what their
  // machine sees.
  const interactive =
    v.json !== true && process.stdin.isTTY === true && process.stdout.isTTY === true
  const stream = !interactive

  const resolved = await buildConnector(v, { requireRegistered: true })
  const { config, connector, host, location, password, key } = resolved

  if (stream) writeEvent({ state: 'connecting', target })
  try {
    const identity = await connector.getIdentity()

    if (interactive) {
      process.stdout.write(
        `${renderCard({
          host,
          target,
          agent: `${location.agent}/${location.profile}`,
          did: identity.did,
          key,
          session: describeSession(saveSession, ttlSeconds),
        })}\n`,
      )
      if (v.yes !== true && !(await askApproval())) {
        throw cliError('cancelled', 'cancelled at the card; nothing was signed')
      }
    } else {
      writeEvent({ state: 'signing', did: identity.did, keyid: identity.keyid, key })
    }

    const outcome = await login(config, {
      connectorId: connector.id,
      nonce: (v.nonce as string) ?? '',
      targetUri: target,
      didChain: await didChainOptions(v, connector),
    })

    // Persisting is best-effort: a cache write must never turn a good login into a
    // failure. The token is still printed below — both paths coexist (ADR §2.5).
    let written: SessionWrite = 'skipped'
    if (outcome.token && saveSession) {
      try {
        await saveSessionToken({
          location,
          password,
          host,
          token: outcome.token,
          did: outcome.did,
          subject: outcome.subject,
          tokenType: outcome.tokenType,
          ttlSeconds,
        })
        written = 'saved'
      } catch (err) {
        written = 'failed'
        console.error(
          `connectx: warning: could not save session (${err instanceof Error ? err.message : String(err)})`,
        )
      }
    }

    if (stream) {
      writeEvent({ state: 'connected', session: written, outcome })
    } else {
      console.log(
        renderSummary({
          host,
          did: outcome.did,
          token: outcome.token,
          tokenType: outcome.tokenType,
          session: written,
          sessionFile: location.sessionFile,
        }),
      )
    }
  } catch (err) {
    reportSuperseded(err)
    if (stream) writeEvent(errorEvent(err))
    throw err
  }
}

/** The failure half of the stream. The operator also gets the message on stderr — that is
 *  the human channel, and it stays where it was; a machine reads this line and the exit
 *  code. A code raised by something the CLI does not own (a wallet provider) is carried
 *  through unchanged: `wallet_confirmation_required` is only useful to an agent if it
 *  reaches this line. */
function errorEvent(err: unknown): LoginEvent {
  if (err instanceof ConnectxError) {
    return {
      state: 'error',
      code: err.code,
      message: err.message,
      ...(err.status !== undefined ? { status: err.status } : {}),
    }
  }
  const code = (err as { code?: unknown })?.code
  return {
    state: 'error',
    code: typeof code === 'string' ? code : 'login_failed',
    message: err instanceof Error ? err.message : String(err),
  }
}

/** `connectx did register` — sign + POST a registration request (with a handle) to the
 *  DID server, print the outcome, and record it locally so the store stops reporting
 *  this identity as unregistered.
 *
 *  The peer here is the DID server, not the application: a handle is a readable alias
 *  bound to a `did:wba` DID (ANP-04), which is why this page sits in the `did` group and
 *  takes no `--wallet` — a CAIP-10 account id is not something a handle can bind to. */
async function runDidRegister(v: Values): Promise<void> {
  require(v, 'target', 'handle')
  const handle = v.handle as string
  // Two contracts, one command. `--rpc` selects the DID server's OWN JSON-RPC register
  // (ANP-03 §2.5.3 L427 leaves that interface to the implementation) instead of the ANP-02
  // signed request, and it changes what has to happen BEFORE the connector is built: the
  // document the server wants carries the server's own `ANPMessageService` entry, and the
  // proof covers whatever is in the document when it is signed. So discovery runs first,
  // and the connector is built from what it found.
  const discovered = v.rpc ? await discoverDidServer(v.target as string) : undefined
  const explicitHost = v.host as string | undefined
  let hostOverride: string | undefined
  if (discovered !== undefined) {
    // The discovered domain is the only one that is a fact rather than a guess about where
    // this identity belongs, so it outranks the recorded host and `--target`'s. The PORT is
    // the exception: a server reached at `127.0.0.1:8765` publishes as `did:wba:localhost`,
    // and `did:wba` spells a non-default port in the host segment (ANP-03 §2.1) — so the
    // port `--target` already names is carried over instead of being dropped.
    hostOverride = hostWithTargetPort(discovered.didDomain, v.target as string)
    if (explicitHost !== undefined && explicitHost !== hostOverride) {
      throw new ConnectxError(
        'invalid_argument',
        `--host ${explicitHost} contradicts the domain this server publishes for itself ` +
          `(${hostOverride}, from ${discovered.documentUrl}). The DID would be composed under a ` +
          `host the server does not serve, and it would refuse the registration as a foreign domain.`,
      )
    }
  }
  const { config, connector, host, location } = await buildConnector(
    v,
    discovered === undefined ? {} : { hostOverride, service: [discovered.service] },
  )
  let outcome: RegisterOutcome
  try {
    outcome = discovered
      ? await registerViaJsonRpc(config, {
          connectorId: connector.id,
          handle,
          targetUri: v.target as string,
        })
      : await register(config, {
          connectorId: connector.id,
          handle,
          nonce: (v.nonce as string) ?? '',
          targetUri: v.target as string,
          didChain: await didChainOptions(v, connector),
        })
  } catch (err) {
    reportSuperseded(err)
    // The SDK refuses a 2xx that came back as a web page (it would otherwise read as a
    // successful registration, since every field of the outcome is optional). That is
    // `--target` aimed at a site origin rather than at the register endpoint, and the
    // flag is worth naming here: the URL resolves and answers, so nothing else in the
    // error points at it. `status` is present only when a response actually arrived,
    // which is what separates this from an `invalid_argument` raised by a config value.
    if (
      err instanceof ConnectxError &&
      err.code === 'invalid_argument' &&
      typeof err.status === 'number' &&
      err.status >= 200 &&
      err.status < 300
    ) {
      throw new ConnectxError(
        'invalid_argument',
        `${err.message} — \`--target\` must be the DID server's register endpoint (the URL the signature ` +
          `is POSTed to), not the site's origin. The registration was not sent anywhere, so nothing was ` +
          `recorded for this identity.`,
        { cause: err, status: err.status },
      )
    }
    // A duplicate handle is a NORMAL outcome, not a transport failure, and the peer says
    // so machine-readably: the deployments we have tested answer 409 with their own
    // `code`, which the SDK passes through as `serverCode`. Without this the operator
    // would see only the SDK's generic message — the peer's prose is not in `message`,
    // because that field is built from `error` / `error_description`.
    //
    // Both readings are named on purpose. There is one name per handle and it is claimed
    // once, so the server cannot tell "someone else has it" from "you already claimed it
    // and your response was lost" — it has no reason to know, and guessing would be worse
    // than saying so. The operator knows which is which, so the message says both and
    // points at the way out: an already-registered identity just logs in.
    //
    // Three spellings, because the vocabulary is the server's: `handle_taken` is what the
    // deployments here answer, `handle_already_registered` / `did_already_registered` are
    // what others do. They are read in two groups rather than one, because the last one
    // rejects a different thing: a DID that is already on file is not a handle somebody
    // else holds, and telling the operator their HANDLE is taken would send them looking
    // for a name that was never the problem.
    const HANDLE_TAKEN = new Set(['handle_taken', 'handle_already_registered'])
    const DID_TAKEN = new Set(['did_already_registered'])
    if (err instanceof ConnectxError && err.serverCode !== undefined && HANDLE_TAKEN.has(err.serverCode)) {
      throw new ConnectxError(
        'register_failed',
        `Handle "${handle}" is already claimed on ${host} — either someone else holds it, or you already registered it. ` +
          `If it is yours, run \`connectx anp login\` instead; registration only needs to succeed once.`,
        { cause: err, status: err.status ?? 409, serverCode: err.serverCode },
      )
    }
    if (err instanceof ConnectxError && err.serverCode !== undefined && DID_TAKEN.has(err.serverCode)) {
      throw new ConnectxError(
        'register_failed',
        `This identity is already registered on ${host} — the DID is on file, so there is nothing to claim. ` +
          `Run \`connectx anp login\` to use it.`,
        { cause: err, status: err.status ?? 409, serverCode: err.serverCode },
      )
    }
    throw err
  }

  // R2.4: the registration HAS happened; making a note of it locally is a separate,
  // best-effort step that must never turn a good registration into a failure.
  //
  // This is where the store gains a host and a DID — before the server answered there was
  // neither to record, which is why the write is tied to the outcome rather than to the
  // create.
  let recorded = false
  try {
    recorded = recordRegistration({ location, host, handle: outcome.handle, did: outcome.did })
  } catch (err) {
    console.error(
      `connectx: warning: registered, but could not update ${location.identityFile} (${err instanceof Error ? err.message : String(err)})`,
    )
  }

  // The server has a document on file for this DID from here on, so this is the moment to
  // keep a copy of it: it is the document the next `did update` has to retire (§2.5.3
  // L417), and fetching it now saves that update a round trip. Silent on failure — a
  // server that publishes no document is not a registration problem, and the update
  // fetches for itself when there is no copy.
  const documentOnFile = await recordDidDocumentOnFile(outcome.did, location, v)

  if (v.json) {
    console.log(
      JSON.stringify(
        {
          ...outcome,
          agent: location.agent,
          profile: location.profile,
          host,
          local: { recorded, documentOnFile },
        },
        null,
        2,
      ),
    )
  } else {
    console.log(`registered handle "${outcome.handle}" on ${host}`)
    console.log(`did:      ${outcome.did}`)
    if (outcome.token) console.log(`token:    ${outcome.token}`)
    if (outcome.tokenType) console.log(`  type:   ${outcome.tokenType}`)
    if (outcome.token && outcome.tokenType && outcome.tokenType.toLowerCase() !== 'bearer') {
      console.log(
        '          the server named a token type other than "Bearer" — present this token as that',
      )
      console.log('          profile requires, not as a Bearer token (ANP-02 §3.2.3)')
    }
    console.log(
      recorded
        ? `local:    ${location.agent}/${location.profile} marked registered in ${location.identityFile}`
        : `local:    no identity store for ${location.agent}/${location.profile} — the key came from --key or $ANP_PRIVATE_KEY, so nothing was recorded`,
    )
    if (documentOnFile) {
      console.log(`document: a copy of the DID document on file is kept at ${location.documentFile}`)
    }
  }
}

/** The DID server to ask when a peer answers 409 `did_superseded`.
 *
 *  Derived from the DID itself, not from `--target`: the target is the application
 *  server, which is a different party from the one hosting our DID — and the host is
 *  part of the stable subject, so the walk can never legitimately leave it (ANP-03
 *  §2.5.3). No flag names it, and there is no default to override.
 *
 *  Configuring `didChain` is the whole request: on a 409 the SDK walks the chain and
 *  hangs the conclusion on the error, so the CLI prints what it found instead of asking
 *  the same question twice. Nothing registers `onDidSuperseded` — the key that was just
 *  retired cannot sign as its successor (an update means a NEW key), so an automatic
 *  retry would be a lie. */
async function didChainOptions(v: Values, connector: AnpConnector): Promise<DidChainOptions | undefined> {
  const { did } = await connector.getIdentity()
  let host: string
  try {
    host = didHost(did)
  } catch (err) {
    // A chain account (`eip155:1:0x…`) is an identity with NO document: `didToUrl` cannot
    // derive a URL from it because there is nothing to fetch. Continuity by document is a
    // `did:wba` fact, so there is no chain to walk and no 409 to answer — and configuring
    // an allowlist here would turn a working web3 login into a policy error.
    if (err instanceof ConnectxError && err.code === 'invalid_did') return undefined
    throw err
  }
  const relaxed = relaxedHosts([host], v)
  return {
    allowedHosts: [host],
    ...(relaxed.length > 0 ? { allowPrivateHosts: relaxed, allowInsecureTransport: relaxed } : {}),
  }
}

/** Say what a 409 `did_superseded` means, keeping the two halves apart: what the peer
 *  CLAIMED (worth nothing on its own — ANP-03 §3.2 calls it an unverified hint) and
 *  what our own walk of the DID's own documents VERIFIED. Silence for every other
 *  error: the caller's own handler prints those. */
function reportSuperseded(err: unknown): void {
  if (!(err instanceof ConnectxError) || err.code !== 'did_superseded') return
  const info = err.didSuperseded
  console.error(`connectx: ${info?.requestedDid ?? 'this DID'} has been superseded.`)
  if (info?.claimedCurrentDid !== undefined) {
    console.error(`connectx: peer claims:      ${info.claimedCurrentDid}  (NOT verified — ANP-03 §3.2)`)
  }
  if (info?.verifiedCurrentDid !== undefined) {
    const hops = info.chain?.hops.length ?? 0
    console.error(
      `connectx: verified current: ${info.verifiedCurrentDid}  (${info.chain?.assurance}, ${hops} hop${hops === 1 ? '' : 's'} through this DID's own documents)`,
    )
  }
  console.error(
    'connectx: this key can no longer sign. If it was moved on from here: `connectx did update --resume` (when a successor is staged) or restore the successor key.',
  )
}

interface BuildConnectorOptions {
  /** Refuse a stored identity that no DID server has taken on yet.
   *
   *  Everything except `did register` composes a DID, and a DID needs the host the
   *  registration recorded. Without this the composition would fall back to whatever
   *  `--target` happens to name — producing a DID no server hosts, which is a different
   *  (and unowned) identity rather than a missing one. `did register` is the one command
   *  that runs BEFORE there is a host, and it is the command that supplies it. */
  requireRegistered?: boolean
  /** The DID host to compose the identity under, read from the server itself
   *  (`discoverDidServer`). It outranks the recorded host and the target's, because those
   *  are guesses about where this identity belongs while this one was read from the party
   *  that decides: a DID composed under any other host is refused as a foreign domain. */
  hostOverride?: string
  /** Service entries to publish in the built DID document. A server that judges the
   *  submitted document against its OWN `ANPMessageService` needs that entry in the
   *  document BEFORE the proof is made — see `anpCli`'s `service` option. */
  service?: DidDocumentServices
}

export async function buildConnector(v: Values, opts: BuildConnectorOptions = {}): Promise<Resolved> {
  const wallet = (v.wallet as string) ?? 'cli'
  const chainId = v['chain-id'] as string | undefined
  const address = v.address as string | undefined
  const explicitHost = v.host as string | undefined
  const location = currentLocation(v)
  // Resolve the password once here (never inside resolveCliKey): --password-stdin
  // is a one-shot read, and the session write needs the same value.
  const password = await resolvePassword(v)
  // The acting agent goes into the path-type DID, so two agents on one host get
  // distinct DIDs. Ignored when the DID is a CAIP-10 account id.
  const path = ['user', location.agent]

  if (wallet === 'cli') {
    const { key: parsed, storedHost, source } = await resolveCliKey(v, password)
    const key: KeyLocation = { source, curve: parsed.curve }
    if (opts.requireRegistered === true && source === 'store' && storedHost === undefined) {
      throw new ConnectxError(
        'identity_not_registered',
        `Identity for agent "${location.agent}" profile "${location.profile}" is not registered on a DID server, so it has no DID yet. Run:\n  ${registerCommandHint(location)}`,
      )
    }
    // --host > the host the REGISTRATION recorded > the target's host.
    //
    // A recorded host exists only after a DID server has accepted the key, and the host
    // is part of the subject: `did:wba:a.example:user:x` and `did:wba:b.example:user:x`
    // are DIFFERENT identities that merely share a key. So once one is on file it has to
    // outrank `--target`, which merely says where this request is going. `--host` still
    // wins, because naming it is how a caller deliberately points the composition
    // somewhere the registration did not.
    //
    // The target fallback is left for BARE MATERIAL (`--key` / `$ANP_PRIVATE_KEY`), which
    // has no store record to read a host from: there the caller names the server by naming
    // the target, and a stored identity never reaches it — see `requireRegistered`.
    const host = explicitHost || opts.hostOverride || storedHost || hostFromTarget(v.target as string | undefined)
    // Derive an EVM-style address for secp256k1 when a chain is given but the user
    // didn't pass --address, so the DID is a proper CAIP-10 account id.
    let caipAddress = address
    if (chainId && !caipAddress && parsed.curve === 'secp256k1') {
      caipAddress = evmAddress(parsed.privateKey)
    }
    const connector = anpCli(parsed, { host, chainId, address: caipAddress, path, service: opts.service })
    // `anpCli` wraps the same key in the same local wallet (`toWallet`), so a caller
    // signing its own proof signs with exactly the key this connector signs with.
    const wallet = keypairWallet(parsed.privateKey, { curve: parsed.curve })
    return { config: createConfig([connector], connector.id), connector, wallet, host, location, password, key }
  }

  if (wallet === 'web3') {
    // `--chain-id` is required, not optional. Without it the host would come from
    // `--target`, composing `did:wba:<the-server-we-happen-to-call>:…:k1_<fp>` — an
    // identity under a host that never accepted this key. The fingerprint makes the
    // inline document self-certifying, so nothing downstream catches it: the server
    // IS the impersonated host and never checks that its own DID server registered
    // the key. `--wallet cli` refuses that same shape (see `requireRegistered`); a
    // wallet has even less claim to a host, so a chain account is the only identity
    // this path may produce.
    require(v, 'provider', 'address', 'chain-id')
    const host = explicitHost || hostFromTarget(v.target as string | undefined)
    const provider = await loadProvider(v.provider as string)
    const w = chainWallet(provider, { address: address as string, chainId })
    const connector = chainWalletConnector(w, { host, chainId, address, path })
    return {
      config: createConfig([connector], connector.id),
      connector,
      wallet: w,
      host,
      location,
      password,
      // A wallet connector holds its own key; this side never sees a curve or a byte.
      key: { source: 'wallet' },
    }
  }

  throw new Error(`--wallet must be "web3" or "cli" (got "${wallet}")`)
}

interface ResolvedCliKey {
  key: ParsedKey
  /** The host this identity is REGISTERED under — set only when the key came from the
   *  store AND a DID server has taken it on, because that is the only way a host is ever
   *  learned. `undefined` for `--key` / `$ANP_PRIVATE_KEY` (bare material with no identity
   *  behind it, so the host has to come from the caller) and for a stored identity that is
   *  still unregistered. */
  storedHost?: string
  /** Which of the four resolution steps answered — the card says it, so an operator can
   *  tell a stored identity from key material handed in on the command line. */
  source: 'store' | 'material'
}

// Resolve the local signing key for `--wallet cli`, in order:
//   1. `--key <spec>`         explicit material (power user / CI) — unchanged
//   2. identity store         `--agent`/`--profile` names an identity, never a key
//   3. `$ANP_PRIVATE_KEY`     backward compat with the scaffolded templates
//   4. otherwise              `identity_not_found` — NEVER created implicitly
//
// `password` was already resolved by the caller (shared with the session write).
async function resolveCliKey(v: Values, password: string): Promise<ResolvedCliKey> {
  const bip39Path = v['bip39-path'] as string | undefined
  const curve = (v.curve as ParsedKeyCurve | undefined) ?? undefined

  if (v.key) {
    const raw = readKeyArg(v.key as string)
    // Only a keystore needs a password — don't prompt or read stdin otherwise.
    const pw = detectFormat(raw) === 'keystore' ? password : undefined
    return { key: await loadKeyMaterial(raw, { password: pw, bip39Path, curve }), source: 'material' }
  }

  const location = storeLocation(
    resolveAgentId(v.agent as string | undefined),
    resolveProfileName(v.profile as string | undefined),
  )
  if (hasStoredKey(location)) {
    return {
      key: await loadStoredKey(location, password),
      storedHost: readIdentity(location)?.host,
      source: 'store',
    }
  }

  const envKey = process.env.ANP_PRIVATE_KEY
  if (envKey && envKey.trim() !== '') {
    const raw = readKeyArg(envKey)
    const pw = detectFormat(raw) === 'keystore' ? password : undefined
    return { key: await loadKeyMaterial(raw, { password: pw, bip39Path, curve }), source: 'material' }
  }

  throw new ConnectxError(
    'identity_not_found',
    `No identity for agent "${location.agent}" profile "${location.profile}" (${location.dir}). Run: connectx did create`,
  )
}

// Dynamic-import an EIP-1193 provider from a module spec. The provider is likely a
// wallet bridge (MetaMask/OKX/Anvil remote) — the private key never enters the agent.
//
// A path is resolved against the current working directory, not the cli.js location:
// a dynamic import is relative to the importing module, which is the bundled
// `dist/cli.js`, so an unresolved relative spec would point at the wrong tree.
//
// Anything that is NOT a file beside the cwd is handed to Node as a bare module
// specifier. Before that fallback existed, `--provider okx-provider` was read as a
// file literally named `okx-provider` in the cwd and failed with an
// ERR_MODULE_NOT_FOUND naming that path — a resolution error aimed at a directory
// the caller never meant. A bare name has to reach Node's own resolution, which is
// where a package name is looked up.
async function loadProvider(spec: string): Promise<Eip1193Provider> {
  const ns = (await import(importTarget(spec))) as Record<string, unknown>
  const provider = ns.default ?? ns.provider ?? ns
  return provider as Eip1193Provider
}

/** A module spec as something `import()` can take, by the rule the note above states. The
 *  one seam that needs it is `--provider` — a dependency the caller installs and this CLI
 *  never declares. */
function importTarget(spec: string): string {
  const asFile = resolve(process.cwd(), spec)
  return spec.startsWith('.') || isAbsolute(spec) || existsSync(asFile) ? asFile : spec
}

function hostFromTarget(target?: string): string {
  if (!target) return 'localhost'
  try {
    return new URL(target).host
  } catch {
    return 'localhost'
  }
}

/** The domain a server publishes for itself, with `--target`'s port added when that domain
 *  does not name one. The domain is read, never guessed — but the port is not something the
 *  server's self document has to repeat: `--target` already names the exact host:port this
 *  registration goes to, and a `did:wba` host segment spells a non-default port as `%3Aport`
 *  (ANP-03 §2.1). Dropping it composes a DID the server never stored. */
function hostWithTargetPort(domain: string, target?: string): string {
  if (domain.includes(':') || target === undefined) return domain
  try {
    const { port } = new URL(target)
    return port === '' ? domain : `${domain}:${port}`
  } catch {
    return domain
  }
}

// secp256k1 → EVM address (last 20 bytes of keccak256 of the uncompressed point).
function evmAddress(privateKey: Uint8Array): string {
  const pub = secp256k1.getPublicKey(privateKey, false) // 65-byte uncompressed (0x04 prefix)
  const hash = keccak_256(pub.slice(1))
  return (
    '0x' +
    Array.from(hash.slice(-20))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
}

export function require(v: Values, ...keys: string[]) {
  for (const k of keys) {
    if (v[k] === undefined || v[k] === '') {
      throw cliError('missing_flag', `missing required option --${k}`)
    }
  }
}

// Resolve an at-rest key password WITHOUT routing it through argv, where it would
// leak into `ps`, shell history and CI logs. Sources, in order: --password-file,
// --password-stdin, $CONNECTX_KEY_PASSWORD, else empty (unencrypted / dev). The
// store is written with whatever this returns; reads must supply the same value.
//
// Exported because `did update` reads and WRITES store key material and must resolve
// the password the same way — and because `--password-stdin` is a one-shot read, every
// caller in one process has to share one answer rather than read stdin twice.
export async function resolvePassword(v: Values): Promise<string> {
  const file = v['password-file'] as string | undefined
  if (file) return readFileSync(file, 'utf8').replace(/\r?\n$/, '')
  if (v['password-stdin']) return readStdinLine()
  if (process.env.CONNECTX_KEY_PASSWORD !== undefined) return process.env.CONNECTX_KEY_PASSWORD
  return ''
}

function readStdinLine(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ''
    process.stdin.setEncoding('utf8')
    process.stdin.on('data', (c) => (data += c))
    process.stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')))
    process.stdin.on('error', reject)
  })
}
