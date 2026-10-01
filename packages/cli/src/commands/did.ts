// `connectx did resolve` — a thin shell over the SDK's DID document / update-chain
// queries. No protocol logic lives here: the SDK decides what a hop's assurance is,
// whether a chain verifies, and whether a document is still current. This module
// parses arguments, prints, and maps the OUTCOME onto an exit code.
//
// `connectx did update` — the WRITE half of the same pair. It owns the one thing the
// SDK deliberately does not: the KEY LIFECYCLE on disk. The SDK signs the two documents
// and delivers the hop; deciding that a new key is needed, where it is kept until the
// server has spoken, and what the store looks like afterwards is the CLI's job, because
// only the CLI has a store (ADR-0001 §2.2 — the local key is never the protocol's).
//
// Exit codes (documented in HELP + packages/cli/README.md). They are scoped to THIS
// command: every other command keeps the plain 0/1 it always had.
//   0  the DID is current (or the document resolved and is not superseded)
//   2  the DID is NOT current — the chain walked on to another DID, or the document
//      itself is a retirement (`deactivated` / `successorDid`)
//   3  the update chain did not verify (`did_chain_broken`)
//   1  anything else: network, policy, bad input
//
// Nothing here ANSWERS from a cache: without a store the SDK re-fetches, and with one
// the query still goes to the network, because a cached answer would defeat the point of
// asking. What `did resolve` does leave behind is a COPY of the document it was served —
// the evidence a later `did update` needs, since a retirement document has to be the one
// the server has on file (ANP-03 §2.5.3 L417). Recording what was served, in one
// direction only, is not the same thing as answering from it.

import { isDeepStrictEqual } from 'node:util'
import { resolveDidChain, resolveDidDocument, isSuperseded, update, anpCli, createConfig, didToUrl, errorCode, ConnectxError } from '@agentx/core'
import type { DidChain, DidChainOptions, ParsedKey, ResolvedDidDocument, ResolveDidOptions, UpdateOutcome } from '@agentx/core'
import { storeLocation, resolveAgentId, resolveProfileName, type StoreLocation } from '../identity/paths'
import {
  discardStagedSuccessor,
  generateSuccessorKey,
  hasStagedSuccessor,
  hasStoredKey,
  installSuccessor,
  loadStagedSuccessorKey,
  loadStoredKey,
  readDidDocumentCopy,
  readIdentity,
  stageSuccessorKey,
  writeDidDocumentCopy,
  type StoredIdentity,
} from '../identity/store'
import type { Values } from './auth'
import { resolvePassword } from './auth'

export const DID_EXIT = {
  current: 0,
  error: 1,
  superseded: 2,
  chainBroken: 3,
} as const

/** `connectx did resolve <did> [--chain] [--json] …`. Returns the process exit code.
 *
 *  `create` / `show` / `list` / `register` are the other half of `did` and live in
 *  `auth.ts`; cli.ts routes them before reaching here, so the throw below names every
 *  subcommand a user could have meant. */
export async function runDid(v: Values, sub: string | undefined, did: string | undefined): Promise<number> {
  try {
    if (sub === 'update') return await runDidUpdate(v)
    // `did restore` is reserved, not implemented: the SDK has no recovery path, so the
    // command states its own absence instead of half-doing one. Throwing puts it on the
    // plain 0/1 line with the same wording as its help page.
    if (sub === 'restore') {
      throw new Error('did restore is in development: nothing was read and nothing was restored')
    }
    if (sub !== 'resolve') {
      throw new Error(
        `Unknown "did" subcommand "${sub ?? ''}" (expected: create | show | list | register | resolve | restore | update)`,
      )
    }
    if (did === undefined || did === '') {
      throw new Error('Missing required argument <did>')
    }
    // These two tune the chain's acceptance policy, not the network. Silently ignoring
    // them in document mode would let a caller believe a policy was applied.
    if (!v.chain && (v['accept-provider-asserted'] || v['report-low-assurance'])) {
      throw new Error('--accept-provider-asserted / --report-low-assurance only apply to --chain')
    }
    const options = resolveOptions(v)
    return v.chain ? await chainMode(did, chainOptions(v, options), v) : await documentMode(did, options, v)
  } catch (err) {
    const code = err instanceof ConnectxError ? err.code : undefined
    const message = err instanceof Error ? err.message : String(err)
    // Under --json the failure is a machine-readable object on stderr, so a caller
    // parsing stdout for a result never confuses the two streams.
    if (v.json) console.error(JSON.stringify({ ok: false, code: code ?? null, error: message }, null, 2))
    else {
      console.error(`connectx: ${message}`)
      const hint = blockedHostHint(err, did)
      if (hint !== null) console.error(hint)
    }
    // Exit 3 belongs to `did resolve`, whose entire output IS the chain verdict.
    // `did update --resume` walks a chain too, but its 0/1 answers a different question
    // (did the store move?), so it stays in the plain vocabulary.
    const chainBroken = code === 'did_chain_broken' && sub !== 'update'
    return chainBroken ? DID_EXIT.chainBroken : DID_EXIT.error
  }
}

/** One document, no chain: "give me what this DID publishes right now". */
async function documentMode(did: string, options: ResolveDidOptions, v: Values): Promise<number> {
  const entry = await resolveDidDocument(did, options)
  // The query is answered from the network above, always. This only leaves a copy
  // behind, and only for this store's OWN DID — see `recordServedDocument`.
  recordServedDocument(entry, v)
  // The SDK returns a superseded document on purpose (it is evidence, and the
  // document-level call has no successor to offer). Saying so is the caller's job —
  // that is exactly what `isSuperseded` is exported for.
  const superseded = isSuperseded(entry.document)
  if (v.json) {
    console.log(JSON.stringify({ ...entry, superseded }, null, 2))
  } else {
    console.log(`did:      ${entry.did}`)
    console.log(`docUrl:   ${entry.docUrl}`)
    console.log(`source:   ${entry.source}`)
    console.log(`status:   ${superseded ? 'SUPERSEDED (not current — pass --chain to find the current DID)' : 'current'}`)
    console.log()
    console.log(JSON.stringify(entry.document, null, 2))
  }
  return superseded ? DID_EXIT.superseded : DID_EXIT.current
}

/** Leave behind the document the server just served, when the DID resolved is this
 *  store's OWN identity.
 *
 *  Only for the identity's own DID, because that is the only DID this CLI will ever have
 *  to retire: `did update` bases the retirement document on the one on file (§2.5.3
 *  L417), and it can only do that for the DID it holds a key for. A single copy slot per
 *  identity is what makes that possible — recording every DID ever resolved would let the
 *  last unrelated query evict the one document an update needs.
 *
 *  This is NOT a read path. The answer above came from the network and always will; the
 *  copy exists only so the next update does not have to go and get it.
 *
 *  Drift is reported (stderr, so a `--json` caller's stdout stays pure): a local copy that
 *  disagrees with what the server serves is the same class of mismatch an update hop would
 *  otherwise paper over. */
function recordServedDocument(entry: ResolvedDidDocument, v: Values): void {
  try {
    const location = storeLocation(
      resolveAgentId(v.agent as string | undefined),
      resolveProfileName(v.profile as string | undefined),
    )
    const stored = readIdentity(location)
    if (stored === null || stored.lastDid !== entry.did) return
    const previous = readDidDocumentCopy(location)
    // Compared deeply rather than as text: the copy is re-serialized through
    // `JSON.stringify`, so key order is not a difference in the document.
    if (previous !== null && previous.did === entry.did && !isDeepStrictEqual(previous.document, entry.document)) {
      console.error(
        `connectx: note: the copy at ${location.documentFile} differs from what this DID now serves (${entry.docUrl}); it has been refreshed.`,
      )
    }
    writeDidDocumentCopy(location, { did: entry.did, document: entry.document, fetchedAt: entry.fetchedAt })
  } catch {
    // A side effect of a query that already succeeded — never fail the query over it.
  }
}


/** The whole update chain: "is the DID I hold still current, and how strongly was
 *  each hop proven". */
async function chainMode(did: string, options: DidChainOptions, v: Values): Promise<number> {
  const chain = await resolveDidChain(did, options)
  if (v.json) {
    console.log(JSON.stringify(chain, null, 2))
  } else {
    printChain(chain)
  }
  return chain.superseded ? DID_EXIT.superseded : DID_EXIT.current
}

function printChain(chain: DidChain): void {
  console.log(`did:         ${chain.did}`)
  console.log(`subject:     ${chain.subject}`)
  console.log(`currentDid:  ${chain.currentDid}`)
  console.log(`superseded:  ${chain.superseded ? 'yes' : 'no'}`)
  // Weakest hop wins (no hops = verified). Printed without interpretation: the CLI
  // does not decide whether an assurance is acceptable, the SDK's policy already did.
  console.log(`assurance:   ${chain.assurance}`)
  console.log(`docUrl:      ${chain.docUrl}`)
  console.log(`hops:        ${chain.hops.length}`)
  chain.hops.forEach((hop, i) => {
    console.log(`  [${i + 1}] ${hop.did} → ${hop.successorDid}`)
    console.log(
      `      assurance=${hop.assurance} source=${hop.source}${hop.proofKeyId ? ` proofKeyId=${hop.proofKeyId}` : ''}`,
    )
  })
}

/** `connectx did update --target <uri>` — retire this identity's DID in favour of a
 *  newly generated key, and hand the hop to the DID server that hosts it.
 *
 *  Three things happen in a strict order, and the order is the whole design:
 *
 *    1. a successor key is generated and STAGED (`key.next`) — before anything is sent,
 *       so a crash after the server accepts cannot lose the only copy of the key the DID
 *       has been updated to;
 *    2. the hop is delivered (the SDK signs the retirement + successor documents and
 *       POSTs them, signed by the retiring DID);
 *    3. only once the server has ACCEPTED does the store move — the new key becomes
 *       `key`, and `subject` / `registered` / `handle` / `createdAt` are carried over.
 *
 *  A failure at step 2 leaves the store exactly as it was. Whether the staged key is
 *  dropped or kept depends on whether the failure told us the hop was refused; see the
 *  catch below.
 *
 *  Nothing here is protocol logic: the CLI chooses the key, the endpoint and the disk
 *  layout. What a hop IS — which document is signed by which key, what makes it
 *  verifiable — belongs to the SDK, and where to deliver it is the DID server's own
 *  contract (ANP-03 §2.5.3 defines no management interface), which is why `--target` is
 *  required rather than derived. */
async function runDidUpdate(v: Values): Promise<number> {
  if (v.resume) return await runDidUpdateResume(v)

  const targetUri = (v.target as string | undefined) ?? ''
  if (targetUri === '') {
    throw new Error("Missing required option --target (the DID server's own update endpoint)")
  }

  const location = storeLocation(
    resolveAgentId(v.agent as string | undefined),
    resolveProfileName(v.profile as string | undefined),
  )
  const stored = readIdentity(location)
  if (stored === null || !hasStoredKey(location)) {
    throw new ConnectxError(
      'identity_not_found',
      `No identity for agent "${location.agent}" profile "${location.profile}" (${location.dir}). An update replaces the key of an identity already on file — run: connectx did create`,
    )
  }
  const password = await resolvePassword(v)
  const host = registeredHost(stored, location)
  const key = await loadStoredKey(location, password)
  const identity = await storedConnector(key, host, location).getIdentity()

  // The DID being retired has to be the one this CLI derives for this identity, or the
  // server would be asked to retire an identifier it does not host. `lastDid` is the last
  // DID this store knew; a mismatch means the store was written under a different
  // host/path convention (or hand-edited), which is worth stopping on rather than
  // delivering a hop about the wrong DID.
  if (stored.lastDid !== undefined && stored.lastDid !== '' && stored.lastDid !== identity.did) {
    throw new ConnectxError(
      'invalid_argument',
      `Refusing to update: identity.json records lastDid "${stored.lastDid}", but host "${host}" + path "user/${location.agent}" derive "${identity.did}". The store does not follow this CLI's convention — fix the store, or update by hand.`,
    )
  }

  // The retirement half has to be THE document on file, not one composed here (see
  // `retirementBase`). Resolved before the successor is generated so a failure to reach
  // the server costs nothing: nothing has been staged and nothing has been signed yet.
  const baseDocument = await retirementBase(identity.did, location, v)
  const retiring = storedConnector(key, host, location, baseDocument)

  const successorKey = generateSuccessorKey(stored.curve)
  const successor = await storedConnector(successorKey, host, location).getIdentity()
  // Checked on the SUBJECT, which is the thing an update must preserve (§2.5.3); the SDK
  // enforces the same rule on the delivery. Failing here instead means the operator gets
  // the store's convention named, rather than the SDK's bare "keeps the stable subject
  // path" message about two DIDs they never typed.
  if (stored.subject !== undefined && stored.subject !== '' && successor.subject !== stored.subject) {
    throw new ConnectxError(
      'invalid_argument',
      `Refusing to update: this identity's stable subject is "${stored.subject}", but a successor derived from host "${host}" + path "user/${location.agent}" lands on "${successor.subject}". An update keeps the subject and moves only the key.`,
    )
  }

  await stageSuccessorKey({ location, password, privateKey: successorKey.privateKey })

  let outcome: UpdateOutcome
  try {
    outcome = await update(createConfig([retiring], retiring.id), {
      connectorId: retiring.id,
      targetUri,
      nonce: (v.nonce as string) ?? '',
      successorDid: successor.did,
      successorDocument: successor.didDocument,
    })
  } catch (err) {
    // Whether the staged key is still worth anything depends on whether we LEARNED that
    // the hop was refused. A local refusal (never sent, `invalid_argument`) or a peer that
    // answered with an error (`update_failed`) both settle it: nothing was updated, so the
    // key has no identity to belong to and is dropped. Anything else — a connection that
    // dropped, a timeout, a body we could not read — is genuinely AMBIGUOUS: the server
    // may well have accepted the hop. Deleting the key then would be the one
    // unrecoverable move available, so it is kept and the operator is told where.
    if (SETTLED_FAILURES.has(errorCode(err) ?? '')) {
      discardStagedSuccessor(location)
    } else {
      console.error(
        `connectx: warning: the update delivery to ${targetUri} did not complete, and whether the server accepted it is NOT knowable from here.\n` +
          `connectx: warning: the successor key has been KEPT at ${location.stagedKeyFile} (the store itself is unchanged).\n` +
          `connectx: warning: check with \`connectx did resolve ${identity.did} --chain --allow-host ${host}\`; if the hop WAS accepted, that file is the only key for ${successor.did}.`,
      )
    }
    throw err
  }

  const installed = await installSuccessor({
    location,
    password,
    privateKey: successorKey.privateKey,
    identity: successor,
  })

  if (v.json) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          agent: location.agent,
          profile: location.profile,
          subject: installed.subject,
          retiringDid: outcome.did,
          successorDid: outcome.successorDid,
          acceptedBy: targetUri,
          keyFile: location.keyFile,
          identityFile: location.identityFile,
        },
        null,
        2,
      ),
    )
    return DID_EXIT.current
  }

  console.log(`updated ${installed.subject}`)
  console.log(`retiring did:  ${outcome.did}`)
  console.log(`successor did: ${outcome.successorDid}`)
  console.log(`accepted by:   ${targetUri}`)
  console.log(`local:         ${location.agent}/${location.profile} now signs as the successor (registered / handle kept)`)
  console.log()
  console.log('The server is the authority on whether the successor is now current; confirm with:')
  console.log(`  connectx did resolve ${outcome.successorDid} --chain --allow-host ${stored.host}`)
  return DID_EXIT.current
}

/** `connectx did update --resume` — settle an update whose delivery outcome nobody
 *  knows yet, by ASKING the DID server which DID it serves as current.
 *
 *  This is the third act that `did update` deliberately leaves open. When the delivery
 *  fails ambiguously the staged key is kept (see `runDidUpdate`), because the server may
 *  well have accepted the hop — and until now the only way to find out was to read the
 *  chain by hand and edit the store by hand, which is exactly what staging exists to
 *  avoid. The question this answers is a single one: **is the staged successor the DID
 *  the server now serves?**
 *
 *  One answer comes from the DID server's own documents, never from the store and never
 *  from a guess: the store's `lastDid` is only the DID to start the walk from. Three
 *  outcomes, and each is a different fact about the world:
 *
 *    the server serves the staged successor  → the hop landed; promote the key (exit 0)
 *    the server still serves `lastDid`       → the hop did NOT land; drop `key.next` (exit 1)
 *    the server serves a third DID           → someone else moved it on; touch NOTHING,
 *                                              keep `key.next` (exit 1)
 *
 *  The last case is why nothing is cleaned up on an unknown answer: `key.next` may still
 *  be the only copy of a key that a later hop needs, and it is cheaper to leave a file
 *  the operator can delete than to destroy the only key to a DID. */
async function runDidUpdateResume(v: Values): Promise<number> {
  if (v.target !== undefined) {
    throw new Error(
      '--resume settles an update that was already attempted, so it takes no --target. To deliver a NEW hop, run `connectx did update --target <uri>`',
    )
  }

  const location = storeLocation(
    resolveAgentId(v.agent as string | undefined),
    resolveProfileName(v.profile as string | undefined),
  )
  const stored = readIdentity(location)
  if (stored === null || !hasStoredKey(location)) {
    throw new ConnectxError(
      'identity_not_found',
      `No identity for agent "${location.agent}" profile "${location.profile}" (${location.dir}). Run: connectx did create`,
    )
  }
  if (!hasStagedSuccessor(location)) {
    throw new ConnectxError(
      'identity_not_found',
      `Nothing to resume: there is no staged successor at ${location.stagedKeyFile}. That file only exists between \`did update\` starting and its outcome being settled.`,
    )
  }
  const from = stored.lastDid ?? ''
  if (from === '') {
    throw new ConnectxError(
      'invalid_argument',
      `identity.json records no lastDid, so there is no DID to ask the server about (${location.identityFile}).`,
    )
  }

  const password = await resolvePassword(v)
  const host = registeredHost(stored, location)
  const stagedKey = await loadStagedSuccessorKey(location, password)
  const successor = await storedConnector(stagedKey, host, location).getIdentity()

  // The whole point: ask the DID server, with the identity's OWN host as the only
  // allowlisted one — see `ownHostOptions` for why that is derived and not a flag.
  const chain = await resolveDidChain(from, ownHostOptions(from, v))

  if (chain.currentDid === successor.did) {
    const installed = await installSuccessor({
      location,
      password,
      privateKey: stagedKey.privateKey,
      identity: successor,
    })
    if (v.json) {
      console.log(
        JSON.stringify(
          {
            ok: true,
            resumed: true,
            agent: location.agent,
            profile: location.profile,
            subject: installed.subject,
            supersededDid: from,
            currentDid: chain.currentDid,
            assurance: chain.assurance,
            keyFile: location.keyFile,
          },
          null,
          2,
        ),
      )
      return DID_EXIT.current
    }
    console.log(`resumed ${installed.subject}`)
    console.log(`superseded did: ${from}`)
    console.log(`current did:    ${chain.currentDid}`)
    console.log(`assurance:      ${chain.assurance}`)
    console.log(`local:          ${location.agent}/${location.profile} now signs as the successor`)
    return DID_EXIT.current
  }

  if (!chain.superseded) {
    // The server still serves the OLD DID as the active one, so the hop was never
    // accepted. `key.next` therefore has no identity to belong to, and keeping it would
    // only make the next `--resume` ask the same settled question.
    discardStagedSuccessor(location)
    throw new ConnectxError(
      'update_failed',
      `The update was NOT accepted: the DID server still serves ${from} as current, so the staged successor (${successor.did}) was never published. The staged key has been dropped; retry with \`connectx did update --target <uri>\`.`,
    )
  }

  throw new ConnectxError(
    'did_superseded',
    `${from} has been superseded to ${chain.currentDid} (${chain.assurance}), which is NOT the staged successor ${successor.did}. Something else moved this DID on. Nothing was changed: the staged key is kept at ${location.stagedKeyFile}, and the store still holds the key it had.`,
  )
}

/** Failures that PROVE the hop was not delivered: a local refusal (nothing was signed or
 *  sent) and a peer that answered with an error status. Everything else is ambiguous by
 *  construction, so it is not in this set — see the catch in `runDidUpdate`. */
const SETTLED_FAILURES = new Set(['invalid_argument', 'connector_unavailable', 'update_failed'])

/** The ONE place the store's host/path convention is spelled out. Building BOTH the
 *  retiring and the successor connector here is what makes the successor land on the same
 *  stable subject path (§2.5.3) by construction — two constructions free to drift apart
 *  would produce a hop the SDK refuses.
 *
 *  `baseDocument` is the retiring connector's ONLY parameter: the successor is a fresh key
 *  whose document is composed from it, and the retiring side hands over the document the
 *  server has on file so the retirement half is built from that one (`retirementBase`). */
function storedConnector(
  key: ParsedKey,
  host: string,
  location: StoreLocation,
  baseDocument?: Record<string, unknown>,
) {
  return anpCli(key, {
    host,
    path: ['user', location.agent],
    ...(baseDocument === undefined ? {} : { baseDocument }),
  })
}

/** The `did register` invocation that would take THIS identity on, for the commands
 *  that need a host it does not have yet.
 *
 *  `--agent` names the identity the reader is actually looking at: a command that left
 *  it off would address the detected default and register some other key. `--profile`
 *  is printed only when it is not `default`, which is the same "a default value is
 *  omitted" rule the help pages use. `--target` is an EXAMPLE rather than a `<uri>`
 *  placeholder — no DID server is recorded before a registration, so there is no fact
 *  to print, and the DID server's own register contract is served under a fixed path
 *  (ADR-0003), which is the one part of the command the reader cannot guess. The handle
 *  stays a placeholder: the server owns its syntax and only the caller can pick it. */
export function registerCommandHint(location: StoreLocation): string {
  const profile = location.profile === 'default' ? '' : ` --profile ${location.profile}`
  return (
    `connectx did register --agent ${location.agent}${profile} ` +
    '--target http://127.0.0.1:8765/user-service/v1/did-auth/rpc --handle <name> --rpc'
  )
}

/** The host this identity is registered under, or a refusal when it has none.
 *
 *  A `did:wba` DID is `did:wba:<host>:<path>`, and the host belongs to the DID server
 *  hosting the document (§2.5.3 L409 names the file). So an identity no server has taken
 *  on has no DID — which makes everything here (retire the current DID, derive its
 *  successor, resolve what the server serves) unanswerable rather than merely unknown. */
function registeredHost(stored: StoredIdentity, location: StoreLocation): string {
  if (!stored.registered || stored.host === undefined || stored.host === '') {
    throw new ConnectxError(
      'identity_not_registered',
      `Identity for agent "${location.agent}" profile "${location.profile}" is not registered on a DID server, so there is no DID and nothing to update. Run:\n  ${registerCommandHint(location)}`,
    )
  }
  return stored.host
}

/** The document a retirement hop is built on, in the only order that can be trusted:
 *  the copy this CLI already holds, else one fetched now, else `undefined` — which makes
 *  the SDK compose one from the key.
 *
 *  Why the copy first: ANP-03 §2.5.3 L417 says the OLD DID document gets `deactivated` +
 *  `successorDid`, and L419 says the re-made proof covers the properties it carries. A
 *  document composed here holds only what a `did:wba` builder produces — no `service`
 *  endpoint, no keys added out of band (L411 allows both without changing the DID) — so
 *  composing produces a retirement document that ISN'T the one on file, and the server
 *  has every right to reject it.
 *
 *  The copy is used only when it names the DID being retired. A copy from before a key
 *  change describes the DID that was current then, so it can never match (the DID embeds
 *  the key fingerprint, §2.5.3 L413) — which is what makes a stale copy inert.
 *
 *  The last step is a FALLBACK, not a plan: the hop can still be built (L411 leaves the
 *  document's other content to us), but it may be missing what the server holds — so it
 *  is announced rather than taken silently. */
async function retirementBase(did: string, location: StoreLocation, v: Values): Promise<Record<string, unknown> | undefined> {
  const copy = readDidDocumentCopy(location)
  if (copy !== null && copy.did === did) return copy.document
  if (copy !== null) {
    console.error(
      `connectx: note: the local copy at ${location.documentFile} describes ${copy.did}, not ${did} — fetching the document on file instead.`,
    )
  }
  try {
    return (await fetchOnFileDocument(did, location, v)).document
  } catch (err) {
    console.error(
      `connectx: warning: could not read the document on file for ${did} (${err instanceof Error ? err.message : String(err)}).\n` +
        `connectx: warning: FALLING BACK to a document composed from the key — any field the DID server holds that this CLI cannot compose (a service endpoint, keys added out of band) will be MISSING from this hop's retirement document.`,
    )
    return undefined
  }
}

/** Fetch the document `did` has on file and RECORD it. No copy-first step: the callers
 *  that want that check first (`retirementBase`). */
async function fetchOnFileDocument(did: string, location: StoreLocation, v: Values): Promise<ResolvedDidDocument> {
  const entry = await resolveDidDocument(did, ownHostOptions(did, v))
  writeDidDocumentCopy(location, { did: entry.did, document: entry.document, fetchedAt: entry.fetchedAt })
  return entry
}

/** Record the document a DID server has on file for `did`, so a later `did update` of
 *  this identity retires the document that is actually there (§2.5.3 L417).
 *
 *  Called after registration is ACCEPTED — the moment the server has a document to have on
 *  file — and silent about failure on purpose: registration already succeeded, and many
 *  DID servers publish no document at all (or only over a host this run was not allowed to
 *  reach), which is not an error for a registration. The copy is an optimization for the
 *  next update, which fetches for itself when there is none.
 *
 *  Returns whether a copy is now on disk. */
export async function recordDidDocumentOnFile(did: string, location: StoreLocation, v: Values): Promise<boolean> {
  try {
    const copy = readDidDocumentCopy(location)
    if (copy !== null && copy.did === did) return true
    await fetchOnFileDocument(did, location, v)
    return true
  } catch {
    return false
  }
}

/** Resolve options for the identity's OWN DID: its host, and only its host, allowlisted.
 *  No flag names it — a fetch allowed to leave this host would not be about this identity
 *  (ANP-03 §2.5.3 keeps the host inside the stable subject path). `--allow-private-host`
 *  remains for a host that is local without being spelled that way; a host that IS spelled
 *  that way needs no flag at all (`relaxedHosts`). */
function ownHostOptions(did: string, v: Values): ResolveDidOptions {
  const host = didHost(did)
  const relaxed = relaxedHosts([host], v)
  return {
    allowedHosts: [host],
    ...(relaxed.length > 0 ? { allowPrivateHosts: relaxed, allowInsecureTransport: relaxed } : {}),
  }
}

/** Name the flag that lifts a network-policy refusal, when one does.
 *
 *  Only the private-address gate has a flag behind it, and it is reached only where the
 *  host is DERIVED rather than typed (`did update`, `anp login`): an operator who typed
 *  `--allow-host localhost` never gets here, because a loopback spelling unlocks that
 *  gate on its own (`relaxedHosts`). `host_not_allowlisted` needs no hint (the message
 *  names the host, and `--allow-host` is the flag they already found), and `unmatched`
 *  has no remedy to offer. */
function blockedHostHint(err: unknown, did: string | undefined): string | null {
  if (!(err instanceof ConnectxError)) return null
  if (err.blockedReason !== 'private_address') return null
  // The host being refused is the DID's own: the chain cannot leave the host inside
  // the stable subject path, and redirects are off by default. A DID that cannot
  // yield a host never got as far as a fetch, so there is nothing to name here.
  let host = '<host>'
  if (did !== undefined) {
    try {
      host = didHost(did)
    } catch {
      return null
    }
  }
  return `connectx: hint: pass --allow-private-host ${host} to permit this host.`
}

/** The hostname of a `did:wba` DID, as `URL.hostname` reports it — NOT `stored.host`
 *  verbatim. The store records the host as the DID spells it, and a `did:wba` host
 *  carrying a port is percent-encoded (`127.0.0.1%3A8080`), which is not what
 *  `URL.hostname` reports. The SDK compares hostnames, so passing the stored string would
 *  allowlist a name no fetch ever has and the fetch would be refused before it left. */
export function didHost(did: string): string {
  return new URL(didToUrl(did)).hostname
}

/** Map the CLI's flags onto `ResolveDidOptions`. The allowlist is REQUIRED and there
 *  is deliberately no default: defaulting it to the DID's own host would make every
 *  host the operator can type reachable, which is exactly what the allowlist exists
 *  to prevent. Naming the host is the confirmation — and for a loopback host it is the
 *  whole confirmation, since that name alone unlocks the two gates behind it. */
function resolveOptions(v: Values): ResolveDidOptions {
  const allowedHosts = hostList(v['allow-host'], '--allow-host')
  if (allowedHosts.length === 0) {
    throw new ConnectxError(
      'did_resolve_blocked',
      'Remote DID resolution needs an explicit allowlist. Pass --allow-host <host> (repeatable, or comma-separated) naming the host of the DID you are resolving.',
    )
  }
  const relaxed = relaxedHosts(allowedHosts, v)
  return {
    allowedHosts,
    ...(relaxed.length > 0 ? { allowPrivateHosts: relaxed, allowInsecureTransport: relaxed } : {}),
  }
}

/** The chain-only half of the options: acceptance policy, not network reach. */
function chainOptions(v: Values, base: ResolveDidOptions): DidChainOptions {
  const options: DidChainOptions = { ...base }
  if (v['accept-provider-asserted']) options.acceptProviderAsserted = true
  if (v['report-low-assurance']) options.reportLowAssurance = true
  return options
}

/** A repeatable (and/or comma-separated) host flag. `parseArgs` hands a repeated flag
 *  over as an array even though the shared `Values` type says `string`. */
export function hostList(raw: unknown, flag: string): string[] {
  const items = (Array.isArray(raw) ? raw : raw === undefined ? [] : [raw]).flatMap((x) =>
    typeof x === 'string' ? x.split(',') : [],
  )
  const hosts = items.map((h) => h.trim()).filter((h) => h !== '')
  for (const host of hosts) assertHostName(host, flag)
  return hosts
}

/** The hosts a run may treat as its own machine: those named in `--allow-private-host`,
 *  plus every LOOPBACK name among `hosts`.
 *
 *  A loopback spelling needs no second flag. `--allow-host localhost` already states that
 *  the fetch is to this machine; the SDK would otherwise refuse the one host the DID
 *  itself names, which is the loop this rule removes. `--allow-private-host` stays for a
 *  host that is local WITHOUT being spelled that way (a LAN address, a name resolving
 *  inward).
 *
 *  The two relaxations travel together because a host declared local is a development
 *  server: ANP-02's TLS requirement is about real deployments, and plain http on this
 *  machine is the case `allowInsecureTransport` exists for. Asking whether it also speaks
 *  http would be a second question with only one possible answer — and `--allow-host` for
 *  a PUBLIC host deliberately does not cover either gate, so no host is ever downgraded
 *  to http without having been named as local. */
export function relaxedHosts(hosts: readonly string[], v: Values): string[] {
  const out = hostList(v['allow-private-host'], '--allow-private-host')
  for (const host of hosts) {
    if (isLoopbackHostName(host) && !out.includes(host)) out.push(host)
  }
  return out
}

/** Is this hostname a spelling of "this machine"? Brackets are stripped first, because
 *  `URL.hostname` keeps them on an IPv6 literal and `hostList` accepts them. */
function isLoopbackHostName(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (bare === 'localhost' || bare === '::1') return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(bare)
  return v4 !== null && Number(v4[1]) === 127
}

/** The allowlist matches `URL.hostname`, so a port (or a scheme, or a path) would
 *  silently never match. Fail loudly here instead of at "not in the allowed hosts
 *  list" — that message is technically true and useless for finding the typo. */
function assertHostName(host: string, flag: string): void {
  if (host.includes('/') || host.includes('://') || host.includes('@')) {
    throw new Error(`${flag} expects a bare hostname (got "${host}")`)
  }
  // A colon is only legitimate inside an IPv6 literal (`[::1]`).
  if (!host.startsWith('[') && host.includes(':')) {
    throw new Error(
      `${flag} expects a hostname WITHOUT a port (got "${host}") — the allowlist matches hostnames only, so pass "${host.split(':')[0]}"`,
    )
  }
}
