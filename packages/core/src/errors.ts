// Unified error model for connectx. Every public throw path surfaces a
// `ConnectxError` carrying a stable `code`, so a caller (or a support person)
// can branch on `err.code` instead of parsing message strings. Codes are grouped
// by what the caller should DO about them:
//   - retry   — transient (network/timeout); the same call may succeed later
//   - fix     — the caller's config/input is wrong; change it and re-run
//   - report  — unexpected / internal; a bug in the SDK or the peer's data
//
// `code` is part of the public contract: codes are never removed or renumbered.
// Adding a code is fine; changing the meaning of an existing one is a breaking
// change (bump major).
//
// When the failure came from a peer's non-2xx response, the error also carries
// `status` (the HTTP status) and `serverCode` (the peer's own machine-readable code,
// e.g. `handle_taken`). The SDK's `code` deliberately stays coarse — every login
// rejection is `login_failed` — so these two are how a caller reaches what the
// server actually said.

import type { DidSupersededInfo } from './types'

export type ConnectxErrorCode =
  // --- connection / configuration (fix) --------------------------------------
  | 'connector_unavailable' // in config but not usable right now (wallet missing / disconnected)
  | 'no_connector_selected' // requested connector id is not in the config
  | 'invalid_argument' // bad argument / config value
  // --- DID resolution (identity + SSRF security) ------------------------------
  | 'invalid_did' // cannot derive a URL from the DID
  | 'did_resolve_blocked' // security policy: host not allowlisted / private address / DNS fail-closed
  | 'did_resolve_failed' // non-2xx fetching the DID document; `status` says which (404/410 = not published, else retry)
  | 'did_resolve_timeout' // fetch aborted after the timeout (retry)
  | 'did_resolve_too_large' // document exceeds the size cap (fix the server or raise maxBytes)
  | 'did_resolve_too_many_redirects' // redirect hop limit exceeded
  | 'did_resolve_invalid_document' // document id mismatch / not parseable JSON / missing or bad top-level proof
  | 'did_resolve_not_found' // no verification method matches the keyid
  | 'did_resolve_unauthorized' // the method exists but is not in the document's `authentication` relationship
  | 'did_chain_broken' // update chain did not verify: a hop skipped a generation, cycled, or changed the stable subject path
  | 'did_chain_assurance_too_low' // chain reached an active DID, but its assurance is below the caller's policy
  // --- agent description (ANP-07 `ad.json`) -----------------------------------
  // The description is a SECOND document, reached through the DID document's
  // `AgentDescription` service entry rather than by any path convention.
  | 'ad_not_found' // the DID document publishes no `AgentDescription` service entry, so this DID has no ad.json
  | 'ad_fetch_failed' // the ad.json could not be fetched: network/HTTP failure, timeout, size cap, too many redirects, or refused by the network policy
  | 'ad_malformed' // the fetched body is not a well-formed ANP-07 Agent Description
  // --- agent discovery (ANP-08 `.well-known/agent-descriptions`) ----------------
  // The domain-wide INDEX of descriptions. One code per kind, as above: an answer, a
  // transport failure, and a body that is not a usable collection page.
  | 'ad_index_not_found' // the domain publishes no index: the entry page answered 404 or 410
  | 'ad_index_fetch_failed' // an index page could not be fetched: network/HTTP failure, timeout, size cap, too many redirects, or refused by the network policy
  | 'ad_index_malformed' // a page is not a well-formed ANP-08 CollectionPage, or the pagination chain does not terminate within maxPages
  // --- WNS Handle (ANP-04) ------------------------------------------------------
  // Two fetches share these codes — the Handle's own Resolution Document and the
  // binding endpoint its DID document names. Which one failed is in the message; the
  // code stays coarse because the caller's action is the same for both.
  | 'invalid_handle' // the input is not `local-part.domain` (or its domain is not an FQDN / carries a port)
  | 'handle_not_found' // the Resolution Endpoint answered 404 (never registered) or 410 (revoked) — ANP-04 §4.8
  | 'handle_fetch_failed' // a WNS document could not be fetched: network/HTTP failure, timeout, size cap, too many redirects, or refused by the network policy
  | 'handle_malformed' // a fetched WNS body is not JSON, or is not a well-formed Handle Resolution Document
  // --- ZK site descriptor (ZKTODO1 §12.1) --------------------------------------
  | 'zk_descriptor_unavailable' // the descriptor could not be fetched: network/HTTP failure, timeout, or a body over the size cap (retry)
  | 'zk_descriptor_malformed' // the fetched body is not a well-formed ZK site descriptor (the site must fix it — do not guess)
  // --- ZK escrow vault (ZKTODO1 §10) (auditor-local, never a wire rejection) -----
  | 'zk_vault_invalid' // a sealed escrow vault could not be opened: wrong auditor key, or the envelope was altered
  // --- key parsing (agent/CLI input) (fix) ------------------------------------
  | 'key_invalid' // malformed key material (length/hex/mnemonic/keystore params/PEM)
  | 'key_wrong_password' // keystore MAC mismatch — wrong password
  | 'key_unsupported' // unsupported format (kdf/cipher/version/prf/multicodec prefix)
  // --- identity store (agent/CLI) (fix) ---------------------------------------
  | 'identity_not_found' // no stored identity for this (agent, profile); run `connectx did create`
  | 'identity_not_registered' // the key is stored but no DID server has taken it on, so there is no DID yet; run `connectx did register`
  | 'identity_exists' // `did create` found an existing identity (pass --force to overwrite)
  | 'agent_ambiguous' // agent detection matched more than one agent; pass --agent <id> or set $CONNECTX_AGENT
  | 'session_invalid' // stored session could not be decrypted / was tampered with (wrong password or corrupt file)
  | 'session_busy' // another process holds the session write lock (retry)
  | 'zk_store_invalid' // stored ZK key / membership could not be decrypted or parsed (wrong password, corrupt file, or a record this build cannot read)
  // --- signature / protocol (fix, or report on peer) --------------------------
  | 'signature_malformed' // malformed Signature-Input header / params / label
  | 'signature_invalid' // signature or key bytes are invalid / mismatched
  | 'wallet_account_mismatch' // recovered key/account does not match the reported address
  | 'wallet_account_changed' // account/chain switched during an async sign (retry with the new account)
  // --- server interaction -----------------------------------------------------
  | 'login_failed' // server rejected the login (non-2xx)
  | 'register_failed' // server rejected the registration (non-2xx)
  | 'update_failed' // server rejected the update delivery (non-2xx)
  | 'did_superseded' // server 409 `did_superseded`: the DID offered has been replaced by a successor (ANP-03 §3.2)
  | 'forbidden_did' // server 403 `forbidden_did`: the DID authenticated but has no permission (ANP-02 vocabulary)
  | 'authorization_denied' // server refused authorization without a more specific ANP-02 error
  | 'response_too_large' // remote response body exceeded the SDK byte cap (fix the server or raise maxBytes)
  // --- framework bindings (react / vue) ----------------------------------------
  | 'react_outside_provider' // hooks used outside <AnpProvider>
  | 'react_session_not_configured' // `usePersistedSession()` without `<AnpProvider session>`
  | 'vue_outside_provider' // composables used outside <AnpProvider>
  | 'vue_session_not_configured' // `usePersistedSession()` without `<AnpProvider session>`

/** The gate that refused a fetch. See `ConnectxErrorOptions.blockedReason`. */
export type BlockedReason =
  // the host did not match the caller's allowlist at all
  | 'host_not_allowlisted'
  // the host matched, but resolved to a private / loopback / link-local address
  | 'private_address'
  // the host matched, but the URL was not https and the host was not opted in
  | 'insecure_transport'
  // the host matched, but could not be cleared, or this environment cannot pin at all
  | 'unmatched'

/** Options for `ConnectxError`, all additive: existing callers pass `{ cause }`. */
export interface ConnectxErrorOptions {
  cause?: unknown
  /** HTTP status of the peer's response, when the failure came from a non-2xx. */
  status?: number
  /** The peer's own machine-readable code (e.g. `handle_taken`), when its error body
   *  carried one. Unlike `code` this is *not* an SDK contract — branch on it only
   *  against a server whose error vocabulary you know. */
  serverCode?: string
  /** WHICH gate of the outbound network policy (SSRF) refused a fetch. Set on the
   *  errors that carry `did_resolve_blocked` and its siblings (`ad_fetch_failed`,
   *  `handle_fetch_failed`), whose `code` is deliberately coarse because the caller's
   *  action is the same for every cause.
   *
   *  It is here so a caller that CAN name a remedy does so without parsing the
   *  message. The first three are the per-host relaxations, and each is answered by a
   *  different option: `host_not_allowlisted` by `allowedHosts`, `private_address` by
   *  `allowPrivateHosts`, `insecure_transport` by `allowInsecureTransport`. Only
   *  `private_address` and `insecure_transport` are local-development cases; the first
   *  is a host that ought to have been named. `unmatched` is the residue — a host that
   *  matched the allowlist but could not be cleared, or an environment with no
   *  resolver at all — and NO option lifts it, so a caller must not suggest one. */
  blockedReason?: BlockedReason
  /** The DID-continuity conclusion this SDK reached while answering a 409
   *  `did_superseded` (ANP-03 §3.2) — present on the error thrown for that status
   *  whenever the caller supplied `didChain`.
   *
   *  §3.2 requires a client to fetch the old DID document, verify `deactivated` /
   *  `successorDid` / the document proof, and resolve forward until it reaches the
   *  active DID — and it forbids retrying off the peer's `currentDid` hint. Walking
   *  the chain IS the prescribed answer, so when the walk runs its conclusion is
   *  reported here rather than withheld: `verifiedCurrentDid` is this SDK's own
   *  conclusion from the DID's documents, while `claimed*` stays the peer's
   *  unverified claim. A caller that cannot produce a signer for the successor (the
   *  usual case after an update — an update means a NEW key) gets the diagnosis
   *  without having to repeat the walk itself. */
  didSuperseded?: DidSupersededInfo
}

export class ConnectxError extends Error {
  readonly code: ConnectxErrorCode
  readonly status?: number
  readonly serverCode?: string
  readonly blockedReason?: BlockedReason
  readonly didSuperseded?: DidSupersededInfo

  constructor(code: ConnectxErrorCode, message: string, options?: ConnectxErrorOptions) {
    super(message)
    this.name = 'ConnectxError'
    this.code = code
    if (options?.status !== undefined) this.status = options.status
    if (options?.serverCode !== undefined) this.serverCode = options.serverCode
    if (options?.blockedReason !== undefined) this.blockedReason = options.blockedReason
    if (options?.didSuperseded !== undefined) this.didSuperseded = options.didSuperseded
    if (options?.cause !== undefined) {
      // Assign without relying on the ES2022 `Error(message, { cause })` form, so
      // this stays target-compatible; `cause` is still reachable for debugging.
      ;(this as { cause?: unknown }).cause = options.cause
    }
  }
}

/** The connector is in the config but is not usable right now (e.g. `window.anp`
 *  missing, or the web3 wallet is locked/disconnected). */
export class ConnectorUnavailableError extends ConnectxError {
  constructor(connectorId: string) {
    super('connector_unavailable', `Connector "${connectorId}" is not available`)
    this.name = 'ConnectorUnavailableError'
  }
}

/** Narrow an unknown thrown value to a `ConnectxError`. */
export function isConnectxError(err: unknown): err is ConnectxError {
  return err instanceof ConnectxError
}

/** The stable error code of a thrown value, or `undefined` if it is not a
 *  connectx error. Use this to branch on failure without `instanceof`. */
export function errorCode(err: unknown): string | undefined {
  return err instanceof ConnectxError ? err.code : undefined
}
