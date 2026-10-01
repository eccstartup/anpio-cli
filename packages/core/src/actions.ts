import type {
  AnpConfig,
  AnpConnector,
  DidUpdateOptions,
  DidSupersededInfo,
  EnvelopeRequest,
  LoginOptions,
  LoginOutcome,
  RequestEnvelope,
  SignRequest,
  SignResult,
  SignedRequest,
  SignedRequestTransport,
} from './types'
import { ConnectxError, ConnectorUnavailableError, type ConnectxErrorCode } from './errors'
import { selectWallet } from './config'
import { subjectOf } from './identity'
import { isFingerprint } from './crypto/fingerprint'
import { resolveDidChain } from './did/chain'

// ---- Uniform operations ------------------------------------------------------
// The agent-facing surface. Every operation is the same regardless of whether the
// selected connector is ANP-native, a browser extension, or an arbitrary-chain
// web3 wallet. The connector seals all wallet-specific signing inside itself.

type Fetcher = (url: string, init: RequestInit) => Promise<Response>

/** The endpoint-specific part of the signed body: everything a `SignRequest` carries
 *  beyond `url` / `method` / `nonce`, under the names the WIRE uses — these are the
 *  fields a server reads and the content-digest covers. Threaded through the pipeline
 *  as one value so the final attempt (a 401 re-sign, a 409 retry) covers exactly what
 *  the first one did: a retry that dropped the handle, or the successor, would be a
 *  different request wearing the same name. */
export type BodyFields = Pick<SignRequest, 'handle' | 'successorDid' | 'successorDocument' | 'extraBody'>

/** The members a connector places itself, under ANP-02's own names. `extraBody` may not
 *  carry one: each is a fact the proof is ABOUT, so "which of the two wins" has no good
 *  answer — the request is refused instead (`assertSigned`), and the caller uses the
 *  field that already exists for it (`handle`, `successorDid`, …). */
export const RESERVED_BODY_FIELDS: readonly string[] = [
  'nonce',
  'did',
  'didDocument',
  'handle',
  'successorDid',
  'successorDocument',
]

/** Sign an ANP-02 login request with the selected connector. Pure — no network. */
export async function signRequest(
  config: AnpConfig,
  connectorId: string,
  req: SignRequest,
): Promise<SignResult> {
  const connector = selectWallet(config, connectorId)
  await assertAvailable(connector)
  return connector.signRequest(req)
}

export interface RegisterOptions extends DidUpdateOptions, SignedRequestTransport {
  connectorId?: string
  /**
   * The name to claim on the DID server you are registering with. It becomes the local
   * part of the DID that server hosts for you — for `did:wba:<server-host>:user:<this>`
   * it is that final segment before the fingerprint — which is why **its syntax belongs
   * to the server**: the name is part of an identifier the server will publish, so a
   * rule invented here could only reject names the server accepts.
   *
   * ⚠️ **Not an ANP-04 Handle.** An ANP-04 Handle is a WNS name of the form
   * `local-part.domain` and is a *resolved* fact — see `AgentDescription.handle`. Do not
   * pass a full ANP-04 Handle here; that is a different concept, owned by a different
   * layer, and a server hosting DIDs has no use for it.
   */
  handle: string
  /** Full URL of the register endpoint. */
  targetUri: string
  /** Server-issued one-time nonce; may be empty to accept a 401 challenge. */
  nonce?: string
}

export interface RegisterOutcome {
  did: string
  /** The name the DID server confirmed it bound (see `register`): it may differ from what
 *  you sent, because the server owns the name's syntax and may normalise it. */
  handle: string
  token?: string
  /** The `token_type` the server named alongside `token` — see `LoginOutcome.tokenType`
   *  for what it obliges a caller that sends the token to do. */
  tokenType?: string
}

// Register this identity's DID with a DID SERVER — the party that hosts the DID and
// serves its document at the URL the DID itself names. This SDK is the CLIENT of that
// exchange and nothing else: it is not a DID server, so it does not own the DID, cannot
// decide whether a name is free, and cannot say what a name means on that server. Those
// are the server's calls, because the server is the one publishing the identifier.
//
// What the SDK contributes is the part that IS specified, and it is the reason to go
// through the SDK instead of POSTing by hand: the request is signed the way ANP-02 signs
// a login, so the DID server can bind the DID to the key it names, and the
// content-digest covers the claimed name (a registration editable in flight would let a
// proxy rename the claim). Plus the 401 challenge loop and the 409 `did_superseded`
// retry, so a credential that has updated is answered along the chain rather than
// silently refused.
export async function register(
  config: AnpConfig,
  opts: RegisterOptions,
): Promise<RegisterOutcome> {
  const connector = selectWallet(config, opts.connectorId)
  await assertAvailable(connector)

  const { res, sig, error, superseded } = await postSigned(config, {
    connector,
    transport: opts.transport ?? globalThis.fetch.bind(globalThis),
    envelope: opts.envelope,
    targetUri: opts.targetUri,
    nonce: opts.nonce ?? '',
    body: { handle: opts.handle },
    didUpdate: opts,
  })

  if (!res.ok) throw serverError('register_failed', res, error!, superseded)
  assertNotWebPage(res, opts.targetUri)
  const bodyData = await readSuccessBody(res)
  // Prefer the name the DID server actually confirmed, because the server owns the
  // name's syntax and may normalise what we sent (lower-casing is the common one).
  // Reporting our own version back would tell the caller it holds a name that does not
  // exist on that server. Fall back to the request only when the server confirms
  // nothing, i.e. it bound no name at all.
  const confirmedHandle = typeof bodyData.handle === 'string' ? bodyData.handle : opts.handle
  const { token, tokenType } = accessTokenFrom(res, bodyData)
  return { did: sig.did, handle: confirmedHandle, token, tokenType }
}

export interface JsonRpcRegisterOptions {
  connectorId?: string
  /** The name to claim, with the same meaning as `RegisterOptions.handle`: the local part
   *  the server binds for this DID. Its syntax belongs to the server, so nothing here
   *  validates or normalises it. */
  handle: string
  /** Full URL of the server's JSON-RPC register endpoint, e.g.
   *  `https://did.example.com/user-service/v1/did-auth/rpc`. */
  targetUri: string
  /** Optional transport override; defaults to globalThis.fetch. */
  transport?: (url: string, init: RequestInit) => Promise<Response>
}

// Register over a DID server's OWN JSON-RPC contract — the "canonical User Service v1"
// `register` that `awiki-open-server` serves at `POST <base>/user-service/v1/did-auth/rpc`.
//
// This is a second contract, not a variant of `register`. Nothing is signed as an RFC 9421
// message signature, no 401 challenge is answered, no 409 `did_superseded` retry applies,
// and the body is a JSON-RPC envelope rather than the flat ANP-02 body: what the server
// verifies is the DataIntegrityProof on the submitted `did_document` itself (§2.5.5),
// which is the whole proof of possession here. One function covering both would share the
// name and nothing else — ANP-03 §2.5.3 L427 leaves this interface to the implementation
// ("将程序化注册和管理留给各个实现方根据其需求自行定义"), and `register` keeps its own
// behaviour (TODO7 R2.1 结论 5).
//
// What the SDK contributes is the document: this key's signed `did:wba` document, carrying
// the server's own `ANPMessageService` entry. Take that entry from `discoverDidServer` and
// hand it to the connector's `service` option BEFORE the document is built — the proof
// covers whatever the document holds at signing time, so it cannot be added afterwards.
//
// ⚠️ Ed25519 only. This contract addresses the `e1_` profile (awiki's `_is_e1_did`), so a
// `k1_` document or a CAIP-10 account id is refused here rather than at the server, where
// it would surface as a domain or proof mismatch.
export async function registerViaJsonRpc(
  config: AnpConfig,
  opts: JsonRpcRegisterOptions,
): Promise<RegisterOutcome> {
  const connector = selectWallet(config, opts.connectorId)
  await assertAvailable(connector)
  const identity = await connector.getIdentity()
  if (!isE1Did(identity.did)) {
    throw new ConnectxError(
      'invalid_argument',
      `${opts.targetUri} registers Ed25519 did:wba identities; this connector's identity is "${identity.did}". ` +
        `A k1_ (secp256k1) identity, or a CAIP-10 account id, has no document this contract can verify.`,
    )
  }

  const transport = opts.transport ?? globalThis.fetch.bind(globalThis)
  const res = await transport(opts.targetUri, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'register',
      params: { handle: opts.handle, did_document: identity.didDocument },
      id: jsonRpcRequestId(),
    }),
  })

  // A 2xx that is a web page must not read as a registration here either (see
  // `assertNotWebPage`); for JSON-RPC the same mistake is a 2xx that is not JSON-RPC at
  // all, which the branches below refuse for the same reason.
  assertNotWebPage(res, opts.targetUri)

  // One read of the body, parsed once: every branch below works off that value, so a
  // failure body can never be consumed twice (and lose `status` / `serverCode`).
  let parsed: unknown
  try {
    parsed = JSON.parse(await readBodyBounded(res)) as unknown
  } catch (err) {
    if (err instanceof ConnectxError) throw err
    throw notJsonRpc(res, opts.targetUri, 'a body that is not JSON')
  }
  const response = plainObject(parsed)
  if (!response) {
    throw notJsonRpc(res, opts.targetUri, Array.isArray(parsed) ? 'an array' : typeof parsed)
  }

  // `error` before `result`: a response carrying both halves is malformed, and reporting
  // the result of a refused registration would name a DID the server never bound.
  const jsonRpcError = plainObject(response.error)
  if (jsonRpcError) throw jsonRpcFailure(res, opts.targetUri, jsonRpcError)
  if (!res.ok) {
    throw new ConnectxError('register_failed', `POST ${opts.targetUri} answered ${res.status}`, {
      status: res.status,
    })
  }

  const result = plainObject(response.result)
  if (!result) throw notJsonRpc(res, opts.targetUri, 'no JSON-RPC result')
  const did = result.did
  if (typeof did !== 'string' || did === '') {
    // The DID is the point of the call, and unlike the handle it has no normalisation
    // story of its own: a server that confirms no DID has not taken this identity on,
    // whatever else it answered with.
    throw new ConnectxError(
      'invalid_argument',
      `${opts.targetUri} answered without a "did", so the registration was not confirmed`,
      { status: res.status },
    )
  }

  // The token and the confirmed handle are read the way `register` reads them — from the
  // server's own words, which here live in `result` — falling back to what was sent only
  // when the server confirms no name at all.
  const confirmedHandle = typeof result.handle === 'string' ? result.handle : opts.handle
  const { token, tokenType } = accessTokenFrom(res, result)
  return { did, handle: confirmedHandle, token, tokenType }
}

/** Whether a DID binds an Ed25519 key — the `e1_` profile, read off the DID's last
 *  segment, which is where the fingerprint always is and where a server reads it too. */
function isE1Did(did: string): boolean {
  const segment = did.slice(did.lastIndexOf(':') + 1)
  return isFingerprint(segment) && segment.startsWith('e1_')
}

/** A fresh JSON-RPC request id. Nothing correlates on it beyond the response, so it only
 *  has to differ per request: `getRandomValues`, not `randomUUID`, whose secure-context
 *  gate a plaintext development origin does not satisfy. */
function jsonRpcRequestId(): string {
  const bytes = new Uint8Array(8)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** The 2xx that is not a JSON-RPC response: the target is not this endpoint, or the server
 *  is not the one this contract describes. `invalid_argument` carrying the status is what
 *  lets the CLI name `--target` — it reads a 2xx `invalid_argument` as "that URL is not the
 *  endpoint you meant". A non-2xx is the server refusing the request instead, i.e. a failed
 *  registration rather than a wrong address. */
function notJsonRpc(res: Response, targetUri: string, what: string): ConnectxError {
  const detail = `POST ${targetUri} answered ${res.status} with ${what}`
  return res.ok
    ? new ConnectxError('invalid_argument', `${detail}: this is not a JSON-RPC DID registration endpoint`, {
        status: res.status,
      })
    : new ConnectxError('register_failed', detail, { status: res.status })
}

/** A JSON-RPC failure. The server's machine-readable code rides in `error.message` (the
 *  JSON-RPC `code` is a number, and these servers put one domain code in all of them), and
 *  that is what the SDK reports as `serverCode` — so `handle_already_registered` reaches a
 *  caller that knows the name. */
function jsonRpcFailure(
  res: Response,
  targetUri: string,
  error: Record<string, unknown>,
): ConnectxError {
  const serverCode =
    typeof error.message === 'string' && error.message !== '' ? error.message : undefined
  return new ConnectxError(
    'register_failed',
    serverCode ??
      `POST ${targetUri} answered ${res.status} with a JSON-RPC error (code ${String(error.code)})`,
    { status: res.status, serverCode },
  )
}

/** A JSON value narrowed to a plain object, or `undefined` for anything else (null, an
 *  array, a scalar) — a peer's body is untrusted input and must not become a TypeError. */
function plainObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

export interface UpdateOptions extends SignedRequestTransport {
  connectorId?: string
  /** Full URL of the DID SERVER's update endpoint.
   *
   *  ⚠️ No ANP document specifies one — ANP-03 §2.5.3 defines what a hop must CONTAIN
   *  (L415–420) and then says the programmatic management interface is out of scope
   *  (L422, and the note at L427: "HTTP API 更新过程没有指定具体的 HTTP API，而是将程序化
   *  注册和管理留给各个实现方根据其需求自行定义") — so this is the server's own contract,
   *  and a server that hosts DIDs is the only thing that can tell you what it is. Nothing
   *  is assumed about the path or the response body. */
  targetUri: string
  /** Server-issued one-time nonce; may be empty to accept a 401 challenge. */
  nonce?: string
  /** The successor DID: a NEW key under the SAME stable subject path (§2.5.3). The
   *  SDK refuses a `successorDid` that leaves that path — see `SignRequest.successorDid`. */
  successorDid: string
  /** The successor's ACTIVE document, already signed by the successor's own key.
   *  Build it the way any identity is built (`anpCli` / `buildWalletIdentity`); this
   *  SDK signs the RETIREMENT document for you, but it does not hold the successor's
   *  key and cannot sign that one. */
  successorDocument: Record<string, unknown>
}

export interface UpdateOutcome {
  /** The DID that was RETIRED — the one whose key signed the delivery, taken from the
   *  attempt that was actually accepted. */
  did: string
  successorDid: string
}

/**
 * Deliver ONE update hop to the DID server that hosts the retiring DID: hand it the
 * retirement document (signed by the retiring key, `deactivated` + `successorDid`) and
 * the successor's active document, in a request signed the way ANP-02 signs a login.
 *
 * ⚠️ **This SDK is the client of that exchange, and only the client.** It does not
 * decide whether an update is allowed, does not publish anything, and does not make a
 * DID current: the DID server accepts the hop (or not), and the successor only becomes
 * real once THAT server serves it. What the SDK contributes is the part that is
 * specified: the two documents, the proof that makes the hop verifiable, and the
 * signature that binds the request to the retiring DID — so a server can check the
 * delivery with the verification machinery it already has for ANP-02 logins.
 *
 * The delivery is a plain ANP-02 request (`nonce` / `did` / `didDocument`) plus
 * `successorDid` / `successorDocument`, so the whole body is under the content-digest:
 * a hop editable in flight would let a proxy point the retirement at a successor of its
 * own choosing, which is the one thing the proof must not allow.
 *
 * The 401 challenge loop applies as it does to a login (a server may want to hand out
 * its own nonce first). A 409 does NOT: this call already names the DID it is retiring,
 * so a "that DID is superseded" answer means the caller's premise is wrong — resolve
 * the chain first (`resolveDidChain`) rather than have the SDK guess at a predecessor
 * whose key it may not even hold.
 */
export async function update(config: AnpConfig, opts: UpdateOptions): Promise<UpdateOutcome> {
  const connector = selectWallet(config, opts.connectorId)
  await assertAvailable(connector)

  const { res, sig, error } = await postSigned(config, {
    connector,
    transport: opts.transport ?? globalThis.fetch.bind(globalThis),
    envelope: opts.envelope,
    targetUri: opts.targetUri,
    nonce: opts.nonce ?? '',
    body: { successorDid: opts.successorDid, successorDocument: opts.successorDocument },
  })

  if (!res.ok) throw serverError('update_failed', res, error!)
  // Before the 2xx is taken as "the hop was delivered": a web page answers 2xx too, and
  // an update that was never delivered must not be reported as one.
  assertNotWebPage(res, opts.targetUri)
  // The exchange is DONE at 2xx — the server accepted the hop, and that is the whole
  // outcome this call can observe. Drain the body so the connection is released, but
  // never read a shape out of it: no document defines one, so anything parsed here
  // would be invention. It is also deliberately NOT allowed to fail the call: a
  // update the server has accepted is not undone by a body we could not read.
  await res.body?.cancel().catch(() => {})
  return { did: sig.did, successorDid: opts.successorDid }
}

/** Login: pick a connector, sign a request, POST, and handle the 401 re-sign loop. */
export async function login(config: AnpConfig, opts: LoginOptions): Promise<LoginOutcome> {
  const connector = selectWallet(config, opts.connectorId)
  await assertAvailable(connector)

  const { res, sig, error, superseded } = await postSigned(config, {
    connector,
    transport: opts.transport ?? globalThis.fetch.bind(globalThis),
    envelope: opts.envelope,
    targetUri: opts.targetUri,
    nonce: opts.nonce,
    body: {},
    didUpdate: opts,
  })

  if (!res.ok) throw serverError('login_failed', res, error!, superseded)

  assertNotWebPage(res, opts.targetUri)
  const bodyData = await readSuccessBody(res)
  const { token, tokenType } = accessTokenFrom(res, bodyData)
  const outcome: LoginOutcome = {
    // The subject is derived from the DID the proof was actually bound to, so a
    // caller can key its session on an identity that survives a key update while
    // the DID (the wire credential) keeps changing. After a `did_superseded` retry
    // this is the SUCCESSOR's DID and subject: `sig` is the last attempt's, not the
    // one the caller's connector started out with.
    subject: subjectOf(sig.did),
    did: sig.did,
    method: 'anp',
    walletType: connector.type,
    docUrl: typeof bodyData.docUrl === 'string' ? bodyData.docUrl : undefined,
    token,
    tokenType,
  }
  return outcome
}

// ---- helpers -----------------------------------------------------------------

/** Sign one ANP-02 request with `connector` and POST it.
 *
 *  Never follows a redirect, for two independent reasons: a 307/308 to another origin
 *  would forward the signed proof (signature-input, content-digest, inline DID
 *  document) to an untrusted host; and ANP-03 forbids a transparent 301/302 as a
 *  update signal — a superseded DID MUST be reported as 409 `did_superseded` and
 *  followed only through chain verification, so silently following a redirect would
 *  accept a substitution the spec requires us to check. */
async function signAndPost(args: {
  connector: AnpConnector
  transport: Fetcher
  targetUri: string
  nonce: string
  body: BodyFields
  envelope?: RequestEnvelope
}): Promise<{ res: Response; sig: SignResult }> {
  const { connector, transport, targetUri, nonce, body: fields } = args
  const sig = await connector.signRequest({
    url: targetUri,
    method: 'POST',
    nonce,
    ...fields,
  })
  assertSigned(sig.body, fields, connector.id)
  const res = await transport(...onTheWire(targetUri, sig, args.envelope))
  return { res, sig }
}

/** The signed request as it goes out: the caller's envelope when it supplied one, the
 *  flat ANP-02 body otherwise.
 *
 *  The envelope runs AFTER `assertSigned`, and deliberately so: what is checked there
 *  is the body the CONNECTOR produced, which is the thing the content-digest covers.
 *  An envelope is free to frame that body (or move it into a field), and a check that
 *  looked at the frame instead would be checking the wrong artifact.
 *
 *  `redirect: 'error'` is not the envelope's to change — never following a redirect is
 *  a security property (see `signAndPost`), not a transport preference. */
function onTheWire(
  targetUri: string,
  sig: SignResult,
  envelope?: RequestEnvelope,
): [string, RequestInit] {
  const headers = { 'content-type': 'application/json', ...sig.headers }
  const signed: SignedRequest = { url: targetUri, method: 'POST', body: sig.body, headers, sig }
  const req: EnvelopeRequest = envelope ? envelope(signed) : signed
  return [
    req.url,
    {
      method: req.method ?? 'POST',
      headers: req.headers ?? {},
      body: req.body,
      redirect: 'error',
    },
  ]
}

/** Every requested body field must be in the body that was ACTUALLY signed.
 *
 *  A connector builds its own body, and the ones that delegate to a wallet
 *  (`anpDevShim`) may ignore a field they do not
 *  understand. For a login that is harmless; for a registration or an update it is
 *  not — the request would arrive as a bare login body while the caller believes a
 *  name was claimed or a hop was delivered, and the content-digest would faithfully
 *  prove a request nobody asked for. Checked on the artifact, BEFORE the POST: nothing
 *  leaves the process unless what was asked for is what is being signed.
 *
 *  `extraBody` is FLATTENED into the names it carries: those members go into the body
 *  at the top level, so the check is whether each of them arrived, not whether an
 *  `extraBody` key did. */
function assertSigned(signedBody: string, fields: BodyFields, connectorId: string): void {
  const { extraBody, ...named } = fields
  if (extraBody) {
    // Refused rather than overridden: the names below are what the proof is ABOUT, so a
    // caller asking to set one has described a request this SDK cannot make. Letting the
    // connector win would post a request proving the opposite of what the caller
    // believes it sent, and letting the caller win would forge the proof's own subject.
    const reserved = Object.keys(extraBody).filter((k) => RESERVED_BODY_FIELDS.includes(k))
    if (reserved.length > 0) {
      throw new ConnectxError(
        'invalid_argument',
        `extraBody may not carry ${reserved.join(', ')} — the connector places those from the identity being proven`,
      )
    }
  }
  const requested = [...Object.keys(named), ...Object.keys(extraBody ?? {})]
  if (requested.length === 0) return
  let parsed: unknown
  try {
    parsed = JSON.parse(signedBody)
  } catch {
    parsed = undefined
  }
  const signed: Record<string, unknown> =
    parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {}
  const missing = requested.filter((key) => !(key in signed))
  if (missing.length > 0) {
    throw new ConnectxError(
      'invalid_argument',
      `Connector "${connectorId}" signed a body without ${missing.join(', ')} — it cannot deliver what was requested`,
    )
  }
}

/** Sign, POST, and re-sign once with the server's own challenge when it answers 401
 *  (e.g. our nonce expired, or we started without one). The server's
 *  `WWW-Authenticate: didwba nonce=".."` is authoritative for what it will accept, so
 *  it — not our own nonce — decides the second attempt. */
async function postWithChallenge(args: {
  connector: AnpConnector
  transport: Fetcher
  targetUri: string
  nonce: string
  body: BodyFields
  envelope?: RequestEnvelope
}): Promise<{ res: Response; sig: SignResult }> {
  const first = await signAndPost(args)
  if (first.res.status !== 401) return first
  const challengeNonce = nonceFromChallenge(first.res)
  if (!challengeNonce || challengeNonce === args.nonce) return first
  return signAndPost({ ...args, nonce: challengeNonce })
}

/** What `postSigned` hands back. `error` is the peer's parsed error body — read ONCE
 *  here, so a caller never consumes the stream twice (a second read sees an empty body
 *  and loses `status` / `serverCode`). */
export interface PostOutcome {
  res: Response
  sig: SignResult
  error?: ParsedError
  /** The 409 `did_superseded` conclusion, when the caller supplied a `didChain` —
   *  present whether or not a retry followed. */
  superseded?: DidSupersededInfo
}

/**
 * The one pipeline `login()` / `register()` share: sign, POST, follow a 401 challenge,
 * and answer a 409 `did_superseded` when the caller configured a `didChain`.
 *
 * The `sig` returned is the FINAL attempt's, so its `did` is the credential actually
 * used. Callers must read the outcome from `sig`, not from the connector they passed
 * in: after a retry those differ, and theirs is by definition the superseded one.
 */
export async function postSigned(
  config: AnpConfig,
  args: {
    connector: AnpConnector
    transport: Fetcher
    targetUri: string
    nonce: string
    body: BodyFields
    envelope?: RequestEnvelope
    /** How to answer a 409 `did_superseded`. Absent for `update`, which signs with the
     *  very DID it retires — there a 409 means the caller's premise is wrong, not that
     *  a retry is due. */
    didUpdate?: DidUpdateOptions
  },
): Promise<PostOutcome> {
  let { res, sig } = await postWithChallenge(args)

  if (res.status === 409) {
    const first = await readError(res)
    const answer = await answerSuperseded(config, { ...args, signedWith: sig, error: first })
    if (!answer.retry) return { res, sig, error: first, superseded: answer.info }
    ;({ res, sig } = answer.retry)
  }

  if (res.ok) return { res, sig }
  return { res, sig, error: await readError(res) }
}

interface SupersededAnswer {
  info?: DidSupersededInfo
  retry?: { res: Response; sig: SignResult }
}

/**
 * Answer a 409 `did_superseded` as ANP-03 §3.2 requires: fetch the old DID document,
 * verify `deactivated` / `successorDid` / the document proof, and resolve forward to the
 * DID that is active now. The peer's `currentDid` is never what we act on — §3.2 calls
 * it an unverified hint, and re-signing from it would hand the peer the choice of
 * credential.
 *
 * Walking and retrying are separate on purpose. Asking the DID server which DID is
 * current IS the prescribed answer, so the walk's conclusion comes back in `info` even
 * when no retry follows — which is the common case, since an update means a NEW key
 * and the caller whose credential was just rejected usually cannot sign as the
 * successor. Requiring both discarded the one thing the caller cannot compute itself.
 *
 * With no `didChain` nothing happens and no request is issued: that option is what
 * authorises the outbound fetches.
 */
async function answerSuperseded(
  config: AnpConfig,
  args: {
    transport: Fetcher
    targetUri: string
    nonce: string
    body: BodyFields
    envelope?: RequestEnvelope
    didUpdate?: DidUpdateOptions
    signedWith: SignResult
    error: ParsedError
  },
): Promise<SupersededAnswer> {
  const { didUpdate } = args
  if (args.error.serverCode !== 'did_superseded') return {}
  const { didChain, onDidSuperseded } = didUpdate ?? {}
  if (!didChain) return {}

  const body = args.error.body
  // The peer's report is about OUR credential; if it names a different DID it is not
  // about what we signed with, so we report the 409 without acting on it.
  const claimed = typeof body.requestedDid === 'string' ? body.requestedDid : undefined
  if (claimed !== undefined && claimed !== args.signedWith.did) return {}

  const info: DidSupersededInfo = {
    requestedDid: args.signedWith.did,
    claimedCurrentDid: typeof body.currentDid === 'string' ? body.currentDid : undefined,
  }

  // A walk that fails propagates as its own diagnosis (`did_chain_broken` /
  // `did_chain_assurance_too_low` / a resolver transport code): the DID is superseded
  // AND the successor could not be established, which is what a caller must escalate.
  const chain = await resolveDidChain(info.requestedDid, didChain)
  info.chain = chain
  info.verifiedCurrentDid = chain.currentDid

  // Our own documents say this DID is still current, so there is no successor to move
  // to; report the peer's 409 with our contrary conclusion attached.
  if (!chain.superseded || !onDidSuperseded) return { info }

  const supplied = await onDidSuperseded(info)
  if (supplied == null) return { info }
  const connector = typeof supplied === 'string' ? selectWallet(config, supplied) : supplied
  await assertAvailable(connector)

  const identity = await connector.getIdentity()
  if (identity.did !== chain.currentDid) {
    throw new ConnectxError(
      'invalid_argument',
      `onDidSuperseded returned a signer for "${identity.did}" while the verified current DID is "${chain.currentDid}"`,
    )
  }

  // The same pipeline as the first attempt, so a burned nonce still gets the 401
  // re-sign treatment instead of failing the login outright.
  const retry = await postWithChallenge({
    connector,
    transport: args.transport,
    envelope: args.envelope,
    targetUri: args.targetUri,
    nonce: args.nonce,
    body: args.body,
  })
  return { info, retry }
}

export async function assertAvailable(connector: AnpConnector): Promise<void> {
  if (!(await connector.isAvailable())) throw new ConnectorUnavailableError(connector.id)
}

/** The ANP-02 §3.2.4.1 error vocabulary. A server speaking ANP-02 reports one of
 *  these in the `WWW-Authenticate` params and/or the response body's `error`. */
export type AnpAuthError =
  | 'invalid_request'
  | 'invalid_nonce'
  | 'invalid_timestamp'
  | 'invalid_did'
  | 'invalid_signature'
  | 'invalid_verification_method'
  | 'invalid_content_digest'
  | 'invalid_access_token'
  | 'forbidden_did'

const ANP_AUTH_ERRORS = new Set<string>([
  'invalid_request',
  'invalid_nonce',
  'invalid_timestamp',
  'invalid_did',
  'invalid_signature',
  'invalid_verification_method',
  'invalid_content_digest',
  'invalid_access_token',
  'forbidden_did',
])

/** Narrow a value to the ANP-02 authentication error vocabulary. */
export function isAnpAuthError(value: unknown): value is AnpAuthError {
  return typeof value === 'string' && ANP_AUTH_ERRORS.has(value)
}

/** A parsed `WWW-Authenticate` challenge. The scheme is returned because ANP-02 is
 *  method-agnostic even though the wire value is still spelled `DIDWba` today. */
export interface WwwAuthenticateChallenge {
  scheme: string
  realm?: string
  error?: AnpAuthError
  /** ANP-02's `error_description` — human-readable, NOT safe to branch on. */
  errorDescription?: string
  /** Server-issued challenge the client must re-sign with (401 only). */
  nonce?: string
}

/**
 * Parse a `WWW-Authenticate` header, e.g.
 *   `DIDWba realm="api.example.com", error="invalid_signature", nonce="xyz987"`
 *
 * Returns `undefined` for an empty header. Values may be quoted-strings (which can
 * contain commas) or bare tokens, per RFC 9110; a malformed tail is ignored rather
 * than throwing, since a challenge is untrusted peer input and the caller's
 * fallback is simply "no nonce offered".
 */
export function parseWwwAuthenticate(header: string | null | undefined): WwwAuthenticateChallenge | undefined {
  const text = (header ?? '').trim()
  if (text === '') return undefined
  const space = text.search(/\s/)
  const scheme = space === -1 ? text : text.slice(0, space)
  const fields = parseAuthParams(space === -1 ? '' : text.slice(space + 1))
  return {
    scheme,
    realm: fields.realm,
    error: isAnpAuthError(fields.error) ? fields.error : undefined,
    errorDescription: fields.error_description,
    nonce: fields.nonce,
  }
}

/**
 * Parse an `Accept-Signature` header — the covered components the server wants on
 * the next request, e.g.
 *   `sig1=("@method" "@target-uri" "@authority" "content-digest");created;expires`
 *
 * Returns the component names of the first entry, or `[]` when none is present.
 * Advisory only: the client still decides what it covers (covering more than asked
 * is fine, covering less is what the verifier rejects).
 */
export function parseAcceptSignature(header: string | null | undefined): string[] {
  const text = (header ?? '').trim()
  const open = text.indexOf('(')
  if (open === -1) return []
  const close = text.indexOf(')', open + 1)
  if (close === -1) return []
  return text
    .slice(open + 1, close)
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((c) => c.replace(/^"|"$/g, ''))
    .filter((c) => c !== '')
}

/** Parse an RFC 9110 `param=value` list (used by WWW-Authenticate). Names are
 *  lowercased; a quoted value may contain commas and backslash escapes. */
function parseAuthParams(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  let i = 0
  while (i < text.length) {
    while (i < text.length && (text[i] === ',' || /\s/.test(text[i]))) i++
    if (i >= text.length) break
    const eq = text.indexOf('=', i)
    if (eq === -1) break
    const name = text.slice(i, eq).trim().toLowerCase()
    i = eq + 1
    let value: string
    if (text[i] === '"') {
      i++
      let out2 = ''
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < text.length) {
          out2 += text[i + 1]
          i += 2
          continue
        }
        out2 += text[i]
        i++
      }
      i++ // closing quote
      value = out2
    } else {
      const start = i
      while (i < text.length && text[i] !== ',') i++
      value = text.slice(start, i).trim()
    }
    if (name !== '') out[name] = value
  }
  return out
}

/** Extract the server's `nonce` challenge from a 401 `WWW-Authenticate` header. */
function nonceFromChallenge(res: Response): string | undefined {
  return parseWwwAuthenticate(res.headers.get('www-authenticate'))?.nonce
}

/** Extract the access token from `Authentication-Info` (header) or `{ token }` (body),
 *  together with the `token_type` the server named for it (ANP-02 §3.2.3).
 *
 *  The two are read from the SAME source on purpose: a `token_type` from the header
 *  describes the header's token, and pairing it with a body token (or the reverse)
 *  would attach one source's typing rules to another source's credential.
 *
 *  Exported for `zk/client.ts`: the ZK profile issues its token through the very same
 *  two carriers (§6.4 reuses ANP-02 L197), and a second reader of `Authentication-Info`
 *  is exactly where the two would drift apart. Not on the main entry — see `index.ts`,
 *  which lists every public name explicitly. */
export function accessTokenFrom(
  res: Response,
  bodyData?: Record<string, unknown>,
): { token?: string; tokenType?: string } {
  const authInfo = res.headers.get('authentication-info')
  if (authInfo) {
    const m = /access_token="([^"]+)"/.exec(authInfo) ?? /access_token=([^,\s]+)/.exec(authInfo)
    if (m) {
      // An empty `token_type=""` reads as absent, not as a type the SDK would then
      // have to report as "not Bearer" — the spec permits an absent one to default.
      const t = /token_type="([^"]+)"/.exec(authInfo) ?? /token_type=([^,\s]+)/.exec(authInfo)
      return { token: m[1], tokenType: t?.[1] }
    }
  }
  // The body form is the non-normative convenience this SDK has always accepted
  // (§4.2 leaves the header-less case undefined), so it carries a `token_type` too
  // when the server sends one.
  if (bodyData && typeof bodyData.token === 'string') {
    return {
      token: bodyData.token,
      tokenType: typeof bodyData.token_type === 'string' ? bodyData.token_type : undefined,
    }
  }
  return {}
}

// Cap on how many bytes of a remote response body the SDK will read and parse.
// Both the success and error paths go through this, so a huge response — whether it
// declares a big Content-Length or streams indefinitely — cannot be buffered fully
// into memory (client-side DoS). Login/register responses are tiny (token + doc url).
const MAX_BODY_BYTES = 1_048_576 // 1 MiB

/** Read a response body up to `maxBytes`, rejecting anything larger. A declared
 *  Content-Length is checked up front; a streaming body is read under a cap so the
 *  reader is canceled (and the network abandoned) as soon as it overflows.
 *
 *  Exported for `did/discovery.ts`, which reads a DID document from a peer: one
 *  implementation of the cap, so neither read can drift into buffering a whole stream. */
export async function readBodyBounded(res: Response, maxBytes = MAX_BODY_BYTES): Promise<string> {
  const length = res.headers.get('content-length')
  if (length) {
    const declared = Number(length)
    if (Number.isFinite(declared) && declared > maxBytes) {
      throw new ConnectxError('response_too_large', `Response body exceeds ${maxBytes} bytes`)
    }
  }
  const body = res.body
  if (!body) return ''
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      // Abandon the stream, but don't let a cancel rejection mask the size error.
      await reader.cancel().catch(() => {})
      throw new ConnectxError('response_too_large', `Response body exceeds ${maxBytes} bytes`)
    }
    chunks.push(value)
  }
  const buffer = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    buffer.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(buffer)
}

/** Read and JSON-parse a success body with a byte cap. A `response_too_large`
 *  propagates; a body that is not valid JSON resolves to `{}` so login/register
 *  still succeed with defaults (the token usually comes from a header). */
export async function readSuccessBody(res: Response): Promise<Record<string, unknown>> {
  try {
    return JSON.parse(await readBodyBounded(res)) as Record<string, unknown>
  } catch (err) {
    if (err instanceof ConnectxError) throw err
    return {}
  }
}

/** Refuse a 2xx that came back as a web page.
 *
 *  A 2xx is not by itself an answer from an ANP peer, and everything a success outcome
 *  needs is optional: the token usually rides in a header, the confirmed handle falls
 *  back to the one we sent, and the body may legitimately be empty (a 204). So a page
 *  that answers 200 would be reported as a successful login / registration, and nothing
 *  about that outcome looks wrong to the caller. The likely cause is a `targetUri`
 *  aimed at a site origin rather than at the endpoint — the mistake a caller cannot
 *  detect afterwards, which is exactly why it must fail here.
 *
 *  Only HTML is refused. A non-JSON or absent body from a real peer stays tolerated:
 *  the body is genuinely optional, so requiring a shape would break servers that omit it. */
export function assertNotWebPage(res: Response, targetUri: string): void {
  const mime = (res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase()
  if (mime !== 'text/html' && mime !== 'application/xhtml+xml') return
  throw new ConnectxError(
    'invalid_argument',
    `POST ${targetUri} answered ${res.status} ${mime}: that is a web page, not an ANP endpoint`,
    { status: res.status },
  )
}

/** Build the error for a peer's non-2xx response. `code` is the SDK's stable
 *  taxonomy; the HTTP status and the peer's own `code` ride along so a caller can
 *  still branch on what the server said — e.g. `err.serverCode === 'handle_taken'`.
 *
 *  `error` is the body already parsed by the caller, never re-read here: consuming
 *  the stream twice would lose `status` and `serverCode` on the second read. */
export function serverError(
  code: 'login_failed' | 'register_failed' | 'update_failed',
  res: Response,
  error: ParsedError,
  superseded?: DidSupersededInfo,
): ConnectxError {
  const { message, serverCode, anpError } = error
  // ANP-02 §3.2.4.2: a 403 means the DID authenticated but is not permitted, which
  // is a different caller decision from "your proof was rejected" — so it gets its
  // own code instead of being folded into login_failed / register_failed.
  //
  // The 409 is narrowed by `serverCode` rather than taken as a whole: this peer
  // already uses 409 for an unrelated conflict (`handle_taken` on a duplicate
  // registration), and mapping every 409 to a DID-update code would mislabel it.
  const finalCode: ConnectxErrorCode =
    res.status === 403
      ? anpError === 'forbidden_did' || serverCode === 'forbidden_did'
        ? 'forbidden_did'
        : 'authorization_denied'
      : res.status === 409 && serverCode === 'did_superseded'
        ? 'did_superseded'
        : code
  return new ConnectxError(finalCode, message, {
    status: res.status,
    serverCode,
    // Only the 409 carries the walk's conclusion, and only when we actually walked.
    didSuperseded: finalCode === 'did_superseded' ? superseded : undefined,
  })
}

/** A peer's error response, parsed. `body` is kept because a 409 `did_superseded`
 *  carries the update hint the caller needs (`requestedDid` / `currentDid` /
 *  `stableSubjectId`), and it must be read from the SAME single read as the rest.
 *
 *  Exported with {@link readError} for `zk/client.ts`, which reports a rejected ZK
 *  login through the same `serverError` this file's pipelines use — the two halves of
 *  one read cannot be split without one of them re-reading the stream. */
export interface ParsedError {
  message: string
  serverCode?: string
  anpError?: string
  body: Record<string, unknown>
}

/** Read a bounded error body. Returns the human-readable `message`, the peer's
 *  machine-readable value, and — when the peer speaks ANP-02 — the spec error.
 *
 *  Two response shapes are handled, because both are in the wild:
 *  ANP-02 §3.2.4.1 uses `{ error: <spec value>, error_description }`, while
 *  agent-on uses a generic `error` plus its own `code` (`handle_taken`,
 *  `did_superseded`). The header is checked too: §4.2.2 makes `WWW-Authenticate`
 *  the authoritative challenge source, and the body only mirrors it.
 *  Oversized responses throw `response_too_large`; a non-JSON body falls back to status.
 *  Exported with {@link ParsedError} — see there. */
export async function readError(res: Response): Promise<ParsedError> {
  const challenge = parseWwwAuthenticate(res.headers.get('www-authenticate'))
  let data: Record<string, unknown>
  try {
    // A peer's body is untrusted input, so narrow it to a plain object before reading
    // fields: a JSON `null` (or an array, or a scalar) must not become a TypeError here.
    const parsed: unknown = JSON.parse(await readBodyBounded(res))
    data = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {}
  } catch (err) {
    if (err instanceof ConnectxError) throw err
    return { message: `Request failed (${res.status})`, anpError: challenge?.error, body: {} }
  }
  const anpError = (isAnpAuthError(data.error) ? data.error : undefined) ?? challenge?.error
  const serverCode = typeof data.code === 'string' ? data.code : undefined
  const description = typeof data.error_description === 'string' ? data.error_description : undefined
  const message =
    description ??
    (typeof data.error === 'string' ? data.error : undefined) ??
    challenge?.errorDescription ??
    `Request failed (${res.status})`
  return { message, serverCode: anpError ?? serverCode, anpError, body: data }
}
