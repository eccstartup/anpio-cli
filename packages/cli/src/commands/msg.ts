// The `msg` family — the client half of an ANPMessageService, i.e. `connectx` talking
// to `AgentXAgent` (or to any conforming service, `awiki-open-server` included).
//
// Two things this file is NOT allowed to do (docs/design/cli.md §9), because both are
// places where a second implementation fails in the hardest possible way — the
// signature verifies on this machine and nowhere else:
//
//   - assemble a JSON-RPC envelope;            `buildMessageRequest` does, once
//   - canonicalize for the origin proof;       `buildOriginProofAuth` does, once
//
// What is left is the part only a command can do: pick the recipient, decide the
// payload, drive the discovery, and report what came back.

import { randomUUID } from 'node:crypto'
import {
  buildMessageRequest,
  buildOriginProofAuth,
  discoverMessageService,
  parseCapabilities,
  postMessage,
  anpCodeOf,
  resolveDidChain,
  walletOriginProofSigner,
  ConnectxError,
} from '@agentx/core'
import type {
  AnpCapabilities,
  AnpErrorResponse,
  AnpMessageServiceTarget,
  AnpMeta,
  AnpResponse,
  DidChain,
  DidChainOptions,
  OriginProofSigner,
  ResolveDidOptions,
} from '@agentx/core'
import { buildConnector, cliError, require, type Values } from './auth'
import { didHost, relaxedHosts } from './did'

/** P3 §7.1.2 L353–355: the three fixed values of a `direct.send`. */
const DIRECT_SEND = 'direct.send'
const DIRECT_PROFILE = 'anp.direct.base.v1'
const TRANSPORT_PROTECTED = 'transport-protected'

/** P1 §8.2 L520. */
const GET_CAPABILITIES = 'anp.get_capabilities'
/** P1 §8.2.1 L528: a capabilities probe explains itself under the core binding. */
const CORE_BINDING = 'anp.core.binding.v1'

/** ANP error 1019 (P1 §10.3 L720). The description is the contract this file follows:
 *  "请求使用的 DID 已存在后继；调用方必须验证迁移、重建请求并重新签名". */
const DID_SUPERSEDED = 'anp.did_superseded'

/** `connectx msg show|inbox|read` and `listen` are NOT here yet: the extension surface
 *  they need is not a Profile, its argument shapes are the implementation's, and
 *  nothing above this line may guess at them (docs/design/cli.md §5). */
export async function runMsg(v: Values, sub: string | undefined, positional: string | undefined): Promise<void> {
  switch (sub) {
    case 'send':
      return runSend(v)
    case 'caps':
      return runCaps(v, positional)
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx msg\``)
  }
}

// ---- the outbound network policy ---------------------------------------------

/** The policy for a fetch whose host is DERIVED rather than typed.
 *
 *  `did resolve` makes the caller name `--allow-host`, because there the host is the
 *  thing being asked about. Here it comes from `--to <did>`: it IS the recipient, and a
 *  second flag repeating it would only be one more way to get it wrong. What the caller
 *  still controls is the private-address gate, because a message service on this machine
 *  is a development setup (`--allow-private-host`). */
function policyFor(hosts: readonly string[], v: Values): ResolveDidOptions {
  const allowedHosts = [...new Set(hosts)]
  const relaxed = relaxedHosts(allowedHosts, v)
  return {
    allowedHosts,
    ...(relaxed.length > 0 ? { allowPrivateHosts: relaxed, allowInsecureTransport: relaxed } : {}),
  }
}

/** The host a DID names, or `undefined` when the identifier names none.
 *
 *  `didHost` throws `invalid_did` for an `eip155:…` account id, and that verdict has to
 *  come from the locator instead (`caip10_has_no_ingress`, docs/design/cli.md §4), so
 *  this swallows it: the empty allowlist that follows is never consulted, because the
 *  locator refuses the identifier before any fetch. Raising the host error here instead
 *  would replace "an account id has no ingress" with a policy complaint about a host
 *  that never existed. */
function hostOf(identity: string): string | undefined {
  try {
    return didHost(identity)
  } catch {
    return undefined
  }
}

/** The host of a `serviceEndpoint`. The document chose it, so a value that is not a URL
 *  is a fact about the document rather than about the caller's flags. */
function endpointHost(endpoint: string): string {
  try {
    return new URL(endpoint).hostname
  } catch {
    throw new ConnectxError(
      'message_service_not_found',
      `the ANPMessageService endpoint ${JSON.stringify(endpoint)} is not a URL`,
    )
  }
}

interface Endpoint {
  target: AnpMessageServiceTarget
  /** The document fetch is held to the DID's host; the POST is held to both that host
   *  and the endpoint's, because the document is what named the endpoint. */
  options: ResolveDidOptions
}

/** P2 §9.1 L549–560: the recipient's document, then its ONE message service.
 *
 *  The locator decides whether this identity can be addressed at all — this file never
 *  asks what kind of identifier it is holding, which is the whole point of §6 of
 *  vendored-core.md and of E3. */
async function discover(identity: string, v: Values): Promise<Endpoint> {
  const documentHost = hostOf(identity)
  const target = await discoverMessageService(identity, policyFor(documentHost === undefined ? [] : [documentHost], v))
  const hosts = documentHost === undefined ? [endpointHost(target.endpoint)] : [documentHost, endpointHost(target.endpoint)]
  return { target, options: policyFor(hosts, v) }
}

// ---- the sender --------------------------------------------------------------

interface Sender {
  did: string
  signer: OriginProofSigner
}

/** The identity this run signs as.
 *
 *  `requireRegistered` because a `direct.send` carries `meta.sender_did` (P3 §7.1.2
 *  L353) and the recipient resolves that DID back to an ingress to answer on. An
 *  identity no DID server has taken on has no such thing, and composing one from
 *  whatever `--target` happened to say would name a host that never accepted this key. */
async function senderFor(v: Values): Promise<Sender> {
  const { connector, wallet } = await buildConnector(v, { requireRegistered: true })
  const identity = await connector.getIdentity()
  return { did: identity.did, signer: walletOriginProofSigner(wallet, identity.keyid) }
}

// ---- the payload -------------------------------------------------------------

interface Payload {
  body: Record<string, unknown>
  contentType: string
}

/** P3 §6.2 and §6.3: of `text` / `payload` / `payload_b64u` EXACTLY one MUST be present,
 *  and the two fixed content types each pin which one (§6.2.4 L262, §6.2.5 L266). The
 *  command therefore takes a payload as text or as a JSON object, and refuses the two
 *  combinations the Profile has no body shape for.
 *
 *  Exported because it is the whole of the command's argument validation: the four
 *  combinations it decides on are the part a test can pin without a peer to talk to. */
export function payloadOf(v: Values): Payload {
  const text = v.text as string | undefined
  const raw = v.body as string | undefined
  const asked = v['content-type'] as string | undefined

  if (text !== undefined && raw !== undefined) {
    throw cliError('invalid_argument', '--text and --body are two spellings of the same thing; pass one')
  }
  if (text === undefined && raw === undefined) {
    throw cliError('missing_flag', 'missing required option --text or --body')
  }

  if (text !== undefined) {
    const contentType = asked ?? 'text/plain'
    if (contentType === 'application/json') {
      throw cliError(
        'invalid_argument',
        '--text is sent as `text`, which content_type application/json does not have a body shape for (P3 §6.2.5 L266); pass --body instead',
      )
    }
    return { body: { text }, contentType }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw as string)
  } catch {
    throw cliError('invalid_argument', `--body must be JSON (got ${JSON.stringify(raw)})`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw cliError(
      'invalid_argument',
      '--body must be a JSON object, which is the only shape `payload` has (P3 §6.2.5 L266); use --text for a plain string',
    )
  }
  const contentType = asked ?? 'application/json'
  if (contentType === 'text/plain') {
    throw cliError(
      'invalid_argument',
      '--body is sent as `payload`, which content_type text/plain does not have a body shape for (P3 §6.2.4 L262); pass --text instead',
    )
  }
  return { body: { payload: parsed }, contentType }
}

// ---- direct.send -------------------------------------------------------------

interface Delivery {
  sender: Sender
  /** `meta.target.did`. Replaced after a VERIFIED migration, never on a peer's word. */
  targetDid: string
  /** `meta.operation_id` == `meta.message_id` (P1 §6.2.6 L392). */
  operationId: string
  contentType: string
  body: Record<string, unknown>
}

async function runSend(v: Values): Promise<void> {
  require(v, 'to')
  const payload = payloadOf(v)
  const sender = await senderFor(v)
  const json = v.json === true

  const delivery: Delivery = {
    sender,
    targetDid: v.to as string,
    // P1 §6.2.6 L392: for a message operation the sender SHOULD make `operation_id`
    // the `message_id`, and P3 §5.5 L208 requires a retry to keep that pair unchanged.
    // One flag therefore pins both, which is the entire reason `--operation-id` exists.
    operationId: (v['operation-id'] as string | undefined) ?? randomUUID(),
    contentType: payload.contentType,
    body: payload.body,
  }

  const first = await deliver(delivery, v)
  if (!isError(first)) return reportAccepted(first.result, json)

  if (anpCodeOf(first) !== DID_SUPERSEDED) throw rejection(first, DIRECT_SEND, delivery.targetDid)

  // P1 §10.3 L726 and P3 §5.5 L206–208: the peer MUST refuse rather than retarget
  // silently, and the sender MUST verify the migration from the DID it actually
  // asked about, rebuilding everything bound to that DID before retrying.
  const chain = await resolveDidChain(delivery.targetDid, chainPolicy(delivery.targetDid, v))
  if (!chain.superseded) {
    // The peer says this DID has a successor; the DID's own documents say it is
    // current. There is nothing to retarget to, and re-sending the same request to the
    // same DID would only get the same answer.
    console.error(
      `connectx: ${delivery.targetDid} was refused as superseded, but its own documents show no migration.`,
    )
    throw rejection(first, DIRECT_SEND, delivery.targetDid)
  }
  reportMigration(delivery.targetDid, claimedCurrentDid(first), chain)

  // Only now is the target replaced, and the whole DID-bound chain is rebuilt with it:
  // the new `meta.target.did` changes the Signed Request Object, so the digest and the
  // signature are made again rather than reused (P1 §10.3 L726).
  delivery.targetDid = chain.currentDid
  const second = await deliver(delivery, v)
  if (!isError(second)) return reportAccepted(second.result, json)
  throw rejection(second, DIRECT_SEND, delivery.targetDid)
}

/** One attempt: discover the recipient's ingress, sign, POST.
 *
 *  Discovery is inside the attempt, not before it: after a verified migration the
 *  successor DID has its own document, and its own ANPMessageService endpoint in it. */
async function deliver(delivery: Delivery, v: Values): Promise<AnpResponse> {
  const { target, options } = await discover(delivery.targetDid, v)
  const meta: AnpMeta = {
    profile: DIRECT_PROFILE,
    security_profile: TRANSPORT_PROTECTED,
    sender_did: delivery.sender.did,
    target: { kind: 'agent', did: delivery.targetDid },
    operation_id: delivery.operationId,
    message_id: delivery.operationId,
    created_at: new Date().toISOString(),
    content_type: delivery.contentType,
  }
  // The Signed Request Object is `{method, meta, body}` (P1 附录 A.3 L1068–1070), so the
  // SAME two objects are handed to the signer and to the envelope builder: one of them
  // copying instead would sign one thing and send another.
  const auth = await buildOriginProofAuth({
    method: DIRECT_SEND,
    meta,
    body: delivery.body,
    signer: delivery.sender.signer,
  })
  // A fresh `id` per exchange: `id` pairs one request with one response, while
  // `operation_id` is what makes the business operation idempotent (P3 §8.2).
  const request = buildMessageRequest({
    id: randomUUID(),
    method: DIRECT_SEND,
    meta,
    auth,
    body: delivery.body,
  })
  return postMessage(target.endpoint, request, options)
}

/** The chain walk's network policy: the TARGET's host, not this identity's. Chain
 *  acceptance stays the caller's, through the same two flags `did resolve --chain`
 *  documents, because the question is the same one — is this migration good enough to
 *  keep talking to. */
function chainPolicy(targetDid: string, v: Values): DidChainOptions {
  return {
    ...policyFor([didHost(targetDid)], v),
    ...(v['accept-provider-asserted'] === true ? { acceptProviderAsserted: true } : {}),
    ...(v['report-low-assurance'] === true ? { reportLowAssurance: true } : {}),
  }
}

/** P1 §10.3 L726: `error.data.details.current_did` is a hint the caller MUST NOT retry
 *  off. It is read here for one purpose — printing it beside our own finding — and the
 *  walk always starts from the DID we sent to, never from what the peer names. */
function claimedCurrentDid(response: AnpErrorResponse): string | undefined {
  const details = response.error.data?.details
  if (typeof details !== 'object' || details === null || Array.isArray(details)) return undefined
  const claimed = (details as Record<string, unknown>).current_did
  return typeof claimed === 'string' ? claimed : undefined
}

/** The peer's claim and our own conclusion, kept apart the way `did resolve` keeps
 *  them: the first is worth nothing on its own, the second is why the retry happens. */
function reportMigration(requested: string, claimed: string | undefined, chain: DidChain): void {
  console.error(`connectx: ${requested} has a successor; the peer's answer was not retargeted off.`)
  if (claimed !== undefined) {
    console.error(`connectx: peer claims:      ${claimed}  (NOT verified — P1 §10.3 L726)`)
  }
  const hops = chain.hops.length
  console.error(
    `connectx: verified current: ${chain.currentDid}  (${chain.assurance}, ${hops} hop${hops === 1 ? '' : 's'} through this DID's own documents)`,
  )
}

// ---- anp.get_capabilities ----------------------------------------------------

/** P1 §8.2: what the peer supports, asked BEFORE sending.
 *
 *  Anonymous on purpose — §8.2.1 L543–544 allow the call, and `meta.sender_did` to be
 *  omitted with it. Requiring an identity would make the one command whose job is "can
 *  this DID be talked to at all" depend on the caller already having one on that DID's
 *  terms. */
async function runCaps(v: Values, positional: string | undefined): Promise<void> {
  if (positional === undefined || positional === '') {
    throw cliError('missing_flag', 'missing required argument <did>')
  }
  const { target, options } = await discover(positional, v)
  const meta: AnpMeta = {
    profile: CORE_BINDING,
    security_profile: TRANSPORT_PROTECTED,
    operation_id: randomUUID(),
    created_at: new Date().toISOString(),
  }
  const request = buildMessageRequest({ id: randomUUID(), method: GET_CAPABILITIES, meta, body: {} })
  const response = await postMessage(target.endpoint, request, options)
  if (isError(response)) throw rejection(response, GET_CAPABILITIES, positional)

  const capabilities = parseCapabilities(response.result)
  if (v.json === true) {
    console.log(JSON.stringify(capabilities, null, 2))
    return
  }
  field('service did:', capabilities.serviceDid)
  field('profiles:', joined(capabilities.supportedProfiles))
  field('security profiles:', joined(capabilities.supportedSecurityProfiles))
  // §8.2.2 L578: recommended, not required, so an empty list is stated rather than
  // rendered as a blank where a reader expects an answer.
  field('content types:', joined(capabilities.supportedContentTypes))
  const limits = Object.entries(capabilities.limits)
  if (limits.length > 0) field('limits:', limits.map(([name, value]) => `${name}=${value}`).join(', '))
}

// ---- reporting ---------------------------------------------------------------

function isError(response: AnpResponse): response is AnpErrorResponse {
  return 'error' in response
}

/** A peer's refusal. The SDK code stays coarse, as it does for login; the peer's own
 *  `anp_code` goes on the message line so a script can branch on it without `--json`. */
function rejection(response: AnpErrorResponse, method: string, identity: string): ConnectxError {
  const anpCode = anpCodeOf(response)
  const named = anpCode ?? `JSON-RPC error ${response.error.code}`
  return new ConnectxError(
    'message_send_failed',
    `${identity} rejected ${method}: ${named}: ${response.error.message}`,
    {
      ...(anpCode !== undefined ? { serverCode: anpCode } : {}),
      cause: { code: response.error.code, anpCode, data: response.error.data },
    },
  )
}

/** P3 §7.1.3 L366–376. Only `accepted` is checked: it MUST be `true` in a success
 *  response, and a run that printed "sent" for `accepted: false` would be reporting the
 *  opposite of what the peer said. The rest is printed as it arrived — this is a shell,
 *  not a second implementation of the receiving side. */
function reportAccepted(result: Record<string, unknown>, json: boolean): void {
  if (result.accepted !== true) {
    throw new ConnectxError('message_invalid', 'direct.send answered without accepted:true (P3 §7.1.3 L368)')
  }
  if (json) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  field('message id:', result.message_id)
  field('operation id:', result.operation_id)
  field('target:', result.target_did)
  field('accepted at:', result.accepted_at)
  field('conversation:', result.conversation_id)
}

function field(label: string, value: unknown): void {
  if (value === undefined) return
  console.log(`${label.padEnd(20)} ${typeof value === 'string' ? value : JSON.stringify(value)}`)
}

function joined(values: readonly string[]): string {
  return values.length === 0 ? '(none)' : values.join(', ')
}
