// The client half of ANP-09, shared by the `msg` and `group` families: who this run signs
// as, which message service answers for a given DID, and one signed call placed on it.
//
// It is a module of its own because three callers now reach the same machinery — the `msg`
// commands, `msg listen` over its socket, and the `group` commands — and the parts that
// must happen exactly once are precisely the parts that break in the hardest way when they
// are copied. The two laws `msg.ts` states at the top (`buildMessageRequest` assembles the
// envelope, `buildOriginProofAuth` canonicalizes for the proof) are joined here by a third:
// the SAME `meta` object is handed to the signer and to the envelope builder, so one of them
// copying would sign one thing and send another.

import { randomUUID } from 'node:crypto'
import {
  buildMessageRequest,
  buildOriginProofAuth,
  discoverMessageService,
  postMessage,
  anpCodeOf,
  walletOriginProofSigner,
  ConnectxError,
} from '@agentx/core'
import type {
  AnpErrorResponse,
  AnpMessageServiceTarget,
  AnpMeta,
  AnpResponse,
  AnpTarget,
  OriginProofSigner,
  ResolveDidOptions,
} from '@agentx/core'
import { buildConnector, cliError, type Values } from './auth'
import { didHost, relaxedHosts } from './did'

export const TRANSPORT_PROTECTED = 'transport-protected'

/** JSON-RPC "no such method". */
export const METHOD_NOT_FOUND = -32601
/** P1 §10.3: 1001 `anp.unsupported_profile`. On an `x_agentx.*` profile this says the
 *  same thing `-32601` does — the peer does not implement this extension. */
export const UNSUPPORTED_PROFILE = 'anp.unsupported_profile'

/** ANP error 1019 (P1 §10.3 L720). The description is the contract: "请求使用的 DID 已存在
 *  后继；调用方必须验证迁移、重建请求并重新签名". */
export const DID_SUPERSEDED = 'anp.did_superseded'

/** The extension surface's own Profile (message-service.md §9.1). P1 §6.2.2 L277 makes
 *  `meta.profile` MUST and calls it "本次请求的唯一解释 Profile", so a read request has
 *  to name one — and no normative Profile interprets `inbox.get`. The `x_` prefix is the
 *  namespace P1 §12 leaves for extensions, and it is what keeps this value out of the
 *  `profiles[]` a service advertises as its spec conformance (message-service.md §13). */
export const EXTENSION_PROFILE = 'x_agentx.inbox.v1'

// ---- the outbound network policy ---------------------------------------------

/** The policy for a fetch whose host is DERIVED rather than typed.
 *
 *  `did resolve` makes the caller name `--allow-host`, because there the host is the
 *  thing being asked about. Here it comes from a DID: it IS the peer, and a second flag
 *  repeating it would only be one more way to get it wrong. What the caller still
 *  controls is the private-address gate, because a message service on this machine is a
 *  development setup (`--allow-private-host`). */
export function policyFor(hosts: readonly string[], v: Values): ResolveDidOptions {
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
export function hostOf(identity: string): string | undefined {
  try {
    return didHost(identity)
  } catch {
    return undefined
  }
}

function endpointHost(endpoint: string): string {
  try {
    return new URL(endpoint).host
  } catch {
    return ''
  }
}

export interface Endpoint {
  target: AnpMessageServiceTarget
  options: ResolveDidOptions
}

/**
 * P2 §9.1 L553–555 for an agent and §9.2 L566–567 for a group are the same two steps, and
 * L546–548 says so: the Agent, Group and Service flows are one discovery picture
 * specialised per target, not three philosophies. A group DID's document carries its own
 * `ANPMessageService` entry exactly as an agent's does, so the group commands address a
 * group by resolving the group's own DID — there is no group-specific lookup to write.
 *
 * Only a group is ever discovered this way. `group.create` has no group DID yet, and P4
 * §8.1.2 L624–625 aims it at a SERVICE, so that one command resolves the caller's own DID.
 */
export async function discover(identity: string, v: Values): Promise<Endpoint> {
  const documentHost = hostOf(identity)
  const target = await discoverMessageService(identity, policyFor(documentHost === undefined ? [] : [documentHost], v))
  const hosts = documentHost === undefined ? [endpointHost(target.endpoint)] : [documentHost, endpointHost(target.endpoint)]
  return { target, options: policyFor(hosts, v) }
}

// ---- the sender --------------------------------------------------------------

export interface Sender {
  did: string
  signer: OriginProofSigner
  /** The local `agent` / `profile` names this run signs under. They are what `msg listen`
   *  derives its default `device_id` from (realtime.md §5.4), so they belong with the
   *  identity rather than being looked up a second time by whichever command needs them. */
  agent: string
  profile: string
}

/** The identity this run signs as.
 *
 *  `requireRegistered` because a message carries `meta.sender_did` (P3 §7.1.2 L353) and
 *  the recipient resolves that DID back to an ingress to answer on. An identity that only
 *  exists on this machine has no ingress, so a send signed by one could not be answered —
 *  refusing here is what keeps that from looking like a network problem later. */
export async function senderFor(v: Values): Promise<Sender> {
  const { connector, wallet, location } = await buildConnector(v, { requireRegistered: true })
  const identity = await connector.getIdentity()
  return {
    did: identity.did,
    signer: walletOriginProofSigner(wallet, identity.keyid),
    agent: location.agent,
    profile: location.profile,
  }
}

/** A read is addressed to the caller's OWN message service. There is no `--to`: the
 *  owner of the inbox is `meta.sender_did`, so the DID whose document has to be fetched
 *  for the service entry is the one we sign as. */
export interface Channel {
  sender: Sender
  target: AnpMessageServiceTarget
  options: ResolveDidOptions
}

/** Exported for `msg listen`, which authenticates the same way but over a socket instead
 *  of a POST: one channel resolution, one signer, two transports (realtime.md §3). */
export async function openChannel(v: Values): Promise<Channel> {
  const sender = await senderFor(v)
  const { target, options } = await discover(sender.did, v)
  return { sender, target, options }
}

// ---- one signed call ---------------------------------------------------------

/** What one call puts on the wire, minus the envelope and the signature.
 *
 *  `target` is a parameter rather than a constant because P4 gives two answers within one
 *  family: `group.create` names the SERVICE it is asking to make a group (§8.1.2 L624),
 *  every other group method names the GROUP (§8.2.2 L648–649, §8.9.2 L833–834). `meta.target` is part
 *  of the Signed Request Object, so this is a signed decision, not a routing hint. */
export interface CallRequest {
  method: string
  profile: string
  target: AnpTarget
  body: Record<string, unknown>
  /** P1 §6.2.7 L399: a message-bearing operation MUST carry it. Set by `direct.send` and
   *  `group.send`, absent on a state change. */
  messageId?: string
  /** P1 §6.2.10 L427 / P4 §7.6 L430: likewise. */
  contentType?: string
}

/** POST one signed request. The response is returned as it arrived — success and refusal
 *  are both answers, and only the caller knows which of them it can act on. */
export async function call(
  channel: Channel,
  request: CallRequest,
  post: typeof postMessage = postMessage,
): Promise<AnpResponse> {
  const meta: AnpMeta = {
    profile: request.profile,
    security_profile: TRANSPORT_PROTECTED,
    sender_did: channel.sender.did,
    target: request.target,
    operation_id: randomUUID(),
    created_at: new Date().toISOString(),
    ...(request.messageId !== undefined ? { message_id: request.messageId } : {}),
    ...(request.contentType !== undefined ? { content_type: request.contentType } : {}),
  }
  // P1 附录 A.3 L1068–1070: the Signed Request Object is `{method, meta, body}`, so the
  // SAME two objects go to the signer and to the envelope builder.
  const auth = await buildOriginProofAuth({ method: request.method, meta, body: request.body, signer: channel.sender.signer })
  // A fresh `id` per exchange: `id` pairs one request with one response, while
  // `operation_id` is what makes the business operation idempotent.
  const envelope = buildMessageRequest({ id: randomUUID(), method: request.method, meta, auth, body: request.body })
  return post(channel.target.endpoint, envelope, channel.options)
}

/** One extension call. Authenticated exactly like `direct.send` — `origin_proof` over
 *  `{method, meta, body}`, no bearer token — because the CLI does not hold one and the
 *  proof is the stronger answer anyway (cli.md §6).
 *
 *  `meta.target` is the mailbox owner, i.e. the identity in use. That is not a formality:
 *  P1 附录 A.4 L1068 requires `meta.target` whenever a method carries an `origin_proof`,
 *  and the same appendix requires an endpoint-local method to have its target modelling
 *  written down by its Profile — which is message-service.md §9.1.1. Reading one's own
 *  inbox is addressed to oneself, so `target.did` and `sender_did` are the same DID. */
export async function callExtension(
  channel: Channel,
  method: string,
  body: Record<string, unknown>,
  post: typeof postMessage = postMessage,
): Promise<Record<string, unknown>> {
  const response = await call(
    channel,
    { method, profile: EXTENSION_PROFILE, target: { kind: 'agent', did: channel.sender.did }, body },
    post,
  )
  if (isError(response)) throw extensionRejection(response, method, channel.sender.did)
  return response.result
}

// ---- the payload -------------------------------------------------------------

export interface Payload {
  body: Record<string, unknown>
  contentType: string
}

/**
 * Of `text` / `payload` / `payload_b64u` EXACTLY one MUST be present, and the two fixed
 * content types each pin which one. The command therefore takes a payload as text or as a
 * JSON object, and refuses the two combinations the Profiles have no body shape for.
 *
 * Written once because P3 §6.2.4 L262 / §6.2.5 L266 and P4 §7.6 L438–447 state the same
 * three-way rule for `direct.send` and `group.send`; the citations differ, the constraint
 * does not, and two copies of it would be two chances to drift.
 */
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
        '--text is sent as `text`, which content_type application/json does not have a body shape for (P3 §6.2.5 L266 / P4 §7.6 L449); pass --body instead',
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
      '--body must be a JSON object, which is the only shape `payload` has (P3 §6.2.5 L266 / P4 §7.6 L449); use --text for a plain string',
    )
  }
  const contentType = asked ?? 'application/json'
  if (contentType === 'text/plain') {
    throw cliError(
      'invalid_argument',
      '--body is sent as `payload`, which content_type text/plain does not have a body shape for (P3 §6.2.4 L262 / P4 §7.6 L438); pass --text instead',
    )
  }
  return { body: { payload: parsed }, contentType }
}

// ---- reporting ---------------------------------------------------------------

export function isError(response: AnpResponse): response is AnpErrorResponse {
  return 'error' in response
}

/** A peer's refusal. The SDK code stays coarse, as it does for login; the peer's own
 *  `anp_code` goes on the message line so a script can branch on it without `--json`. */
export function rejection(response: AnpErrorResponse, method: string, identity: string): ConnectxError {
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

/** B8. A peer that has no extension surface is not a failure — it is an answer, and a
 *  specific one. Both codes say "I do not have this": `-32601` is what a JSON-RPC
 *  service returns for a method it does not implement (awiki's `dispatch` returns it for
 *  an unknown method or a mismatched surface), and `1001` is what a service returns for a
 *  Profile it does not know.
 *
 *  No capabilities probe is made first: an extension Profile is not supposed to be in
 *  `profiles[]` (message-service.md §13), so the probe could only ever confirm the
 *  absence, at the price of a second round trip (cli.md §5). */
export function extensionRejection(response: AnpErrorResponse, method: string, identity: string): ConnectxError {
  const anpCode = anpCodeOf(response)
  if (response.error.code !== METHOD_NOT_FOUND && anpCode !== UNSUPPORTED_PROFILE) {
    return rejection(response, method, identity)
  }
  const named = anpCode ?? `JSON-RPC error ${response.error.code}`
  return new ConnectxError(
    'unsupported_extension',
    `${identity} does not implement ${method} (${named}): the inbox / history / read-state methods ` +
      'are an implementation extension, not defined by the ANP message specification',
    {
      ...(anpCode !== undefined ? { serverCode: anpCode } : {}),
      cause: { code: response.error.code, anpCode, data: response.error.data },
    },
  )
}

export function field(label: string, value: unknown): void {
  if (value === undefined) return
  console.log(`${label.padEnd(20)} ${typeof value === 'string' ? value : JSON.stringify(value)}`)
}

export function joined(values: readonly string[]): string {
  return values.length === 0 ? '(none)' : values.join(', ')
}

/** A peer's JSON, narrowed rather than trusted: everything that reads it may meet a
 *  different implementation, and a value with a field missing is still worth printing. */
export type Row = Record<string, unknown>

export function asRow(value: unknown): Row | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Row) : undefined
}

export function rowsOf(result: Row, key: string): Row[] {
  const raw = result[key]
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    const row = asRow(item)
    return row === undefined ? [] : [row]
  })
}

export function textOf(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined
}
