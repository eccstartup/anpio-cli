// The `msg` family — the client half of an ANPMessageService, i.e. `connectx` talking
// to `AgentXAgent` (or to any conforming service, `awiki-open-server` included).
//
// What is left here is what only a `msg` command can decide: which recipient, which
// payload, and how to report what came back. Resolving a DID to its message service,
// holding the signer, and placing one signed call are shared with `group` and live in
// `channel.ts`, along with the two laws this file used to state at its top —
// `buildMessageRequest` assembles the envelope, `buildOriginProofAuth` canonicalizes for
// the origin proof, and neither is assembled a second time anywhere.

import { randomUUID } from 'node:crypto'
import {
  buildMessageRequest,
  buildOriginProofAuth,
  parseCapabilities,
  postMessage,
  resolveDidChain,
  anpCodeOf,
  ConnectxError,
} from '@agentx/core'
import type { AnpErrorResponse, AnpMeta, AnpResponse, DidChain, DidChainOptions } from '@agentx/core'
import { cliError, require, type Values } from './auth'
import { didHost } from './did'
import {
  DID_SUPERSEDED,
  TRANSPORT_PROTECTED,
  asRow,
  callExtension,
  discover,
  field,
  isError,
  joined,
  openChannel,
  payloadOf,
  policyFor,
  rejection,
  rowsOf,
  senderFor,
  type Channel,
  type Row,
  type Sender,
} from './channel'
import { runListen } from './listen'

/** P3 §7.1.2 L353–355: the three fixed values of a `direct.send`. */
const DIRECT_SEND = 'direct.send'
const DIRECT_PROFILE = 'anp.direct.base.v1'

/** P1 §8.2 L520. */
const GET_CAPABILITIES = 'anp.get_capabilities'
/** P1 §8.2.1 L528: a capabilities probe explains itself under the core binding. */
const CORE_BINDING = 'anp.core.binding.v1'

/** message-service.md §9.3: the three extension methods the read commands call. */
const INBOX_GET = 'inbox.get'
const INBOX_MARK_READ = 'inbox.mark_read'
const MESSAGE_GET_BATCH = 'message.get_batch'

/** How many unread ids `msg read --all` asks for at a time. */
const ALL_PAGE = 100

export async function runMsg(v: Values, sub: string | undefined, args: string[]): Promise<void> {
  switch (sub) {
    case 'send':
      return runSend(v)
    case 'caps':
      return runCaps(v, args[0])
    case 'inbox':
      return runInbox(v)
    case 'show':
      return runShow(v, args[0])
    case 'read':
      return runRead(v, args)
    case 'listen':
      return runListen(v)
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx msg\``)
  }
}

// ---- direct.send -------------------------------------------------------------

interface Delivery {
  sender: Sender
  /** `meta.target.did`. Replaced after a VERIFIED migration, never on a peer's word. */
  targetDid: string
  /** `meta.operation_id` == `meta.message_id` (P1 §6.2.6 L394). */
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
    // P1 §6.2.6 L394: for a message operation the sender SHOULD make `operation_id`
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

// ---- the extension surface (message-service.md §9) ---------------------------

/** message-service.md §9.3: `inbox.get` takes `limit` (default 20), `skip`, `include_read`. */
function limitOf(v: Values): number {
  const raw = v.limit as string | undefined
  if (raw === undefined) return 20
  const parsed = Number(raw)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw cliError('invalid_argument', `--limit must be a positive integer (got ${JSON.stringify(raw)})`)
  }
  return parsed
}

// ---- msg inbox / show / read -------------------------------------------------

async function runInbox(v: Values): Promise<void> {
  const body: Record<string, unknown> = { limit: limitOf(v) }
  if (v['include-read'] === true) body.include_read = true
  const result = await callExtension(await openChannel(v), INBOX_GET, body)
  if (v.json === true) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  const rows = rowsOf(result, 'messages')
  if (rows.length === 0) {
    console.log(v['include-read'] === true ? 'no messages' : 'no unread messages; pass --include-read to see the rest')
    return
  }
  console.log(summaryOf(rows, result))
  for (const row of rows) console.log(renderMessage(row).join('\n'))
}

async function runShow(v: Values, id: string | undefined): Promise<void> {
  if (id === undefined || id === '') {
    throw cliError('missing_flag', 'missing required argument <message_id>')
  }
  const result = await callExtension(await openChannel(v), MESSAGE_GET_BATCH, { message_ids: [id] })
  if (v.json === true) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  const rows = rowsOf(result, 'items').flatMap((item) => {
    const message = asRow(item.message)
    return message === undefined ? [] : [message]
  })
  // `unavailable` is the peer's list of ids it could not resolve, and it is why this is
  // reported rather than rendered as an empty inbox — a message that does not exist and
  // one that was asked for under the wrong id look identical otherwise.
  if (rows.length === 0) throw new ConnectxError('message_not_found', `no message ${id} in this inbox`)
  for (const row of rows) console.log(renderMessage(row).join('\n'))
}

async function runRead(v: Values, ids: string[]): Promise<void> {
  const all = v.all === true
  if (all && ids.length > 0) {
    throw cliError('invalid_argument', '--all and <message_id> are two spellings of the same thing; pass one')
  }
  if (!all && ids.length === 0) {
    throw cliError('missing_flag', 'missing required argument <message_id>, or --all')
  }
  const channel = await openChannel(v)
  const messageIds = all ? await unreadIds(channel) : ids
  if (messageIds.length === 0) {
    if (v.json === true) console.log(JSON.stringify({ updated_count: 0, message_ids: [], read_at: null }, null, 2))
    else console.log('nothing unread')
    return
  }
  const result = await callExtension(channel, INBOX_MARK_READ, { message_ids: messageIds })
  if (v.json === true) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  field('marked read:', typeof result.updated_count === 'number' ? result.updated_count : messageIds.length)
  field('read at:', result.read_at)
}

/** Every unread id, paged. `--all` marks the ids that were LISTED, not "whatever is unread
 *  when the write lands": a message arriving between the two calls is left unread, which is
 *  the only reading of the flag that does not silently swallow one (message-service.md §9.3). */
async function unreadIds(channel: Channel): Promise<string[]> {
  const ids: string[] = []
  let skip = 0
  for (;;) {
    const page = await callExtension(channel, INBOX_GET, { limit: ALL_PAGE, skip, include_read: false })
    const rows = rowsOf(page, 'messages')
    for (const row of rows) {
      const id = idOf(row)
      if (id !== undefined) ids.push(id)
    }
    // A page that contributes nothing under `has_more` would repeat forever, so an empty
    // page ends the walk whatever the flag says.
    if (page.has_more !== true || rows.length === 0) return ids
    skip += rows.length
  }
}

// ---- reading what came back --------------------------------------------------

/** The identifier `msg show` takes. `id` is the same value under the name
 *  `_direct_message_result` also publishes, so either spelling resolves. */
function idOf(row: Row): string | undefined {
  const id = row.message_id ?? row.id
  return typeof id === 'string' && id !== '' ? id : undefined
}

function summaryOf(rows: Row[], result: Row): string {
  const unread = rows.filter(isUnread).length
  const more = result.has_more === true ? ' (more available)' : ''
  return `${rows.length} message${rows.length === 1 ? '' : 's'}, ${unread} unread${more}`
}

function isUnread(row: Row): boolean {
  return row.read_at === null || row.read_at === undefined
}

/** One message, as an IM client shows one: who and when on the opening line, the body
 *  under it, the id last. Three lines rather than one because the id is the argument to
 *  `msg show` and has to survive a copy — a truncated one is a broken command. */
function renderMessage(row: Row): string[] {
  const direction = typeof row.direction === 'string' ? row.direction : 'unknown'
  const counterpart = direction === 'outgoing' ? row.recipient_did : row.sender_did
  const peer = typeof counterpart === 'string' && counterpart !== '' ? counterpart : '(unknown peer)'
  const at = typeof row.created_at === 'string' ? row.created_at : ''
  const out = [`  ${isUnread(row) ? 'unread' : 'read  '}  ${at}  ${direction}  ${peer}`]
  out.push(...contentOf(row).map((line) => `    ${line}`))
  const id = idOf(row)
  if (id !== undefined) out.push(`    id ${id}`)
  return out
}

/** The body as it arrived. `text` and `payload` are the two shapes P3 §6.2 defines and are
 *  printed as they were sent; a P5/P6 payload stays opaque, because decrypting is the
 *  client's job and this service never holds the key (message-service.md §11). */
function contentOf(row: Row): string[] {
  const body = asRow(row.body)
  if (body !== undefined) {
    if (typeof body.text === 'string') return body.text.split('\n')
    if (body.payload !== undefined) return JSON.stringify(body.payload, null, 2).split('\n')
    if (typeof body.payload_b64u === 'string') {
      return [`(encrypted or binary payload, ${body.payload_b64u.length} base64url characters)`]
    }
  }
  if (typeof row.content === 'string') return row.content.split('\n')
  return ['(no content)']
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
