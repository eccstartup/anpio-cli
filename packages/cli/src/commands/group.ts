// The `group` family — P4, `anp.group.base.v2` (`04-群组基础语义.md`).
//
// It is a family of its own rather than more `msg` subcommands because the thing being
// addressed is not a peer: a group has its own `group_did` and its own host, and it is
// reached by resolving the GROUP's DID document — the same five discovery steps P2 §9.1
// L549–560 defines for an agent (§3.1 "一个群，一个 Group DID"). So there is no group
// addressing to invent; `discover()` already does it.
//
// The one thing P4 does not let this file treat as a constant is `meta.target`:
//
//   group.create      kind = "service",  did = ANPMessageService.serviceDid   (§8.1.2 L624–625)
//   everything else   kind = "group",    did = group_did                      (§8.2.2 L648–649, §8.9.2 L833–834)
//
// `meta.target` is inside the Signed Request Object, so that difference is signed, not
// routed: `group.create` asks a service to make a group, and there is no group to name yet.

import { randomUUID } from 'node:crypto'
import { ConnectxError } from '@agentx/core'
import { cliError, type Values } from './auth'
import {
  asRow,
  call,
  discover,
  field,
  isError,
  openChannel,
  payloadOf,
  rejection,
  rowsOf,
  senderFor,
  textOf,
  type Channel,
  type Row,
} from './channel'

/** P4 §5.1 L197. */
const GROUP_PROFILE = 'anp.group.base.v2'

const CREATE = 'group.create'
const GET_INFO = 'group.get_info'
const JOIN = 'group.join'
const LEAVE = 'group.leave'
const SEND = 'group.send'

/**
 * P4 §7.1 L313–328, the structure that section recommends, used verbatim.
 *
 * `admission_mode` is the one field worth arguing about, and the argument is not about
 * this Profile: `admin-add` would make a CLI-created group impossible to populate, because
 * the only other way in is `group.add`, which this command surface does not have (see
 * TODO1 B6). `open-join` is also the value §7.1's own example carries. A deployment that
 * wants the other mode passes `--policy`.
 */
const DEFAULT_POLICY: Record<string, unknown> = {
  message_security_profile: 'transport-protected',
  bootstrap_security_profile: 'transport-protected',
  admission_mode: 'open-join',
  permissions: {
    send: 'member',
    add: 'admin',
    remove: 'admin',
    update_profile: 'admin',
    update_policy: 'owner',
  },
  attachments_allowed: true,
  max_members: '500',
}

/** §7.1 L353–361: the five standard keys, and the three roles. Checked here rather than
 *  left to the service, because a policy the service will refuse is a round trip the
 *  caller can skip — and the refusal would arrive as a generic policy violation. */
const POLICY_PERMISSIONS = ['send', 'add', 'remove', 'update_profile', 'update_policy'] as const
const POLICY_ROLES = ['owner', 'admin', 'member'] as const
const ADMISSION_MODES = ['admin-add', 'open-join'] as const

export async function runGroup(v: Values, sub: string | undefined, args: string[]): Promise<void> {
  switch (sub) {
    case 'create':
      return runCreate(v)
    case 'info':
      return runInfo(v, groupDidOf(args), false)
    case 'members':
      return runInfo(v, groupDidOf(args), true)
    case 'join':
      return runJoin(v, groupDidOf(args))
    case 'leave':
      return runLeave(v, groupDidOf(args))
    case 'send':
      return runSend(v, groupDidOf(args))
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx group\``)
  }
}

function groupDidOf(args: string[]): string {
  const did = args[0]
  if (did === undefined || did === '') {
    throw cliError('missing_flag', 'missing required argument <group_did>')
  }
  return did
}

// ---- addressing --------------------------------------------------------------

/** A call addressed to the group itself. The group's own DID document names the host
 *  that answers for it, exactly as an agent's does: P2 §9.2 L564–568 resolves a
 *  `group_did` the same way §9.1 resolves an `agent_did` — read the document, take its
 *  one `ANPMessageService` — and L546–548 says the three flows are one picture rather
 *  than three philosophies. So there is no group-specific discovery here to write. */
async function groupChannel(v: Values, groupDid: string): Promise<Channel> {
  const sender = await senderFor(v)
  const { target, options } = await discover(groupDid, v)
  return { sender, target, options }
}

/**
 * The target for `group.create`: the SERVICE, not a group (§8.1.2 L625, "`meta.target.did`
 * MUST 等于目标 `ANPMessageService.serviceDid`").
 *
 * A service reachable only from its own domain is not required to publish a `serviceDid`
 * (P2 §8.7 L508 makes it a cross-domain requirement), and this command cannot be made
 * conformant without one — `kind` is `service`, so no other DID would be the right value.
 * Refusing with the reason is the only honest answer; substituting the caller's own DID
 * would sign a claim the service never made.
 */
function serviceTarget(channel: Channel): { kind: 'service'; did: string } {
  const did = channel.target.serviceDid
  if (did === undefined) {
    throw new ConnectxError(
      'message_invalid',
      `${channel.target.identity} publishes an ANPMessageService with no serviceDid, and group.create ` +
        'must name it as the target (P4 §8.1.2 L625; a serviceDid is otherwise only required for ' +
        'cross-domain calls, P2 §8.7 L508)',
    )
  }
  return { kind: 'service', did }
}

// ---- group create ------------------------------------------------------------

async function runCreate(v: Values): Promise<void> {
  const channel = await openChannel(v)
  const body: Record<string, unknown> = { group_policy: policyOf(v) }
  const name = textOf(v.name)
  // §7.4 L411: `display_name` SHOULD be provided when creating a group, so `--name` is
  // where it goes; an empty profile object is not sent, because a group with no name is
  // better described by an absent object than by an empty one.
  if (name !== undefined) body.group_profile = { display_name: name }

  const response = await call(channel, {
    method: CREATE,
    profile: GROUP_PROFILE,
    target: serviceTarget(channel),
    body,
  })
  if (isError(response)) throw rejection(response, CREATE, channel.sender.did)
  reportCreate(response.result, v.json === true)
}

/** `--policy` is JSON, merged over {@link DEFAULT_POLICY}: the caller names what changes
 *  and the rest keeps the recommended structure. A shallow merge, deliberately — the only
 *  nested object is `permissions`, and half a permissions object is not a policy. */
function policyOf(v: Values): Record<string, unknown> {
  const raw = v.policy as string | undefined
  if (raw === undefined) return DEFAULT_POLICY

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw cliError('invalid_argument', `--policy must be JSON (got ${JSON.stringify(raw)})`)
  }
  const override = asRow(parsed)
  if (override === undefined) {
    throw cliError('invalid_argument', '--policy must be a JSON object (P4 §7.1 L309)')
  }
  const policy: Record<string, unknown> = { ...DEFAULT_POLICY, ...override }
  checkPolicy(policy)
  return policy
}

/** §7.1 L334–335, L349, L353, L360: both MUST-be-present fields, and the closed sets they
 *  range over. Everything else in the object is optional and passed through. */
function checkPolicy(policy: Record<string, unknown>): void {
  const mode = policy.admission_mode
  if (!ADMISSION_MODES.includes(mode as (typeof ADMISSION_MODES)[number])) {
    throw cliError(
      'invalid_argument',
      `--policy admission_mode must be one of ${ADMISSION_MODES.join(', ')} (P4 §7.1 L349)`,
    )
  }
  const permissions = asRow(policy.permissions)
  if (permissions === undefined) {
    throw cliError('invalid_argument', '--policy permissions must be an object (P4 §7.1 L335)')
  }
  const keys = Object.keys(permissions)
  // "包含且仅包含" (L353): a sixth key is as wrong as a missing one, and it is the kind of
  // wrong a service may quietly ignore rather than refuse.
  const extra = keys.filter((key) => !POLICY_PERMISSIONS.includes(key as (typeof POLICY_PERMISSIONS)[number]))
  const missing = POLICY_PERMISSIONS.filter((key) => !keys.includes(key))
  if (extra.length > 0 || missing.length > 0) {
    throw cliError(
      'invalid_argument',
      `--policy permissions must contain exactly ${POLICY_PERMISSIONS.join(', ')} (P4 §7.1 L353)` +
        `${missing.length > 0 ? `; missing ${missing.join(', ')}` : ''}${extra.length > 0 ? `; unknown ${extra.join(', ')}` : ''}`,
    )
  }
  for (const [key, value] of Object.entries(permissions)) {
    if (!POLICY_ROLES.includes(value as (typeof POLICY_ROLES)[number])) {
      throw cliError(
        'invalid_argument',
        `--policy permissions.${key} must be one of ${POLICY_ROLES.join(', ')} (P4 §7.1 L360)`,
      )
    }
  }
}

// ---- group info / members ----------------------------------------------------

/** One implementation for both, because `group members` IS `group.get_info` with a
 *  projection (P4 §8.2.2 L654): asking for the roster is not a different operation, and a
 *  second call path would be a second place to get the visibility rules wrong. */
async function runInfo(v: Values, groupDid: string, members: boolean): Promise<void> {
  const channel = await groupChannel(v, groupDid)
  const response = await call(channel, {
    method: GET_INFO,
    profile: GROUP_PROFILE,
    target: { kind: 'group', did: groupDid },
    body: members ? { include_member_list: true } : {},
  })
  if (isError(response)) throw rejection(response, GET_INFO, groupDid)
  if (v.json === true) {
    console.log(JSON.stringify(response.result, null, 2))
    return
  }
  if (members) reportRoster(response.result)
  else reportInfo(response.result)
}

// ---- group join / leave ------------------------------------------------------

async function runJoin(v: Values, groupDid: string): Promise<void> {
  const channel = await groupChannel(v, groupDid)
  // §8.3.2 L686: the member is exactly `meta.sender_did` — the body MUST NOT name or
  // identify the joining member, so there is nothing here to pass.
  const response = await call(channel, {
    method: JOIN,
    profile: GROUP_PROFILE,
    target: { kind: 'group', did: groupDid },
    body: {},
  })
  if (isError(response)) throw rejection(response, JOIN, groupDid)
  if (v.json === true) console.log(JSON.stringify(response.result, null, 2))
  else reportMembership(response.result, 'member')
}

async function runLeave(v: Values, groupDid: string): Promise<void> {
  const channel = await groupChannel(v, groupDid)
  // §8.6.2 L749: `meta.sender_did` MUST be the leaver, which it is by construction —
  // leaving is the one group operation whose subject can only be oneself.
  const response = await call(channel, {
    method: LEAVE,
    profile: GROUP_PROFILE,
    target: { kind: 'group', did: groupDid },
    body: {},
  })
  if (isError(response)) throw rejection(response, LEAVE, groupDid)
  if (v.json === true) console.log(JSON.stringify(response.result, null, 2))
  else reportMembership(response.result, 'leaver')
}

// ---- group send --------------------------------------------------------------

async function runSend(v: Values, groupDid: string): Promise<void> {
  const payload = payloadOf(v)
  const channel = await groupChannel(v, groupDid)

  // P1 §6.2.6 L394: for a message operation the sender SHOULD make `operation_id` the
  // `message_id`. One flag pins both, so a retry keeps the pair unchanged — the same
  // reason `msg send` has `--operation-id`.
  const operationId = (v['operation-id'] as string | undefined) ?? randomUUID()
  const response = await call(channel, {
    method: SEND,
    profile: GROUP_PROFILE,
    target: { kind: 'group', did: groupDid },
    body: payload.body,
    messageId: operationId,
    contentType: payload.contentType,
  })
  if (isError(response)) throw rejection(response, SEND, groupDid)
  reportSent(response.result, v.json === true)
}

// ---- reporting ---------------------------------------------------------------

/** §8.1.3 L636–638: `group_did` at minimum, and the pair a caller has to keep for the
 *  next call — the group it just made, and where that group's state stands. */
function reportCreate(result: Row, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  const groupDid = textOf(result.group_did)
  if (groupDid === undefined) {
    throw new ConnectxError('message_invalid', 'group.create answered without a group_did (P4 §8.1.3 L638)')
  }
  field('group:', groupDid)
  field('state version:', result.group_state_version)
  field('created at:', result.created_at)
  field('creator:', result.creator_did)
  const profile = asRow(result.group_profile)
  if (profile !== undefined) field('name:', textOf(profile.display_name))
}

/** §8.2.3 L662–674. `member_count` is a decimal string (§8.2.3 L674) and is printed as it
 *  arrived rather than parsed — it is the peer's number, and rounding it would be this
 *  CLI inventing a fact. */
function reportInfo(result: Row): void {
  field('group:', result.group_did)
  field('state version:', result.group_state_version)
  const profile = asRow(result.group_profile)
  if (profile !== undefined) {
    field('name:', textOf(profile.display_name))
    field('description:', textOf(profile.description))
    field('discoverability:', textOf(profile.discoverability))
  }
  field('members:', result.member_count)
  const policy = asRow(result.group_policy)
  // §8.2.3 L657: the policy comes back only when the caller asked AND is entitled to see
  // it, so its absence is reported as the service's answer and not as a missing field.
  if (policy !== undefined) {
    field('admission:', textOf(policy.admission_mode))
    const permissions = asRow(policy.permissions)
    if (permissions !== undefined) {
      field('permissions:', Object.entries(permissions).map(([k, val]) => `${k}=${String(val)}`).join(', '))
    }
  } else {
    field('policy:', '(not returned; the service decides what this caller may see)')
  }
}

/** §7.2 L376–380: `agent_did` / `role` / `status` are the minimum; `joined_at` and
 *  `added_by` are optional and printed when present. */
function reportRoster(result: Row): void {
  const rows = rowsOf(result, 'member_list')
  if (rows.length === 0) {
    console.log('no members listed (the service returns a roster only to callers entitled to it)')
    return
  }
  console.log(`${rows.length} member${rows.length === 1 ? '' : 's'}`)
  for (const row of rows) {
    const role = textOf(row.role) ?? 'member'
    const status = textOf(row.status) ?? 'unknown'
    const joined = textOf(row.joined_at)
    console.log(`  ${status.padEnd(8)} ${role.padEnd(6)} ${textOf(row.agent_did) ?? '(unnamed)'}${joined === undefined ? '' : `  joined ${joined}`}`)
  }
}

/** §8.3.3 L690 / §8.6.4 L760–763: the two answers differ in which field names the
 *  subject of the change, and reporting the wrong one would be reporting someone else. */
function reportMembership(result: Row, subject: 'member' | 'leaver'): void {
  field('group:', result.group_did)
  field(`${subject}:`, subject === 'member' ? result.member_did : result.leaver_did)
  field('status:', result.membership_status)
  field('state version:', result.group_state_version)
}

/** §8.9.4 L852–862: `accepted` MUST be `true`, and the event position is what a reader
 *  needs to line the message up with what the group's other members saw. */
function reportSent(result: Row, json: boolean): void {
  if (result.accepted !== true) {
    throw new ConnectxError('message_invalid', 'group.send answered without accepted:true (P4 §8.9.4 L856)')
  }
  if (json) {
    console.log(JSON.stringify(result, null, 2))
    return
  }
  field('group:', result.group_did)
  field('message id:', result.message_id)
  field('event seq:', result.group_event_seq)
  field('state version:', result.group_state_version)
  field('accepted at:', result.accepted_at)
}
