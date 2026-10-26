// C9 —— 群组处理器（`groups.ts`）的语义。
//
// 直接调处理器而不是走 HTTP：这一层要验的是 P4 的规矩——什么推进什么、谁有权限、
// 两个通知的发起者分别是谁、拒绝回哪个码——而信封、认证、幂等各有自己的测试。

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { verifyObjectProofDetailed, type AnpMeta, type AnpRejection } from '@anpio-cli/core'
import { loadConfig } from '../config'
import { openStorage } from '../storage/sqlite'
import type { DeliveryRecord, Storage } from '../storage/types'
import { groupDidDocument } from './groupDidDocument'
import {
  GROUP_ADD,
  GROUP_CREATE,
  GROUP_GET_INFO,
  GROUP_HANDLERS,
  GROUP_INCOMING,
  GROUP_JOIN,
  GROUP_LEAVE,
  GROUP_PROFILE,
  GROUP_REMOVE,
  GROUP_SECURITY_PROFILE,
  GROUP_SEND,
  GROUP_STATE_CHANGED,
  GROUP_UPDATE_POLICY,
  GROUP_UPDATE_PROFILE,
  groupDidKeyId,
  validateAddBody,
  validateCreateBody,
  validateJoinBody,
  validateSendBody,
} from './groups'
import { AnpRefusal } from './refusal'

const SERVICE = 'did:web:anpio.example'
const ALICE = 'did:web:alice.example'
const BOB = 'did:web:bob.example'
const CAROL = 'did:web:carol.example'
const DAVE = 'did:web:dave.example'
const AT = '2026-10-01T00:00:00.000Z'
const DIGEST = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'

let storage: Storage
let pending: DeliveryRecord[]

beforeEach(() => {
  storage = openStorage({ path: ':memory:' })
  pending = []
})

afterEach(() => {
  storage.close()
})

/** §7.1 L347–358：`permissions` 五个键一个不少，`admission_mode` 取两值之一。 */
const OPEN_POLICY = {
  admission_mode: 'open-join',
  permissions: {
    send: 'member',
    add: 'admin',
    remove: 'admin',
    update_profile: 'admin',
    update_policy: 'owner',
  },
}

const CLOSED_POLICY = { ...OPEN_POLICY, admission_mode: 'admin-add' }

interface CallInput {
  actor?: string
  target?: string
  body?: Record<string, unknown>
  operationId?: string
  messageId?: string
  contentType?: string
  securityProfile?: string
  /** 不给就省掉 `sender_did`，也就是匿名。 */
  anonymous?: boolean
}

function invoke(name: string, input: CallInput = {}): Record<string, unknown> {
  const handler = GROUP_HANDLERS[name]
  if (handler === undefined) throw new Error(`the handler table lost ${name}`)
  const meta: AnpMeta = {
    profile: GROUP_PROFILE,
    security_profile: input.securityProfile ?? GROUP_SECURITY_PROFILE,
    ...(input.anonymous === true ? {} : { sender_did: input.actor ?? ALICE }),
    ...(input.target !== undefined
      ? { target: { kind: name === GROUP_CREATE ? 'service' : 'group', did: input.target } }
      : {}),
    operation_id: input.operationId ?? 'op-1',
    ...(input.messageId !== undefined ? { message_id: input.messageId } : {}),
    ...(input.contentType !== undefined ? { content_type: input.contentType } : {}),
  }
  return handler({
    storage,
    serviceDid: SERVICE,
    meta,
    body: input.body ?? {},
    acceptedAt: AT,
    requestDigest: DIGEST,
    onDelivery: (record) => pending.push(record),
  })
}

function refusalOf(fn: () => unknown): AnpRejection {
  try {
    fn()
  } catch (err) {
    if (err instanceof AnpRefusal) return err.rejection
    throw err
  }
  throw new Error('expected a refusal')
}

/** 正文校验只需要 `meta.content_type`（P3 §6.2.4–§6.2.6），其余字段随便填。 */
function sendMeta(contentType: string): AnpMeta {
  return { profile: GROUP_PROFILE, security_profile: GROUP_SECURITY_PROFILE, content_type: contentType }
}

function mintGroup(policy: Record<string, unknown> = OPEN_POLICY, extra: Record<string, unknown> = {}): string {
  const result = invoke(GROUP_CREATE, { actor: ALICE, target: SERVICE, body: { group_policy: policy, ...extra } })
  return result.group_did as string
}

function deliveriesFor(did: string): DeliveryRecord[] {
  return storage.deliveriesSince(did, '', 0, 100, undefined)
}

/** 某个收件人收到的 `group.state_changed` 事件对象。 */
function stateChangesFor(did: string): Array<Record<string, unknown>> {
  return deliveriesFor(did)
    .filter((record) => record.method === GROUP_STATE_CHANGED)
    .map((record) => (JSON.parse(record.paramsJson) as { body: Record<string, unknown> }).body)
}

function counters(groupDid: string): { version: string; seq: string } {
  const group = storage.group(groupDid)
  if (group === undefined) throw new Error('no such group')
  return { version: String(group.groupStateVersion), seq: String(group.groupEventSeq) }
}

describe('group.create (P4 §8.1)', () => {
  it('mints a group under the service DID, with both counters at 1', () => {
    const result = invoke(GROUP_CREATE, { actor: ALICE, target: SERVICE, body: { group_policy: OPEN_POLICY } })
    const groupDid = result.group_did as string

    // §6.1 L227：`group_did` 恰好是"这个服务自己的命名空间 + 一个不透明段"。
    expect(groupDid.startsWith(`${SERVICE}:g:`)).toBe(true)
    expect(result.group_state_version).toBe('1')
    expect(result.group_event_seq).toBe('1')
    expect(result.created_at).toBe(AT)
    expect(result.creator_did).toBe(ALICE)
    expect(result.group_policy).toEqual(OPEN_POLICY)

    // §8.1.2 L632：创建者成为 `owner`。
    expect(storage.groupMember(groupDid, ALICE)).toMatchObject({
      role: 'owner',
      membershipStatus: 'active',
      stateVersion: 1,
    })
    // §7.9：回执的 `payload_digest` 就是这次请求的 SRO 摘要。
    expect(result.group_receipt).toMatchObject({
      receipt_type: 'group-operation-accepted',
      group_did: groupDid,
      group_state_version: '1',
      group_event_seq: '1',
      subject_method: GROUP_CREATE,
      actor_did: ALICE,
      accepted_at: AT,
      payload_digest: DIGEST,
    })
    // 回执**带** `proof`（groups.md §7，B1b-A5 起一律签）：`assertionMethod` 授权的那个
    // keyid，`created` 取 `accepted_at` 而不是现实时钟。验证本身在下面那个 describe 里。
    expect(result.group_receipt).toMatchObject({
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        proofPurpose: 'assertionMethod',
        verificationMethod: groupDidKeyId(groupDid),
        created: AT,
      },
    })
  })

  it('mints the group its own Ed25519 key, in the same transaction as the group row', () => {
    const groupDid = mintGroup()

    const key = storage.groupSigningKey(groupDid)
    expect(key).toBeDefined()
    expect(key?.createdAt).toBe(AT)
    // hex 的 32 字节种子：`parsePrivateKey(hex, 'ed25519')` 认的形状，与 `ANPIOCLI_KEY_FILE`
    // 那种裸 hex 同一套（groups.md §2.1）。
    expect(key?.privateKeyHex).toMatch(/^[0-9a-f]{64}$/)

    // 每个群一把，不是一份部署一把。
    expect(storage.groupSigningKey(mintGroup())?.privateKeyHex).not.toBe(key?.privateKeyHex)
  })

  it('refuses a target that is not this service, with 1014', () => {
    const rejection = refusalOf(() => invoke(GROUP_CREATE, { actor: ALICE, target: BOB, body: { group_policy: OPEN_POLICY } }))
    expect(rejection.code).toBe(1014)
    expect(rejection.anpCode).toBe('anp.invalid_target_binding')
  })

  it('defaults discoverability to private, and keeps the caller\'s value when given one', () => {
    const closed = invoke(GROUP_CREATE, { actor: ALICE, target: SERVICE, body: { group_policy: OPEN_POLICY } })
    expect(closed.group_profile).toEqual({ discoverability: 'private' })

    const listed = invoke(GROUP_CREATE, {
      actor: ALICE,
      target: SERVICE,
      body: { group_policy: OPEN_POLICY, group_profile: { name: 'weeklies', discoverability: 'listed' } },
    })
    expect(listed.group_profile).toEqual({ name: 'weeklies', discoverability: 'listed' })
  })

  it('enrols initial_members as one state change, with no event and no notification', () => {
    const groupDid = mintGroup(OPEN_POLICY, {
      initial_members: [{ member_did: BOB }, { member_did: CAROL, role: 'admin' }],
    })

    expect(counters(groupDid)).toEqual({ version: '1', seq: '1' })
    expect(storage.groupMember(groupDid, BOB)).toMatchObject({ role: 'member', membershipStatus: 'active', addedBy: ALICE })
    expect(storage.groupMember(groupDid, CAROL)).toMatchObject({ role: 'admin', membershipStatus: 'active' })
    // 创建不产生事件，也不发通知（groups.md §7）。
    expect(stateChangesFor(BOB)).toEqual([])
    expect(pending).toEqual([])
  })

  it('checks the policy it is asked to govern with, at 1003', () => {
    const cases: Array<Record<string, unknown>> = [
      { permissions: OPEN_POLICY.permissions }, // 缺 admission_mode
      { ...OPEN_POLICY, admission_mode: 'invite-only' },
      { ...OPEN_POLICY, permissions: { send: 'member' } }, // 缺四个键
      { ...OPEN_POLICY, permissions: { ...OPEN_POLICY.permissions, invite: 'member' } }, // 多一个键
      { ...OPEN_POLICY, permissions: { ...OPEN_POLICY.permissions, send: 'root' } },
      { ...OPEN_POLICY, max_members: 3 }, // §7.1 L371 要的是十进制字符串
    ]
    for (const policy of cases) {
      const rejection = validateCreateBody({ group_policy: policy })
      expect(rejection?.code).toBe(1003)
      expect(rejection?.anpCode).toBe('anp.invalid_params_shape')
    }
  })

  it('refuses a body field the spec section does not name', () => {
    expect(validateCreateBody({ group_policy: OPEN_POLICY, name: 'x' })?.code).toBe(1003)
    // 每个条目都得有 `member_did`（§8.1.2 L629）。
    expect(validateCreateBody({ group_policy: OPEN_POLICY, initial_members: [{}] })?.code).toBe(1003)
  })
})

// B1b-A5 —— 回执的证明。
//
// 证明里的每一样都指向"这次受理"：`payload_digest` 是请求的 SRO 摘要、两个序号是排序位置、
// `verificationMethod` 是群文档里被 `assertionMethod` 授权的那个 keyid。
//
// 验证走 `verifyObjectProofDetailed(receipt, groupDid, groupDocument)`——与
// `groupDidDocument.test.ts` 里验那份文档本身的是**同一条路**（附录 B 的九步）。这里比那边
// 多钉一层：回执的 `verificationMethod` 必须真的被**那份群文档**授权，否则一句"某把钥签了
// 个东西"就冒充了群对这次受理的确认。
describe('the group_receipt proof (B1b-A5)', () => {
  /** 群文档就是本服务发布给别的域的那一份（A2/A3）。这里只拿它当"授权清单"用，所以
   *  `serviceEntry` 取自哪份配置都行。 */
  function documentOf(groupDid: string): Record<string, unknown> {
    const document = groupDidDocument(storage, loadConfig({}), groupDid)
    if (document === undefined) throw new Error(`no document for ${groupDid}`)
    return document
  }

  function verify(receipt: Record<string, unknown>, groupDid: string) {
    return verifyObjectProofDetailed({
      document: receipt,
      issuerDid: groupDid,
      issuerDocument: documentOf(groupDid),
    })
  }

  function receiptOf(result: Record<string, unknown>): Record<string, unknown> {
    const receipt = result.group_receipt
    if (typeof receipt !== 'object' || receipt === null) throw new Error('no group_receipt')
    return receipt as Record<string, unknown>
  }

  it('signs the receipt of every mutating method, against the published document', () => {
    const groupDid = mintGroup(OPEN_POLICY, { initial_members: [{ member_did: BOB }] })
    const receipts = [
      receiptOf(invoke(GROUP_UPDATE_PROFILE, {
        actor: ALICE,
        target: groupDid,
        body: { group_profile_patch: { name: 'weeklies' } },
        operationId: 'op-2',
      })),
      // 消息那条是另一个 receipt_type（`group-message-accepted`），也是另一个构造点。
      receiptOf(invoke(GROUP_SEND, {
        actor: BOB,
        target: groupDid,
        body: { text: 'hello' },
        operationId: 'op-3',
        messageId: 'm-1',
        contentType: 'text/plain',
      })),
    ]

    for (const receipt of receipts) {
      const verdict = verify(receipt, groupDid)
      expect(verdict.ok).toBe(true)
      if (verdict.ok) expect(verdict.verificationMethod).toBe(groupDidKeyId(groupDid))
    }
  })

  it('fails verification as soon as any field of the receipt is edited', () => {
    // 摘要签的就是整份回执，所以改一个序号就够了——这正是"回执不可伪造"的全部内容。
    const groupDid = mintGroup()
    const receipt = receiptOf(invoke(GROUP_UPDATE_PROFILE, {
      actor: ALICE,
      target: groupDid,
      body: { group_profile_patch: { name: 'weeklies' } },
      operationId: 'op-2',
    }))

    const tampered = { ...receipt, group_event_seq: '99' }
    expect(verify(tampered, groupDid).ok).toBe(false)
    // 证明本身也不能搬——换个群文档就对不上了（keyid 与钥都不是那一份里的）。
    expect(verify(receipt, mintGroup()).ok).toBe(false)
  })

  it('leaves a group that has no signing key unsigned, because it cannot be cross-domain', () => {
    // v11 之前建的群没有钥（A1 决定不补铸），因此也没有可发布的群文档（A3 对它们答 404），
    // 于是 §7.9 那条"跨域回执 MUST 有 proof"对它无从谈起。这是**创建时**就定下的属性，
    // 不随请求变，所以不会出现"同一种回执有时签有时不签"。
    const legacy = `${SERVICE}:g:legacy`
    storage.insertGroup({
      groupDid: legacy,
      hostServiceDid: SERVICE,
      groupStateVersion: 1,
      groupEventSeq: 1,
      groupProfileJson: JSON.stringify({ discoverability: 'private' }),
      groupPolicyJson: JSON.stringify(OPEN_POLICY),
      createdAt: AT,
      creatorDid: ALICE,
    })
    storage.upsertGroupMember({
      groupDid: legacy,
      memberDid: ALICE,
      role: 'owner',
      membershipStatus: 'active',
      stateVersion: 1,
      joinedAt: AT,
    })

    const result = invoke(GROUP_UPDATE_PROFILE, {
      actor: ALICE,
      target: legacy,
      body: { group_profile_patch: { name: 'weeklies' } },
      operationId: 'op-2',
    })
    expect(receiptOf(result)).not.toHaveProperty('proof')
    // 而它确实没有文档可发布：A3 的路由此刻答 404。
    expect(groupDidDocument(storage, loadConfig({}), legacy)).toBeUndefined()
  })
})

describe('group.get_info (P4 §8.2)', () => {
  it('gives an active member the count, and the policy and roster on request', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: CAROL }, operationId: 'op-2' })

    const result = invoke(GROUP_GET_INFO, {
      actor: ALICE,
      target: groupDid,
      body: { include_policy: true, include_member_list: true },
    })
    expect(result.group_did).toBe(groupDid)
    // 创建占掉 1/1，CAROL 入群是第二次状态变更（初成员属于创建那一次）。
    expect(result.group_state_version).toBe('2')
    expect(result.group_profile).toEqual({ discoverability: 'private' })
    // §8.2.3 L674：十进制字符串，数的是 `active` DID。
    expect(result.member_count).toBe('3')
    expect(result.group_policy).toEqual(CLOSED_POLICY)
    // §7.2 的成员对象用 `agent_did` / `status`，不是响应里那几处的 `member_did`。
    expect(result.member_list).toEqual([
      { agent_did: ALICE, role: 'owner', status: 'active', joined_at: AT },
      { agent_did: BOB, role: 'member', status: 'active', joined_at: AT, added_by: ALICE },
      { agent_did: CAROL, role: 'member', status: 'active', joined_at: AT, added_by: ALICE },
    ])
  })

  it('drops members who left from the roster, and from the count', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    invoke(GROUP_LEAVE, { actor: BOB, target: groupDid, body: {} })

    const result = invoke(GROUP_GET_INFO, {
      actor: ALICE,
      target: groupDid,
      body: { include_member_list: true },
    })
    expect(result.member_count).toBe('1')
    expect(result.member_list).toEqual([{ agent_did: ALICE, role: 'owner', status: 'active', joined_at: AT }])
  })

  it('shows a stranger only the profile snapshot of a public group', () => {
    const groupDid = mintGroup(OPEN_POLICY, { group_profile: { discoverability: 'public', name: 'town-hall' } })

    const result = invoke(GROUP_GET_INFO, { anonymous: true, target: groupDid, body: {} })
    expect(result).toEqual({
      group_did: groupDid,
      group_state_version: '1',
      group_profile: { discoverability: 'public', name: 'town-hall' },
    })
  })

  it('refuses a projection a stranger may not see, with 3003', () => {
    const groupDid = mintGroup(OPEN_POLICY, { group_profile: { discoverability: 'public' } })

    const rejection = refusalOf(() => invoke(GROUP_GET_INFO, { anonymous: true, target: groupDid, body: { include_member_list: true } }))
    expect(rejection.code).toBe(3003)
    expect(rejection.anpCode).toBe('group.policy_violation')
  })

  it('refuses a stranger outright when the group is private, with 3000', () => {
    const groupDid = mintGroup(CLOSED_POLICY)

    const rejection = refusalOf(() => invoke(GROUP_GET_INFO, { anonymous: true, target: groupDid, body: {} }))
    expect(rejection.code).toBe(3000)
    expect(rejection.anpCode).toBe('group.not_member')
  })

  it('answers "not a member" for a group this service does not host', () => {
    const rejection = refusalOf(() => invoke(GROUP_GET_INFO, { actor: ALICE, target: `${SERVICE}:g:nope`, body: {} }))
    expect(rejection.code).toBe(3000)
  })
})

describe('group.join (P4 §8.3)', () => {
  it('activates the caller under open-join, and tells the others', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    const result = invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {} })

    expect(result).toMatchObject({
      group_did: groupDid,
      member_did: BOB,
      membership_status: 'active',
      group_state_version: '2',
    })
    expect(counters(groupDid)).toEqual({ version: '2', seq: '2' })
    expect(storage.groupMember(groupDid, BOB)).toMatchObject({ role: 'member', membershipStatus: 'active' })

    const [event] = stateChangesFor(ALICE)
    expect(event).toMatchObject({
      event_type: 'member-activated',
      group_did: groupDid,
      group_state_version: '2',
      group_event_seq: '2',
      subject_method: GROUP_JOIN,
      subject_did: BOB,
      membership_status: 'active',
      actor_did: BOB,
      changed_at: AT,
    })
    // 处理器不回执自己的通知：发起人自己不收那条 `group.state_changed`。
    expect(pending.map((record) => record.ownerDid)).toEqual([ALICE])
    // §8.11 L919/L921：通知的安全模式写死，发起者是**群自己**。
    const params = JSON.parse(deliveriesFor(ALICE)[0]?.paramsJson ?? '{}') as { meta: AnpMeta }
    expect(params.meta.security_profile).toBe(GROUP_SECURITY_PROFILE)
    expect(params.meta.sender_did).toBe(groupDid)
  })

  it('refuses when the group is not open-join, with 3003 (§8.3.2 L686)', () => {
    const groupDid = mintGroup(CLOSED_POLICY)
    const rejection = refusalOf(() => invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {} }))
    expect(rejection.code).toBe(3003)
    expect(rejection.anpCode).toBe('group.policy_violation')
  })

  it('answers an existing member with 3001', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {} })
    const rejection = refusalOf(() => invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {}, operationId: 'op-2' }))
    expect(rejection.code).toBe(3001)
    expect(rejection.anpCode).toBe('group.already_member')
  })

  it('lets a member who left come back, keeping the role they held', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB, role: 'admin' }] })
    invoke(GROUP_LEAVE, { actor: BOB, target: groupDid, body: {} })

    const rejection = refusalOf(() => invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {}, operationId: 'op-2' }))
    // 非 open-join 的群，离群之后不能自己回来。
    expect(rejection.code).toBe(3003)

    storage.updateGroupPolicy(groupDid, JSON.stringify(OPEN_POLICY))
    invoke(GROUP_JOIN, { actor: BOB, target: groupDid, body: {}, operationId: 'op-3' })
    expect(storage.groupMember(groupDid, BOB)).toMatchObject({ role: 'admin', membershipStatus: 'active' })
  })

  it('refuses a body that names a member, with 1003 (§8.3.2 L681)', () => {
    expect(validateJoinBody({ member_did: BOB })?.code).toBe(1003)
    // `reason_text` 是那一段唯一认的正文字段。
    expect(validateJoinBody({ reason_text: 'hello' })).toBeUndefined()
  })
})

describe('group.add / group.remove (P4 §8.4–§8.5)', () => {
  it('adds under permissions.add, defaulting the role to member', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    const result = invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: BOB } })

    expect(result).toMatchObject({ member_did: BOB, membership_status: 'active', group_state_version: '2' })
    expect(storage.groupMember(groupDid, BOB)).toMatchObject({ role: 'member', membershipStatus: 'active', addedBy: ALICE })
  })

  it('refuses when the caller lacks permissions.add, with 3003', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    // CLOSED_POLICY 的 add 要求 admin，而 BOB 是 member。
    const rejection = refusalOf(() => invoke(GROUP_ADD, { actor: BOB, target: groupDid, body: { member_did: CAROL } }))
    expect(rejection.code).toBe(3003)
  })

  it('answers a target who is already active with 3001', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    const rejection = refusalOf(() => invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: BOB } }))
    expect(rejection.code).toBe(3001)
  })

  it('refuses to grow past max_members, with 3003', () => {
    const groupDid = mintGroup({ ...OPEN_POLICY, max_members: '1' })
    const rejection = refusalOf(() => invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: BOB } }))
    expect(rejection.code).toBe(3003)
  })

  it('re-activates someone who was removed', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    invoke(GROUP_REMOVE, { actor: ALICE, target: groupDid, body: { member_did: BOB }, operationId: 'op-2' })
    expect(storage.groupMember(groupDid, BOB)?.membershipStatus).toBe('removed')

    invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: BOB }, operationId: 'op-3' })
    expect(storage.groupMember(groupDid, BOB)?.membershipStatus).toBe('active')
  })

  it('answers an inactive target of group.remove with 3005', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    invoke(GROUP_LEAVE, { actor: BOB, target: groupDid, body: {}, operationId: 'op-2' })

    const rejection = refusalOf(() => invoke(GROUP_REMOVE, { actor: ALICE, target: groupDid, body: { member_did: BOB }, operationId: 'op-3' }))
    expect(rejection.code).toBe(3005)
    expect(rejection.anpCode).toBe('group.member_conflict')
  })

  it('sends a removed member the final notice addressed to themselves (§8.11 L926–928)', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }, { member_did: CAROL }] })
    invoke(GROUP_REMOVE, { actor: ALICE, target: groupDid, body: { member_did: BOB } })

    // BOB 已经不是 active，所以这条不会被"当前成员"那一步生成——它只来自那条例外。
    const [final] = stateChangesFor(BOB)
    expect(final).toMatchObject({ event_type: 'member-removed', subject_did: BOB, membership_status: 'removed' })
    const params = JSON.parse(deliveriesFor(BOB)[0]?.paramsJson ?? '{}') as { meta: AnpMeta }
    expect(params.meta.sender_did).toBe(groupDid)
    expect(params.meta.target).toEqual({ kind: 'agent', did: BOB })

    // 其余成员照常收到一份。
    expect(stateChangesFor(CAROL)).toHaveLength(1)
    expect(stateChangesFor(CAROL)[0]).toMatchObject({ event_type: 'member-removed', subject_did: BOB })
    // 发起人自己不收。
    expect(stateChangesFor(ALICE)).toEqual([])
  })
})

describe('group.leave (P4 §8.6)', () => {
  it('marks the caller left, and still reaches them with the final notice', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    const result = invoke(GROUP_LEAVE, { actor: BOB, target: groupDid, body: {} })

    expect(result).toMatchObject({ leaver_did: BOB, group_state_version: '2' })
    expect(storage.groupMember(groupDid, BOB)?.membershipStatus).toBe('left')
    expect(stateChangesFor(BOB)[0]).toMatchObject({ event_type: 'member-left', subject_did: BOB })
    expect(stateChangesFor(ALICE)[0]).toMatchObject({ event_type: 'member-left', subject_did: BOB })
  })

  it('answers a non-member with 3000', () => {
    const groupDid = mintGroup(CLOSED_POLICY)
    const rejection = refusalOf(() => invoke(GROUP_LEAVE, { actor: DAVE, target: groupDid, body: {} }))
    expect(rejection.code).toBe(3000)
  })
})

describe('group.update_profile (P4 §8.7)', () => {
  it('applies an RFC 7386 merge to the stored profile', () => {
    const groupDid = mintGroup(OPEN_POLICY, {
      group_profile: { discoverability: 'listed', name: 'weeklies', details: { topic: 'anp', city: 'sh' } },
    })
    const result = invoke(GROUP_UPDATE_PROFILE, {
      actor: ALICE,
      target: groupDid,
      body: { group_profile_patch: { details: { city: 'bj' }, name: null, note: 'hi' } },
    })

    // 对象递归合并、`null` 删键、其余替换。
    expect(result.group_profile).toEqual({
      discoverability: 'listed',
      details: { topic: 'anp', city: 'bj' },
      note: 'hi',
    })
    expect(storage.group(groupDid)?.groupProfileJson).toBe(JSON.stringify(result.group_profile))
    expect(counters(groupDid)).toEqual({ version: '2', seq: '2' })
    expect(stateChangesFor(ALICE)).toEqual([])
  })

  it('re-materialises the private default when a patch deletes discoverability', () => {
    const groupDid = mintGroup(OPEN_POLICY, { group_profile: { discoverability: 'public' } })
    const result = invoke(GROUP_UPDATE_PROFILE, {
      actor: ALICE,
      target: groupDid,
      body: { group_profile_patch: { discoverability: null } },
    })
    expect(result.group_profile).toEqual({ discoverability: 'private' })
  })

  it('refuses a caller without permissions.update_profile, with 3003', () => {
    const groupDid = mintGroup(CLOSED_POLICY, { initial_members: [{ member_did: BOB }] })
    const rejection = refusalOf(() =>
      invoke(GROUP_UPDATE_PROFILE, { actor: BOB, target: groupDid, body: { group_profile_patch: { name: 'x' } } }),
    )
    expect(rejection.code).toBe(3003)
    expect(storage.group(groupDid)?.groupProfileJson).toBe(JSON.stringify({ discoverability: 'private' }))
  })

  it('refuses a patch that is not a JSON object, with 1003', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    const rejection = refusalOf(() =>
      invoke(GROUP_UPDATE_PROFILE, { actor: ALICE, target: groupDid, body: { group_profile_patch: 'nope' } }),
    )
    expect(rejection.code).toBe(1003)
  })
})

describe('group.update_policy (P4 §8.8)', () => {
  it('validates the merged object, not the patch', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    const before = storage.group(groupDid)?.groupPolicyJson

    // 一个完全合法的 patch，合并之后多出一个权限键。
    const rejection = refusalOf(() =>
      invoke(GROUP_UPDATE_POLICY, {
        actor: ALICE,
        target: groupDid,
        body: { group_policy_patch: { permissions: { invite: 'member' } } },
      }),
    )
    expect(rejection.code).toBe(1003)
    expect(rejection.anpCode).toBe('anp.invalid_params_shape')
    // 失败即不落库：策略与两个计数器都没动。
    expect(storage.group(groupDid)?.groupPolicyJson).toBe(before)
    expect(counters(groupDid)).toEqual({ version: '1', seq: '1' })
  })

  it('applies a patch that keeps the structure intact', () => {
    const groupDid = mintGroup(OPEN_POLICY)
    const result = invoke(GROUP_UPDATE_POLICY, {
      actor: ALICE,
      target: groupDid,
      body: { group_policy_patch: { admission_mode: 'admin-add', permissions: { send: 'admin' } } },
    })

    expect(result.group_policy).toEqual({
      admission_mode: 'admin-add',
      permissions: { ...OPEN_POLICY.permissions, send: 'admin' },
    })
    expect(counters(groupDid)).toEqual({ version: '2', seq: '2' })
  })

  it('refuses a caller without permissions.update_policy, with 3003', () => {
    const groupDid = mintGroup(OPEN_POLICY, { initial_members: [{ member_did: BOB, role: 'admin' }] })
    const rejection = refusalOf(() =>
      invoke(GROUP_UPDATE_POLICY, { actor: BOB, target: groupDid, body: { group_policy_patch: { admission_mode: 'admin-add' } } }),
    )
    expect(rejection.code).toBe(3003)
  })
})

describe('group.send (P4 §8.9–§8.10)', () => {
  const SEND_BODY = { text: 'hello group' }

  function send(groupDid: string, input: Partial<CallInput> = {}): Record<string, unknown> {
    return invoke(GROUP_SEND, {
      actor: ALICE,
      target: groupDid,
      body: SEND_BODY,
      messageId: 'm-1',
      contentType: 'text/plain',
      ...input,
    })
  }

  it('advances the sequence, not the version, and delivers to the other active members', () => {
    const groupDid = mintGroup(OPEN_POLICY, { initial_members: [{ member_did: BOB }, { member_did: CAROL }] })
    const result = send(groupDid)

    expect(result).toMatchObject({
      accepted: true,
      group_did: groupDid,
      message_id: 'm-1',
      group_event_seq: '2',
      group_state_version: '1',
      accepted_at: AT,
    })
    expect(counters(groupDid)).toEqual({ version: '1', seq: '2' })

    // 发送者自己那一半由 `messages` 行补出来，所以只给其余成员写投递。
    expect(storage.message(ALICE, groupDid, 'm-1')).toMatchObject({ groupEventSeq: 2, groupStateVersion: 1 })
    const recipients = pending.map((record) => record.ownerDid).sort()
    expect(recipients).toEqual([BOB, CAROL])
    expect(pending.every((record) => record.method === GROUP_INCOMING)).toBe(true)

    const params = JSON.parse(deliveriesFor(BOB)[0]?.paramsJson ?? '{}') as {
      meta: AnpMeta
      body: Record<string, unknown>
    }
    // §8.10 L880：发起者是**原始发送方**，与 `group.state_changed` 恰好相反。
    expect(params.meta.sender_did).toBe(ALICE)
    expect(params.meta.message_id).toBe('m-1')
    expect(params.meta.target).toEqual({ kind: 'agent', did: BOB })
    expect(params.body).toMatchObject({
      group_did: groupDid,
      group_event_seq: '2',
      group_state_version: '1',
      text: 'hello group',
    })
    const receipt = params.body.group_receipt as Record<string, unknown>
    expect(receipt).toMatchObject({ receipt_type: 'group-message-accepted', message_id: 'm-1', actor_did: ALICE })
  })

  it('answers a message-level duplicate with the snapshot it was accepted at', () => {
    const groupDid = mintGroup(OPEN_POLICY, { initial_members: [{ member_did: BOB }] })
    const first = send(groupDid)
    // 群状态往前走一步，序列也再走一步——重复识别要回的是**首次受理时**的那些值。
    invoke(GROUP_ADD, { actor: ALICE, target: groupDid, body: { member_did: CAROL }, operationId: 'op-2' })
    send(groupDid, { messageId: 'm-2', operationId: 'op-3' })

    const replay = send(groupDid, { operationId: 'op-4' })
    expect(replay.group_event_seq).toBe(first.group_event_seq)
    expect(replay.group_state_version).toBe(first.group_state_version)
    expect(replay.operation_id).toBe('op-4')
    expect(replay).not.toHaveProperty('group_receipt')

    // 没有再存第二行，也没有再排第二条投递。
    const incomingForBob = pending.filter((record) => record.ownerDid === BOB && record.method === GROUP_INCOMING)
    expect(incomingForBob).toHaveLength(2)
    expect(storage.group(groupDid)?.groupEventSeq).toBe(4)
  })

  it('refuses a non-member with 3000 and a permission shortfall with 3003', () => {
    const groupDid = mintGroup({ ...OPEN_POLICY, permissions: { ...OPEN_POLICY.permissions, send: 'admin' } }, {
      initial_members: [{ member_did: BOB }],
    })

    expect(refusalOf(() => send(groupDid, { actor: DAVE })).code).toBe(3000)
    expect(refusalOf(() => send(groupDid, { actor: BOB })).code).toBe(3003)
  })

  it('refuses a payload that does not match the content type, with 1003', () => {
    // text/plain 要求 `text`，给了 `payload`。
    expect(validateSendBody({ payload: { a: 1 } }, sendMeta('text/plain'))?.code).toBe(1003)
    // 自定义内容类型不施加约束——它的字段只有发送方认得。
    expect(validateSendBody({ payload: { a: 1 } }, sendMeta('application/x-custom'))).toBeUndefined()
    // 三个负载字段恰好一个。
    expect(validateSendBody({}, sendMeta('text/plain'))?.code).toBe(1003)
  })

  it('rejects an unknown body field only for the governance methods, not for send', () => {
    expect(validateSendBody({ text: 'hi', custom_field: 1 }, sendMeta('text/plain'))).toBeUndefined()
    expect(validateAddBody({ member_did: BOB, note: 'x' })?.code).toBe(1003)
  })
})
