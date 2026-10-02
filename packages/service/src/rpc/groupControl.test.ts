// C13 —— P6 §9 的四条控制面方法，走**整条**受理路径跑（方法表、外层证明、正文校验、设备
// 资格、幂等、处理器、存储）。
//
// 为什么不在这一层直调处理器：这一块有一半的规矩是"哪一步先判"。`add` 的设备定址要读
// `body.member_did`，而它在正文校验**之后**才被调用；§13.6 L1693 的一次性 nonce 检查落在
// `perform` 之内、幂等台账之后；§13.3 L1627 又要求成员/设备/leaf 三条按次序判在正文之前。
// 直调处理器会把这三次次序一起测掉，而它们正是这几条方法最容易写错的地方。
//
// 方法表本身（Profile、安全模式、目标建模、设备点数、幂等作用域）另有一段纯单测——那些是
// "表里写了什么"，与跑得通跑不通无关。
//
// `did_wba_binding` 的 proof 与 `origin_proof` 都是**真的签**的：前者是 §6.4 L445–448 第 4–6
// 项要验的那一份，后者是 P6 这四条与两条 Key 方法最大的差别（§9.2.3 等逐字 "MUST exist"）。
// 编一份假的会让验签这一步悄悄失效，而被测的恰好就是"这份证明算不算数"。

import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  DidDeviceResolver,
  DidKeyResolver,
  ed25519OriginProofSigner,
  type AnpMeta,
  type AnpRequest,
  type AnpSigningIdentity,
  type DeviceResolver,
  type KeyResolver,
  type LocateOptions,
} from '@agentx/core'
import { signDidDocumentProofSync } from '@agentx/core/advanced'
import { loadConfig } from '../config'
import { createHttpNonceStore } from '../federation/nonces'
import { openObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import type { Storage, StoredDeviceEnvelope } from '../storage/types'
import { createDispatch } from './dispatch'
import type { RpcHandler, RpcRequest } from '../http/server'
import {
  GROUP_CIPHER_CONTENT_TYPE,
  GROUP_E2EE_ADD,
  GROUP_E2EE_CREATE,
  GROUP_E2EE_REMOVE,
  GROUP_E2EE_SECURITY_PROFILE,
  GROUP_E2EE_SEND,
} from './groupControl'
import { GROUP_E2EE_PROFILE } from './groupE2ee'
import { GROUP_E2EE_NOTICE } from './groupEnvelopes'
import {
  applyMemberDidUpdate,
  GROUP_ADD,
  GROUP_CREATE,
  GROUP_HANDLERS,
  GROUP_PROFILE,
  GROUP_SECURITY_PROFILE,
} from './groups'
import { lookupMethod } from './methods'

const config = loadConfig({})
const SERVICE_DID = config.serviceDid

/** 三个身份：owner 建群、member 被加进来、outsider 谁也不是。第三个人存在的理由是"KeyPackage
 *  自己合规但不属于这次点名的那台设备"那一条。 */
const owner = createAnpIdentity('owner.example')
const member = createAnpIdentity('member.example')
const outsider = createAnpIdentity('outsider.example')

const OWNER_DEVICE = 'dev-owner-7N3KQ2'
const MEMBER_DEVICE = 'dev-member-4B8XT'
const OUTSIDER_DEVICE = 'dev-outsider-2P9WZ'

/** 一个时刻，让 `accepted_at` 是字面量，证明的时间窗也能钉在它两侧。 */
const NOW = new Date('2026-10-01T12:00:00Z')
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000)

/** 两个合法的无填充 base64url：`crypto_group_id` 的"这一个群"与"另一个群"。 */
const CRYPTO_GROUP_ID = 'Z3JvdXAtb25l'
const OTHER_CRYPTO_GROUP_ID = 'Z3JvdXAtdHdv'

/** P4 §7.1 L347–358：五个权限键一个不少。`send: 'member'` 让被加进来的那台设备发得出去。 */
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

const DIGEST = 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'

function signerFor(did: string): AnpSigningIdentity {
  for (const identity of [owner, member, outsider]) if (identity.did === did) return identity
  throw new Error(`no test identity for ${did}`)
}

// ---- 夹具：设备文档、清单解析、盖章 ------------------------------------------
// 与 `groupE2ee.test.ts` 同一套：P6 的资格要求（`GROUP_E2EE_DEVICE`）与那里完全相同，所以
// 设备文档必须宣告那四项 Profile，签名钥必须落 `assertionMethod`、e2ee 钥落 `keyAgreement`。

/** 一份够 §4.2 判定的设备文档：身份自己的 `#key-1` 留在 `assertionMethod` 上（`did_wba_binding`
 *  的证明用它签），另加一颗本设备的 X25519 落在 `keyAgreement` 上，清单把两者绑在这台设备上。 */
function deviceDocument(identity: AnpSigningIdentity, deviceId: string): Record<string, unknown> {
  const e2eeKeyId = `${identity.did}#${deviceId}-e2ee`
  return {
    ...identity.didDocument,
    verificationMethod: [
      ...(identity.didDocument.verificationMethod as unknown[]),
      { id: e2eeKeyId, type: 'Multikey', controller: identity.did, publicKeyMultibase: 'z6LSexample' },
    ],
    keyAgreement: [e2eeKeyId],
    deviceManifest: {
      type: 'ANPDeviceManifest',
      devices: [
        {
          device_id: deviceId,
          signing_key_id: identity.keyid,
          e2ee_key_id: e2eeKeyId,
          profiles: [
            'anp.core.binding.v1',
            'anp.identity.discovery.v1',
            'anp.group.base.v2',
            GROUP_E2EE_PROFILE,
          ],
        },
      ],
    },
  }
}

/** 设备资格读的是 `deviceResolver`（清单从调用方的表里来），`origin_proof` 验签读的是
 *  `resolver`（文档同上）。两张表分属两条路，这里各给一份。 */
function deviceResolverFor(documents: Record<string, unknown>): DeviceResolver {
  const base = new DidDeviceResolver()
  return {
    resolveDevice(identity: string, deviceId: string, opts: LocateOptions = {}) {
      return base.resolveDevice(identity, deviceId, { ...opts, didDocument: documents[identity] })
    },
  }
}

function inlineResolver(documents: Record<string, unknown>): KeyResolver {
  const base = new DidKeyResolver()
  return {
    resolve(identity: string, keyid: string, opts: LocateOptions = {}) {
      const bare = keyid.includes('#') ? keyid.slice(0, keyid.indexOf('#')) : keyid
      return base.resolve(identity, keyid, { ...opts, didDocument: documents[bare] })
    },
  }
}

function defaultDeviceDocuments(): Record<string, unknown> {
  return {
    [owner.did]: deviceDocument(owner, OWNER_DEVICE),
    [member.did]: deviceDocument(member, MEMBER_DEVICE),
    [outsider.did]: deviceDocument(outsider, OUTSIDER_DEVICE),
  }
}

function keyDocuments(): Record<string, unknown> {
  return {
    [owner.did]: owner.didDocument,
    [member.did]: member.didDocument,
    [outsider.did]: outsider.didDocument,
  }
}

/** §6.4 L445–448 第 4–6 项要验的那份证明，由**这台设备的那把钥**真签。 */
function bindingFor(signer: AnpSigningIdentity, deviceId: string): Record<string, unknown> {
  const document = {
    agent_did: signer.did,
    device_id: deviceId,
    verification_method: signer.keyid,
    leaf_signature_key_b64u: 'AAAA',
    issued_at: '2026-09-30T00:00:00Z',
    expires_at: '2027-01-01T00:00:00Z',
  }
  return { ...document, proof: signDidDocumentProofSync(document, signer.keyid, signer.priv) }
}

/** §7.3 那份 `group_key_package`。 */
function keyPackageFor(
  signer: AnpSigningIdentity,
  deviceId: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    key_package_id: `kp-${deviceId}`,
    owner_did: signer.did,
    owner_device_id: deviceId,
    suite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
    mls_key_package_b64u: 'AAAA',
    ...overrides,
    did_wba_binding: bindingFor(signer, deviceId),
  }
}

// ---- P4 前置状态 -------------------------------------------------------------
// P6 的四条控制动作都以"P4 业务群已经建好"为前提（§9.2.1、§9.3.1）。P4 那一层自己有测试，
// 这里直调它的处理器把状态摆出来，不重测它。

function p4Meta(target: AnpMeta['target'], operationId: string): AnpMeta {
  return {
    profile: GROUP_PROFILE,
    security_profile: GROUP_SECURITY_PROFILE,
    sender_did: owner.did,
    target,
    operation_id: operationId,
  }
}

function mintP4Group(storage: Storage, policy: Record<string, unknown> = OPEN_POLICY): string {
  const handler = GROUP_HANDLERS[GROUP_CREATE]
  if (handler === undefined) throw new Error('the handler table lost group.create')
  const result = handler({
    storage,
    serviceDid: SERVICE_DID,
    meta: p4Meta({ kind: 'service', did: SERVICE_DID }, 'op-p4-create'),
    body: { group_policy: policy },
    acceptedAt: NOW.toISOString(),
    requestDigest: DIGEST,
    onDelivery: () => undefined,
  })
  return result.group_did as string
}

/** 把一个 DID 加进 P4 群（owner 有 `add` 权限）。这是 `group.e2ee.add` 的前置：§9.3.3 要求
 *  `member_did` 是当前的 P4 `active` 成员。 */
function addP4Member(storage: Storage, groupDid: string, did: string): void {
  const handler = GROUP_HANDLERS[GROUP_ADD]
  if (handler === undefined) throw new Error('the handler table lost group.add')
  handler({
    storage,
    serviceDid: SERVICE_DID,
    meta: p4Meta({ kind: 'group', did: groupDid }, `op-p4-add-${did}`),
    body: { member_did: did },
    acceptedAt: NOW.toISOString(),
    requestDigest: DIGEST,
    onDelivery: () => undefined,
  })
}

// ---- 受理路径上的夹具 --------------------------------------------------------

interface Outcome {
  status: number
  json:
    | {
        result?: Record<string, unknown>
        error?: { code: number; message: string; data?: { anp_code?: string; details?: Record<string, unknown> } }
      }
    | undefined
}

interface Harness {
  storage: Storage
  call(request: AnpRequest): Promise<Outcome>
}

function harness(overrides: { storage?: Storage; devices?: Record<string, unknown> } = {}): Harness {
  const storage = overrides.storage ?? openStorage({ path: ':memory:' })
  const handle: RpcHandler = createDispatch({
    config,
    storage,
    objects: openObjectStore({ directory: mkdtempSync(join(tmpdir(), 'agentx-groupcontrol-')), maxBytes: 1024 }),
    resolver: inlineResolver(keyDocuments()),
    deviceResolver: deviceResolverFor(overrides.devices ?? defaultDeviceDocuments()),
    nonceStore: createHttpNonceStore(storage),
    log: () => undefined,
    now: () => NOW,
  })
  return {
    storage,
    async call(request: AnpRequest): Promise<Outcome> {
      // 不带 `method`：走**同域明文**那条路，外层 HTTP 身份整段跳过。这几条方法要的业务层
      // 证明在 `params.auth` 里，由 `authenticate()` 判——与 P5/P6 的两组 Key 方法不同，
      // 那两组压根不需要这一层。
      const rpc: RpcRequest = {
        body: JSON.stringify(request),
        headers: {},
        url: new URL(`${config.publicUrl}/anp-im/rpc`),
      }
      const response = await handle(rpc)
      return { status: response.status, json: response.body === '' ? undefined : JSON.parse(response.body) }
    },
  }
}

/** 真的签一份 `origin_proof`。`created` / `expires` 围着 `NOW` 钉，于是时间窗这一半是确定的
 *  字面量，被拒时拒因只可能来自 nonce 那一半。 */
async function signed(
  method: string,
  meta: AnpMeta,
  body: Record<string, unknown>,
  options: { nonce?: string; signer?: AnpSigningIdentity; id?: string } = {},
): Promise<AnpRequest> {
  const signer = options.signer ?? signerFor(meta.sender_did ?? '')
  const auth = await buildOriginProofAuth({
    method,
    meta,
    body,
    signer: ed25519OriginProofSigner(signer.priv, signer.keyid),
    created: NOW_SECONDS - 60,
    expires: NOW_SECONDS + 3600,
    ...(options.nonce !== undefined ? { nonce: options.nonce } : {}),
  })
  return buildMessageRequest({ id: options.id ?? `req-${method}`, method, meta, body, auth })
}

// ---- 请求的 meta / body ------------------------------------------------------

function createMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: GROUP_E2EE_PROFILE,
    security_profile: GROUP_E2EE_SECURITY_PROFILE,
    sender_did: owner.did,
    sender_device_id: OWNER_DEVICE,
    target: { kind: 'service', did: SERVICE_DID },
    operation_id: 'op-create-1',
    ...overrides,
  }
}

function groupMeta(groupDid: string, overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: GROUP_E2EE_PROFILE,
    security_profile: GROUP_E2EE_SECURITY_PROFILE,
    sender_did: owner.did,
    sender_device_id: OWNER_DEVICE,
    target: { kind: 'group', did: groupDid },
    operation_id: 'op-1',
    ...overrides,
  }
}

function sendMeta(groupDid: string, overrides: Partial<AnpMeta> = {}): AnpMeta {
  return groupMeta(groupDid, {
    operation_id: 'op-send-1',
    message_id: 'msg-1',
    content_type: GROUP_CIPHER_CONTENT_TYPE,
    ...overrides,
  })
}

function stateRef(groupDid: string, version = '1'): Record<string, unknown> {
  return { group_did: groupDid, group_state_version: version }
}

function createBody(groupDid: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    group_did: groupDid,
    group_state_ref: stateRef(groupDid),
    creator_key_package: keyPackageFor(owner, OWNER_DEVICE),
    crypto_group_id_b64u: CRYPTO_GROUP_ID,
    epoch: '0',
    suite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
    ...overrides,
  }
}

function addBody(groupDid: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    member_did: member.did,
    member_device_id: MEMBER_DEVICE,
    group_state_ref: stateRef(groupDid),
    crypto_group_id_b64u: CRYPTO_GROUP_ID,
    epoch: '1',
    commit_b64u: 'AAAA',
    welcome_b64u: 'AAAA',
    ratchet_tree_b64u: 'AAAA',
    group_key_package: keyPackageFor(member, MEMBER_DEVICE),
    ...overrides,
  }
}

function removeBody(groupDid: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    member_did: member.did,
    member_device_id: MEMBER_DEVICE,
    group_state_ref: stateRef(groupDid),
    crypto_group_id_b64u: CRYPTO_GROUP_ID,
    epoch: '2',
    commit_b64u: 'AAAA',
    ...overrides,
  }
}

function sendBody(groupDid: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    group_cipher_object: {
      crypto_group_id_b64u: CRYPTO_GROUP_ID,
      private_message_b64u: 'AAAA',
      epoch: '1',
      group_state_ref: stateRef(groupDid),
    },
    ...overrides,
  }
}

// ---- 组合好的前置状态 --------------------------------------------------------

/** P4 群已在，且已在一个 MLS epoch 上（owner 那一行 leaf）。 */
async function groupWithState(
  overrides: { storage?: Storage; devices?: Record<string, unknown>; create?: Record<string, unknown> } = {},
): Promise<{ h: Harness; groupDid: string; created: Record<string, unknown> }> {
  const h = harness(overrides)
  const groupDid = mintP4Group(h.storage)
  const outcome = await h.call(await signed(GROUP_E2EE_CREATE, createMeta(), createBody(groupDid, overrides.create)))
  const created = outcome.json?.result
  if (created === undefined) throw new Error(`create did not succeed: ${JSON.stringify(outcome.json)}`)
  return { h, groupDid, created }
}

/** 再往前一步：member 的 P4 成员行与它的 MLS leaf 都在。 */
async function groupWithMember(): Promise<{ h: Harness; groupDid: string }> {
  const { h, groupDid } = await groupWithState()
  addP4Member(h.storage, groupDid, member.did)
  await h.call(await signed(GROUP_E2EE_ADD, groupMeta(groupDid, { operation_id: 'op-add-1' }), addBody(groupDid)))
  return { h, groupDid }
}

// ---- 方法表 ------------------------------------------------------------------

describe('the four control methods in the method table', () => {
  const CONTROL = [GROUP_E2EE_CREATE, GROUP_E2EE_ADD, GROUP_E2EE_REMOVE, GROUP_E2EE_SEND]

  it('files create as service-scoped and the other three as group-addressed', () => {
    // §4.4.1 L292–293 刻意把 `create` 定成 service-scoped（那时群还没有密码学状态），
    // §4.4.2 把另外三条定在 `meta.target.did == group_did` 上。
    expect(lookupMethod(GROUP_E2EE_CREATE)?.targetMode).toBe('service-scoped')
    for (const name of [GROUP_E2EE_ADD, GROUP_E2EE_REMOVE, GROUP_E2EE_SEND]) {
      expect(lookupMethod(name)?.targetMode).toBe('group-addressed')
    }
  })

  it('declares the P6 profile under the group-e2ee security mode, and requires an origin proof', () => {
    for (const name of CONTROL) {
      const spec = lookupMethod(name)
      expect(spec?.profiles).toEqual([GROUP_E2EE_PROFILE])
      expect(spec?.securityProfiles).toEqual([GROUP_E2EE_SECURITY_PROFILE])
      expect(spec?.requiresOriginProof(createMeta())).toBe(true)
      // §17 L1930：认证失败复用 P1 Core 的码，P6 不另立一套。
      expect(spec?.authCodes.invalidProof).toEqual({ code: 1005, anpCode: 'anp.unauthorized' })
    }
  })

  it('names the caller alone for create/remove/send, and the join target as well for add', () => {
    const created = lookupMethod(GROUP_E2EE_CREATE)?.deviceAddressed?.(createMeta(), createBody('g'))
    expect(created?.pairs).toEqual([{ identity: owner.did, deviceId: OWNER_DEVICE }])

    const removed = lookupMethod(GROUP_E2EE_REMOVE)?.deviceAddressed?.(groupMeta('g'), removeBody('g'))
    expect(removed?.pairs).toEqual([{ identity: owner.did, deviceId: OWNER_DEVICE }])

    const sent = lookupMethod(GROUP_E2EE_SEND)?.deviceAddressed?.(sendMeta('g'), sendBody('g'))
    expect(sent?.pairs).toEqual([{ identity: owner.did, deviceId: OWNER_DEVICE }])

    const added = lookupMethod(GROUP_E2EE_ADD)?.deviceAddressed?.(groupMeta('g'), addBody('g'))
    expect(added?.pairs).toEqual([
      { identity: owner.did, deviceId: OWNER_DEVICE },
      { identity: member.did, deviceId: MEMBER_DEVICE },
    ])
  })

  it('gives send no validateBody and the other three one', () => {
    // `send` 唯一那条正文要求属于 §13.3 L1627 的第 8 项，必须排在成员判定之后，所以它不能
    // 被提到方法表这一层（`groupControl.ts` 的正文校验一节写了完整理由）。
    expect(lookupMethod(GROUP_E2EE_SEND)?.validateBody).toBeUndefined()
    for (const name of [GROUP_E2EE_CREATE, GROUP_E2EE_ADD, GROUP_E2EE_REMOVE]) {
      expect(typeof lookupMethod(name)?.validateBody).toBe('function')
    }
  })

  it('scopes every P6 operation by the group it is about', () => {
    // `create` 的群在正文里，另外三条在 `meta.target.did` 上。合起来是一条不变量：一次 P6
    // 操作的幂等作用域就是它所针对的那个群。
    expect(lookupMethod(GROUP_E2EE_CREATE)?.targetScope?.(createMeta(), { group_did: 'did:g' })).toBe('did:g')
    for (const name of [GROUP_E2EE_ADD, GROUP_E2EE_REMOVE, GROUP_E2EE_SEND]) {
      expect(lookupMethod(name)?.targetScope?.(groupMeta('did:g'), {})).toBe('did:g')
    }
  })
})

// ---- create ------------------------------------------------------------------

describe(`${GROUP_E2EE_CREATE} (§9.2)`, () => {
  it('seats the owner as the initial leaf, and does not touch either P4 counter', async () => {
    const { h, groupDid } = await groupWithState()
    const group = h.storage.group(groupDid)
    // §9.2.4 逐字：控制动作 MUST NOT 独立产生 `group_state_version` / `group_event_seq`。
    expect(group?.groupStateVersion).toBe(1)
    expect(group?.groupEventSeq).toBe(1)

    const leaf = h.storage.groupLeaf(groupDid, owner.did, OWNER_DEVICE)
    expect(leaf?.state).toBe('active')
    expect(leaf?.cryptoGroupId).toBe(CRYPTO_GROUP_ID)
    expect(leaf?.epoch).toBe('0')
  })

  it('echoes the five §9.2.4 fields', async () => {
    const { groupDid, created } = await groupWithState()
    expect(created).toEqual({
      created: true,
      group_did: groupDid,
      group_state_ref: stateRef(groupDid),
      crypto_group_id_b64u: CRYPTO_GROUP_ID,
      epoch: '0',
      accepted_at: NOW.toISOString(),
    })
  })

  it('refuses a second initialisation on the same coordinates with 5005', async () => {
    // 同一个群在同一组坐标上被初始化了两次——调用方该做的是"这个请求重来过"，而不是换群。
    const { h, groupDid } = await groupWithState()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta({ operation_id: 'op-create-2' }),
        createBody(groupDid),
        { id: 'req-create-2' },
      ),
    )
    expect(outcome.json?.error?.code).toBe(5005)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.epoch_conflict')
  })

  it('refuses a second initialisation under a different crypto_group_id with 5006', async () => {
    // §17 L1924 逐字"`group_did` 与 `crypto_group_id` 的绑定不一致"——§14.5 说的分叉。
    const { h, groupDid } = await groupWithState()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta({ operation_id: 'op-create-fork' }),
        createBody(groupDid, { crypto_group_id_b64u: OTHER_CRYPTO_GROUP_ID }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5006)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.crypto_group_mismatch')
  })

  it('refuses a non-owner member with 5003', async () => {
    const h = harness()
    const groupDid = mintP4Group(h.storage)
    addP4Member(h.storage, groupDid, member.did)
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta({ sender_did: member.did, sender_device_id: MEMBER_DEVICE }),
        createBody(groupDid, { creator_key_package: keyPackageFor(member, MEMBER_DEVICE) }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5003)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.controller_required')
  })

  it('refuses a group this service does not host with the P4 3000', async () => {
    const h = harness()
    const outcome = await h.call(await signed(GROUP_E2EE_CREATE, createMeta(), createBody(`${SERVICE_DID}:g:missing`)))
    expect(outcome.json?.error?.code).toBe(3000)
    expect(outcome.json?.error?.data?.anp_code).toBe('group.not_member')
  })
})

// ---- add ---------------------------------------------------------------------

describe(`${GROUP_E2EE_ADD} (§9.3)`, () => {
  it('adds the member leaf and advances every active leaf to the new epoch', async () => {
    const { h, groupDid } = await groupWithMember()
    const added = h.storage.groupLeaf(groupDid, member.did, MEMBER_DEVICE)
    expect(added?.state).toBe('active')
    expect(added?.epoch).toBe('1')
    // §9.3.3 的 `epoch` 是 "after this add"，Commit 推进**所有人**——owner 那一行也在新坐标上。
    expect(h.storage.groupLeaf(groupDid, owner.did, OWNER_DEVICE)?.epoch).toBe('1')
  })

  it('refuses an already-active leaf with 5005', async () => {
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(GROUP_E2EE_ADD, groupMeta(groupDid, { operation_id: 'op-add-again' }), addBody(groupDid, { epoch: '2' })),
    )
    expect(outcome.json?.error?.code).toBe(5005)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.epoch_conflict')
  })

  it('refuses a target that is not an active P4 member with 5004', async () => {
    // §9.3.3："`member_did` MUST be a current P4 `active` member"。业务层还没把这个人放进群，
    // 密码学层无从跟上——所以是 5004（状态未就绪），不是 3000（调用方自己就是 owner）。
    const { h, groupDid } = await groupWithState()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_ADD,
        groupMeta(groupDid, { operation_id: 'op-add-outsider' }),
        addBody(groupDid, { member_did: outsider.did, member_device_id: OUTSIDER_DEVICE, group_key_package: keyPackageFor(outsider, OUTSIDER_DEVICE) }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5004)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.state_not_ready')
  })

  it('refuses a KeyPackage whose owner is not the named member, with 5002', async () => {
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_ADD,
        groupMeta(groupDid, { operation_id: 'op-add-wrongkp' }),
        addBody(groupDid, { group_key_package: keyPackageFor(outsider, OUTSIDER_DEVICE) }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5002)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.did_binding_invalid')
  })
})

// ---- remove ------------------------------------------------------------------

describe(`${GROUP_E2EE_REMOVE} (§9.4)`, () => {
  it('marks the exact leaf terminal and keeps the row', async () => {
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(GROUP_E2EE_REMOVE, groupMeta(groupDid, { operation_id: 'op-remove-1' }), removeBody(groupDid)),
    )
    expect(outcome.json?.error).toBeUndefined()
    const leaf = h.storage.groupLeaf(groupDid, member.did, MEMBER_DEVICE)
    // §11 DDL 注释：terminal 的行留着，否则同一 `(did, device)` 重新加入时分不出"第一次进群"
    // 与"重新加入"（§10.3 L1066 要用到"该精确设备当前没有 Leaf"）。
    expect(leaf?.state).toBe('terminal')
    expect(leaf?.epoch).toBe('2')
  })

  it('refuses an absent or already-terminal target with 5004, not 5013', async () => {
    // 5013 是 §11.9.1 L1306 的**发送方侧**终态信号，回给那台设备自己；`body.member_did` 那台
    // 正要离开的设备收到它只会误以为自己也该收敛。这条区分是本方法里最容易被写错的一处。
    const { h, groupDid } = await groupWithMember()
    await h.call(await signed(GROUP_E2EE_REMOVE, groupMeta(groupDid, { operation_id: 'op-remove-1' }), removeBody(groupDid)))
    const outcome = await h.call(
      await signed(GROUP_E2EE_REMOVE, groupMeta(groupDid, { operation_id: 'op-remove-again' }), removeBody(groupDid, { epoch: '3' })),
    )
    expect(outcome.json?.error?.code).toBe(5004)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.state_not_ready')
  })
})

// ---- owner leaf（§13.4 L1640 第 2 项）-----------------------------------------

describe('the owner branch also requires a current owner leaf (§13.4 L1640 item 2)', () => {
  it('refuses add when the owner is the group owner but has no leaf yet, with 5013', async () => {
    // "是 owner"与"这台设备是当前 leaf"是两半。此时 P4 把 owner 认成 owner（`requireOwner`
    // 放行），但密码学层还没有它的位置——§17 L1930 的 `leaf_not_current` 说的正是后者。
    const h = harness()
    const groupDid = mintP4Group(h.storage)
    addP4Member(h.storage, groupDid, member.did)
    const outcome = await h.call(
      await signed(GROUP_E2EE_ADD, groupMeta(groupDid, { operation_id: 'op-add-noleaf' }), addBody(groupDid)),
    )
    expect(outcome.json?.error?.code).toBe(5013)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.leaf_not_current')
    expect(outcome.json?.error?.data?.details?.sender_device_id).toBe(OWNER_DEVICE)
  })

  it('refuses remove on the same ground, and before the coordinate check', async () => {
    // 这一条同时钉住次序：正文里的 `crypto_group_id_b64u` 是另一个群，但 leaf 检查排在坐标
    // 检查之前，所以回的是 5013 而不是 5006。§13.4 没有给这几项规定次序，本服务把"你是谁"
    // 那一组读在一起。
    const h = harness()
    const groupDid = mintP4Group(h.storage)
    addP4Member(h.storage, groupDid, member.did)
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_REMOVE,
        groupMeta(groupDid, { operation_id: 'op-remove-noleaf' }),
        removeBody(groupDid, { crypto_group_id_b64u: OTHER_CRYPTO_GROUP_ID }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5013)
  })

  it('lets the same request through once the owner has a leaf', async () => {
    const { h, groupDid } = await groupWithState()
    addP4Member(h.storage, groupDid, member.did)
    const outcome = await h.call(
      await signed(GROUP_E2EE_ADD, groupMeta(groupDid, { operation_id: 'op-add-1' }), addBody(groupDid)),
    )
    expect(outcome.json?.error).toBeUndefined()
    expect(h.storage.groupLeaf(groupDid, member.did, MEMBER_DEVICE)?.state).toBe('active')
  })
})

// ---- send --------------------------------------------------------------------

describe(`${GROUP_E2EE_SEND} (§9.5)`, () => {
  it('accepts a member device ciphertext, and advances only the event sequence', async () => {
    const { h, groupDid } = await groupWithMember()
    const before = h.storage.group(groupDid)
    const outcome = await h.call(
      await signed(GROUP_E2EE_SEND, sendMeta(groupDid, { sender_did: member.did, sender_device_id: MEMBER_DEVICE }), sendBody(groupDid)),
    )
    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result?.accepted).toBe(true)
    // §14.1 L1705：`group.e2ee.send` 进事件排序链——推 `group_event_seq`，不推
    // `group_state_version`（§10.6，与 P4 的 `group.send` 同级）。
    expect(outcome.json?.result?.group_state_version).toBe(String(before?.groupStateVersion))
    expect(outcome.json?.result?.group_event_seq).toBe(String((before?.groupEventSeq ?? 0) + 1))
    // §9.5.3：响应里的 `epoch` 是**被接受的那一份**的 epoch（那颗密文自己报的）。
    expect(outcome.json?.result?.epoch).toBe('1')
    expect(h.storage.group(groupDid)?.groupEventSeq).toBe((before?.groupEventSeq ?? 0) + 1)
  })

  it('refuses a sender whose DID is a member but whose device has no leaf, with 5013', async () => {
    // §13.3 第 5 项的分岔：DID 是 P4 `active` 成员（第 4 项过）、设备也仍合格，但那个二元组
    // 不在投影里。这一条绝不能折叠进第 4 项——否则一台只被移除了 leaf 的设备永远收敛不了：
    // 它的 DID 还是 active，3000 那条信号永远不会为它触发。
    const { h, groupDid } = await groupWithState()
    addP4Member(h.storage, groupDid, member.did)
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { sender_did: member.did, sender_device_id: MEMBER_DEVICE }),
        sendBody(groupDid),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5013)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.leaf_not_current')
    expect(outcome.json?.error?.data?.details?.sender_device_id).toBe(MEMBER_DEVICE)
  })

  it('refuses a sender who is not a P4 member at all with 3000', async () => {
    // §13.3 第 4 项先于第 5 项：outsider 两条都不满足，得到的是"你不是成员"。
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { operation_id: 'op-send-outsider', sender_did: outsider.did, sender_device_id: OUTSIDER_DEVICE }),
        sendBody(groupDid),
      ),
    )
    expect(outcome.json?.error?.code).toBe(3000)
    expect(outcome.json?.error?.data?.anp_code).toBe('group.not_member')
  })

  it('refuses a ciphertext naming another crypto group with 5006', async () => {
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { sender_did: member.did, sender_device_id: MEMBER_DEVICE, operation_id: 'op-send-fork' }),
        sendBody(groupDid, {
          group_cipher_object: {
            crypto_group_id_b64u: OTHER_CRYPTO_GROUP_ID,
            private_message_b64u: 'AAAA',
            epoch: '1',
            group_state_ref: stateRef(groupDid),
          },
        }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5006)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.crypto_group_mismatch')
  })

  it('refuses a wrong content_type with 1003, before any membership question', async () => {
    // §9.5.3 把它固定成 `application/anp-group-cipher+json`。判在成员之前——那是**请求**自己
    // 的形状，形状先于身份。
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { sender_did: member.did, sender_device_id: MEMBER_DEVICE, content_type: 'text/plain' }),
        sendBody(groupDid),
      ),
    )
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
  })

  it('refuses an incomplete group_cipher_object with 5007, after the sender is cleared', async () => {
    // §13.3 L1627 的第 8 项。`send` 故意不写 `validateBody`，所以这一条只能由处理器报——正是
    // "正文检查排在成员之后"那条次序的可观测形态。
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { sender_did: member.did, sender_device_id: MEMBER_DEVICE, operation_id: 'op-send-bad' }),
        { group_cipher_object: { crypto_group_id_b64u: CRYPTO_GROUP_ID } },
      ),
    )
    expect(outcome.json?.error?.code).toBe(5007)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.private_message_invalid')
  })
})

// ---- §13.6 L1693：一次性 nonce -------------------------------------------------

describe('the one-time proof nonce (§13.6 L1693)', () => {
  it('accepts the first use of a nonce and refuses the second with 1005', async () => {
    // 两次调用打两个不同的群、用两个 `operation_id`，所以第二次**不是**幂等重放——它一定会
    // 走到 `perform`，在那里撞上已被兑掉的 nonce。§17 L1930 要求这类失败复用 P1 的码。
    const h = harness()
    const first = mintP4Group(h.storage)
    const second = mintP4Group(h.storage)

    const accepted = await h.call(
      await signed(GROUP_E2EE_CREATE, createMeta(), createBody(first, {}), { nonce: 'proof-nonce-1', id: 'req-n1' }),
    )
    expect(accepted.json?.error).toBeUndefined()

    const reused = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta({ operation_id: 'op-create-2' }),
        createBody(second, {}),
        { nonce: 'proof-nonce-1', id: 'req-n2' },
      ),
    )
    expect(reused.json?.error?.code).toBe(1005)
    expect(reused.json?.error?.data?.anp_code).toBe('anp.unauthorized')
  })

  it('does not burn the nonce on a rejected call', async () => {
    // 兑 nonce 的那句 INSERT 与处理器在同一个事务里，被拒即整体回滚——调用方改掉正文重签一份
    // 就能再来。这里第一次调用因为 owner 不是 owner 而被拒（5013 走不到，5003），第二次带着
    // 同一个 nonce 打另一个群，应当被受理。
    const h = harness()
    const first = mintP4Group(h.storage)
    const second = mintP4Group(h.storage)
    const refused = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta({ sender_did: member.did, sender_device_id: MEMBER_DEVICE }),
        createBody(first, { creator_key_package: keyPackageFor(member, MEMBER_DEVICE) }),
        { nonce: 'proof-nonce-2', id: 'req-n1' },
      ),
    )
    expect(refused.json?.error?.code).toBe(5003)

    const retried = await h.call(
      await signed(GROUP_E2EE_CREATE, createMeta(), createBody(second, {}), { nonce: 'proof-nonce-2', id: 'req-n2' }),
    )
    expect(retried.json?.error).toBeUndefined()
  })

  it('accepts a proof that carries no nonce at all', async () => {
    // A.2 L1018 让 nonce 是可选参数；没有可兑的值就不自造一条拒绝理由。
    const h = harness()
    const first = mintP4Group(h.storage)
    const second = mintP4Group(h.storage)
    const one = await h.call(await signed(GROUP_E2EE_CREATE, createMeta(), createBody(first, {}), { id: 'req-a' }))
    const two = await h.call(
      await signed(GROUP_E2EE_CREATE, createMeta({ operation_id: 'op-create-2' }), createBody(second, {}), { id: 'req-b' }),
    )
    expect(one.json?.error).toBeUndefined()
    expect(two.json?.error).toBeUndefined()
  })
})

// ---- 正文校验（1003）先于设备定址 ----------------------------------------------

describe('body validation runs before the device-addressing step', () => {
  it('refuses add with a missing member_did as a proper 1003, not an internal error', async () => {
    // `add` 的 `deviceAddressed` 要读 `body.member_did`，而它在 `validateBody` **之后**才被调用。
    // 少了这一层，那个字段的缺失会以 `ConnectxError`（500）的形式冒出来，而不是一条体面的
    // 拒绝——这正是这四条必须写 `validateBody` 的理由。
    const { h, groupDid } = await groupWithMember()
    const { member_did: _dropped, ...rest } = addBody(groupDid)
    void _dropped
    const outcome = await h.call(
      await signed(GROUP_E2EE_ADD, groupMeta(groupDid, { operation_id: 'op-add-nofield' }), rest),
    )
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
    expect(outcome.json?.error?.message).toContain('member_did')
  })

  it('refuses create when group_state_ref names a different group, with 1003', async () => {
    const h = harness()
    const groupDid = mintP4Group(h.storage)
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_CREATE,
        createMeta(),
        createBody(groupDid, { group_state_ref: { group_did: 'did:web:other.example:g:1', group_state_version: '1' } }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('group_state_ref.group_did')
  })

  it('refuses a padded base64url that is not no-padding base64url, with 1003', async () => {
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(
        GROUP_E2EE_REMOVE,
        groupMeta(groupDid, { operation_id: 'op-remove-b64' }),
        removeBody(groupDid, { commit_b64u: 'AA==' }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('commit_b64u')
  })
})

// ---- §12：受理时就写进 Device Delivery Queue ------------------------------------

/** 队列里的每一条，按 `(did, device, seq)`。`due` 那个参数取一个远未来的时刻，于是"队头已
 *  到期"这条规则对每条队列都成立，读到的就是整条队列——测试要看的是**装了什么**，不是到期
 *  与否（那件事由 `delivery/deviceQueue.test.ts` 与 `sqlite.test.ts` 管）。 */
function queued(storage: Storage): StoredDeviceEnvelope[] {
  return storage.dueDeviceEnvelopes('9999-12-31T00:00:00Z', 1000)
}

function parsed(row: StoredDeviceEnvelope | undefined): Record<string, any> {
  if (row === undefined) throw new Error('no such envelope')
  return JSON.parse(row.envelopeJson) as Record<string, any>
}

describe('the Device Delivery Queue is written with the accepted call (§12)', () => {
  it('queues nothing for create', async () => {
    // §9.2.1：初始成员是 owner 自己，没有 Commit 要投，也没有 Welcome。create 一个信封都不发。
    const { h } = await groupWithState()
    expect(queued(h.storage)).toEqual([])
  })

  it('queues a commit for every leaf plus a welcome for the joined device, on add', async () => {
    // §12.3 L1447：Add 投两样——Commit 给**加完之后**的每条 active leaf（含新 leaf），Welcome
    // 只给新 leaf（§12.4 且 MUST NOT 发给 sibling）。
    const { h, groupDid } = await groupWithMember()
    const rows = queued(h.storage).filter((r) => r.groupDid === groupDid)
    // 队列按 `(did, device, seq)` 排，所以 member 那条队列排在 owner 前面（DID 的字面序）。
    expect(rows.map((r) => `${r.recipientDeviceId}:${r.kind}`)).toEqual([
      `${MEMBER_DEVICE}:commit`,
      `${MEMBER_DEVICE}:welcome`,
      `${OWNER_DEVICE}:commit`,
    ])

    const commit = parsed(rows[0])
    expect(commit.method).toBe(GROUP_E2EE_NOTICE)
    expect(commit.params.meta.profile).toBe(GROUP_E2EE_PROFILE)
    // §12.2.2 L1426：notice 那一档写死 `transport-protected`，与群的策略无关。
    expect(commit.params.meta.security_profile).toBe('transport-protected')
    // §12.2.2 L1428：发起者是群自己。
    expect(commit.params.meta.sender_did).toBe(groupDid)
    expect(commit.params.meta.target).toEqual({ kind: 'agent', did: member.did })
    expect(commit.params.meta.recipient_device_id).toBe(MEMBER_DEVICE)
    // §12.2：通知不带 proof。附一个反而违规（§13.6 L1663）。
    expect(commit.params.auth).toBeUndefined()
    expect(commit.params.body).toMatchObject({
      notice_type: 'commit-delivery',
      group_did: groupDid,
      crypto_group_id_b64u: CRYPTO_GROUP_ID,
      epoch: '1',
      subject_did: member.did,
      subject_device_id: MEMBER_DEVICE,
      subject_status: 'active',
      commit_b64u: 'AAAA',
    })

    // 逐叶的那几份共用一个 `notice_id`（§7.6 L665），但各自去重时只看自己那条流。
    expect(parsed(rows[2]).params.body.notice_id).toBe(commit.params.body.notice_id)
    expect(parsed(rows[1]).params.body).toMatchObject({
      notice_type: 'welcome-delivery',
      notice_id: commit.params.body.notice_id,
      welcome_b64u: 'AAAA',
      ratchet_tree_b64u: 'AAAA',
    })
    // Welcome 里没有 `subject_status`——那一位是 Commit 的（§7.6 L673）。
    expect(parsed(rows[1]).params.body.subject_status).toBeUndefined()
  })

  it('queues one group.incoming per current leaf on send, preserving the accepted fields', async () => {
    // §12.5 L1491：逐叶一封独立的信封，携带**同一份** ordering fields / receipt / 密文，只有
    // target 与 recipient_device_id 变。
    const { h, groupDid } = await groupWithMember()
    const before = queued(h.storage).length
    const outcome = await h.call(await signed(GROUP_E2EE_SEND, sendMeta(groupDid), sendBody(groupDid)))
    expect(outcome.json?.error).toBeUndefined()

    const rows = queued(h.storage).filter((r) => r.kind === 'incoming')
    expect(rows.map((r) => r.recipientDeviceId)).toEqual([MEMBER_DEVICE, OWNER_DEVICE])
    expect(rows.length + before).toBe(queued(h.storage).length)

    for (const row of rows) {
      const envelope = parsed(row)
      expect(envelope.method).toBe('group.incoming')
      // §12.5 L1484：应用密文那一档是 `group-e2ee`。
      expect(envelope.params.meta.security_profile).toBe('group-e2ee')
      // §12.5 L1486/L1487：发送方那一对与三个被接受的字段原样保留。
      expect(envelope.params.meta.sender_did).toBe(owner.did)
      expect(envelope.params.meta.sender_device_id).toBe(OWNER_DEVICE)
      expect(envelope.params.meta.message_id).toBe('msg-1')
      expect(envelope.params.meta.operation_id).toBe('op-send-1')
      expect(envelope.params.meta.content_type).toBe(GROUP_CIPHER_CONTENT_TYPE)
      // §12.6 第 2 条：ordering fields、receipt、密文一字不改。响应的序号就是信封里的序号。
      expect(envelope.params.body.group_state_version).toBe(outcome.json?.result?.group_state_version)
      expect(envelope.params.body.group_event_seq).toBe(outcome.json?.result?.group_event_seq)
      expect(envelope.params.body.group_receipt).toEqual(outcome.json?.result?.group_receipt)
      expect(envelope.params.body.group_cipher_object).toEqual(sendBody(groupDid).group_cipher_object)
    }
    // 逐叶只变 target 那一处。
    expect(parsed(rows[0]).params.meta.target.did).toBe(member.did)
    expect(parsed(rows[1]).params.meta.target.did).toBe(owner.did)
  })

  it('preserves the submission origin proof and adds its origin context (§13.6)', async () => {
    // §13.6 L1670：重建时把提交里的 origin proof 连同 `origin_context` 一起保留——接收方
    // 靠它判"这份 proof 当初是为什么、什么时候做的"，而 proof 里的时间窗在投递时已经过期。
    const { h, groupDid } = await groupWithMember()
    await h.call(await signed(GROUP_E2EE_SEND, sendMeta(groupDid), sendBody(groupDid)))
    const envelope = parsed(queued(h.storage).find((r) => r.kind === 'incoming'))

    expect(envelope.params.auth.scheme).toBe('anp-rfc9421-origin-proof-v1')
    // A.2：那份 proof 的三个字段一字不动地留着（`contentDigest` / `signatureInput` / `signature`）。
    for (const field of ['contentDigest', 'signatureInput', 'signature']) {
      expect(typeof envelope.params.auth.origin_proof[field]).toBe('string')
    }
    // §13.6 L1677：`created_at` 是**提交时**那个，不是投递时刻；信封自己那个是投递时刻。
    expect(envelope.params.auth.origin_context.created_at).toBe(sendMeta(groupDid).created_at ?? undefined)
    // §13.6 L1683 的黑名单字段一个都不在 extra_meta 里。
    const extra = envelope.params.auth.origin_context.extra_meta ?? {}
    for (const reserved of ['profile', 'security_profile', 'sender_did', 'target', 'message_id', 'created_at']) {
      expect(extra).not.toHaveProperty(reserved)
    }
  })

  it('queues the commits plus a last final notice on remove, and stops queueing for that leaf', async () => {
    // §12.3 L1455：Commit 给每条保留的 leaf，最终通知给被移除的那一条；§6.1 要它压在最后。
    const { h, groupDid } = await groupWithMember()
    const outcome = await h.call(
      await signed(GROUP_E2EE_REMOVE, groupMeta(groupDid, { operation_id: 'op-remove-1' }), removeBody(groupDid)),
    )
    expect(outcome.json?.error).toBeUndefined()

    const memberRows = queued(h.storage)
      .filter((r) => r.groupDid === groupDid && r.recipientDeviceId === MEMBER_DEVICE)
      .map((r) => `${r.seq}:${r.kind}`)
    // 队内次序就是入队次序：commit、welcome 之后是最终通知，`seq` 最大。
    expect(memberRows).toEqual(['1:commit', '2:welcome', '3:final-notice'])
    expect(queued(h.storage).filter((r) => r.groupDid === groupDid && r.recipientDeviceId === OWNER_DEVICE)).toHaveLength(2)

    const removed = parsed(queued(h.storage).find((r) => r.kind === 'final-notice'))
    expect(removed.params.body.subject_status).toBe('removed')
    expect(removed.params.body.subject_device_id).toBe(MEMBER_DEVICE)
    expect(removed.params.meta.target).toEqual({ kind: 'agent', did: member.did })
    // 同一颗 Commit / 同一个坐标。
    expect(removed.params.body.commit_b64u).toBe('AAAA')
    expect(removed.params.body.epoch).toBe('2')

    // §12.6：一条 leaf 被 Remove 之后 MUST NOT 再为它入队新的应用信封。这里 member 的 P4 成员
    // 行还在、owner 的 leaf 也还在，所以这次 send 会成功——但它只给**还在投影里的**那条 leaf
    // 入队，被移除的那台一个信封都收不到。
    const before = queued(h.storage)
    const resent = await h.call(
      await signed(GROUP_E2EE_SEND, sendMeta(groupDid, { operation_id: 'op-send-2', message_id: 'msg-2' }), sendBody(groupDid)),
    )
    expect(resent.json?.error).toBeUndefined()
    const added = queued(h.storage).slice(before.length)
    expect(added.map((r) => `${r.recipientDeviceId}:${r.kind}`)).toEqual([`${OWNER_DEVICE}:incoming`])
  })
})

// ---- §10.5：换 DID 之后的编排 --------------------------------------------------
//
// §8.12 的改名只动成员行，`group_leaves` 一行都不动（`groups.ts` 的 `applyMemberDidUpdate`
// 上写了理由）。于是改名一落定，投影里就留着一条**旧 DID 名下**的 active leaf——那正是 §10.5
// 那条暂停判据 "an active leaf whose DID is no longer an active member" 的可观测形态，群
// **自动**进入暂停。这一节跑的就是"自动进入暂停之后，Host 一侧能观测到的那几件事"：
// 编排行有没有开、无关的 add/remove 有没有被挡、匹配的 remove 有没有把这行清掉、send 有没有恢复。

describe('orchestrating the MLS side of a DID change (§10.5)', () => {
  /** 换掉 member 的 DID：直调那个原子的核心，不重跑 §8.12 的受理前验证（那是 `memberDidUpdate.ts`
   *  的事，`dispatch.test.ts` 从请求那一路测过）。 */
  const successor = createAnpIdentity('member-successor.example')

  function renameMember(h: Harness, groupDid: string): boolean {
    return applyMemberDidUpdate({
      storage: h.storage,
      hostServiceDid: SERVICE_DID,
      groupDid,
      previousDid: member.did,
      subjectDid: successor.did,
      acceptedAt: NOW.toISOString(),
    })
  }

  it('opens the row and pauses the group as soon as the renamed DID still holds a leaf', async () => {
    const { h, groupDid } = await groupWithMember()
    const before = h.storage.groupMember(groupDid, member.did)
    expect(renameMember(h, groupDid)).toBe(true)

    // §11.10.3：Host SHOULD 持久化"这次更新在 Add 还是 Remove"。`expected` 就是要退役的那批
    // 旧 DID leaf——它们正好是 §10.5 要逐个 Remove 掉的东西。开头是 `add-pending`。
    const row = h.storage.groupDidUpdate(groupDid)
    expect(row?.progress).toBe('add-pending')
    expect(row?.expectedJson).toBe(JSON.stringify([[member.did, MEMBER_DEVICE]]))
    expect(row?.doneJson).toBe('[]')
    expect(JSON.parse(row?.eventRefJson ?? '{}')).toMatchObject({
      group_did: groupDid,
      previous_subject_did: member.did,
      subject_did: successor.did,
    })

    // §8.12：成员行搬到新 DID，`role` / `joined_at` 这些一位不动。
    expect(h.storage.groupMember(groupDid, member.did)).toBeUndefined()
    const moved = h.storage.groupMember(groupDid, successor.did)
    expect(moved?.membershipStatus).toBe('active')
    expect(moved?.role).toBe(before?.role)
    expect(moved?.joinedAt).toBe(before?.joinedAt)

    // 投影不动：旧 DID 的 leaf 还在、还是 active。它留着，暂停才成立。
    expect(h.storage.groupLeaf(groupDid, member.did, MEMBER_DEVICE)?.state).toBe('active')

    // 群已暂停：另一名合法成员（owner）发不出应用消息。
    const paused = await h.call(
      await signed(GROUP_E2EE_SEND, sendMeta(groupDid, { operation_id: 'op-send-paused' }), sendBody(groupDid)),
    )
    expect(paused.json?.error?.code).toBe(5004)
    expect(paused.json?.error?.data?.anp_code).toBe('anp.group.e2ee.state_not_ready')
    expect(paused.json?.error?.message).toContain('is paused')

    // §8.12："stop authorizing the old DID for new operations"。旧 DID 连"是成员"这一关都
    // 过不去了——回的是 3000，而不是暂停那条群级的 5004。
    const old = await h.call(
      await signed(
        GROUP_E2EE_SEND,
        sendMeta(groupDid, { operation_id: 'op-send-old', sender_did: member.did, sender_device_id: MEMBER_DEVICE }),
        sendBody(groupDid),
      ),
    )
    expect(old.json?.error?.code).toBe(3000)
    expect(old.json?.error?.data?.anp_code).toBe('group.not_member')
  })

  it('refuses an Add that is not for the update’s current subject', async () => {
    // §10.5："MUST NOT accept an unrelated group.e2ee.add … until the DID update completes"。
    // owner 是合法成员、设备也合格，但这次更新的 Add 只能加**新 DID** 的设备。
    const { h, groupDid } = await groupWithMember()
    expect(renameMember(h, groupDid)).toBe(true)

    const outcome = await h.call(
      await signed(
        GROUP_E2EE_ADD,
        groupMeta(groupDid, { operation_id: 'op-add-unrelated' }),
        addBody(groupDid, {
          member_did: owner.did,
          member_device_id: OWNER_DEVICE,
          group_key_package: keyPackageFor(owner, OWNER_DEVICE),
        }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5004)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.state_not_ready')
    expect(outcome.json?.error?.message).toContain("is not the update's current subject")
    expect(outcome.json?.error?.message).toContain(successor.did)
  })

  it('refuses a Remove aimed outside the superseded DID’s leaves', async () => {
    // 同一句的另一半：这次的 Remove 只能退役**旧 DID** 的 leaf。owner 的 leaf 与这次更新无关。
    const { h, groupDid } = await groupWithMember()
    expect(renameMember(h, groupDid)).toBe(true)

    const outcome = await h.call(
      await signed(
        GROUP_E2EE_REMOVE,
        groupMeta(groupDid, { operation_id: 'op-remove-unrelated' }),
        removeBody(groupDid, { member_did: owner.did, member_device_id: OWNER_DEVICE }),
      ),
    )
    expect(outcome.json?.error?.code).toBe(5004)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.state_not_ready')
    expect(outcome.json?.error?.message).toContain('is not a leaf of the superseded')
    expect(outcome.json?.error?.message).toContain(member.did)
  })

  it('lets the matching Remove retire the old leaf, clear the row, and resume sends', async () => {
    // §10.5 的收尾：最后一次 Remove 成功之后才有可能恢复应用消息。这一条同时钉住"两道暂停
    // 判据一起解除"——投影里那条旧 leaf 变 `terminal`，编排行也清掉。
    const { h, groupDid } = await groupWithMember()
    expect(renameMember(h, groupDid)).toBe(true)

    const outcome = await h.call(
      await signed(GROUP_E2EE_REMOVE, groupMeta(groupDid, { operation_id: 'op-remove-1' }), removeBody(groupDid)),
    )
    expect(outcome.json?.error).toBeUndefined()
    expect(h.storage.groupLeaf(groupDid, member.did, MEMBER_DEVICE)?.state).toBe('terminal')
    expect(h.storage.groupDidUpdate(groupDid)).toBeUndefined()

    const resumed = await h.call(
      await signed(GROUP_E2EE_SEND, sendMeta(groupDid, { operation_id: 'op-send-resumed' }), sendBody(groupDid)),
    )
    expect(resumed.json?.error).toBeUndefined()
    expect(resumed.json?.result?.accepted).toBe(true)
  })
})
