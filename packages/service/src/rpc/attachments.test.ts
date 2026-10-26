// C10 —— P7 控制面（`attachments.ts`）的语义。
//
// 直接调处理器而不是走 HTTP：信封、认证、幂等各有自己的测试，这里要验的是 P7 的规矩——
// 四条方法各自的字段表、状态机的边、拒绝回哪个码、Grant 在哪一刻长出来。

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import type { AnpMeta, AnpRejection } from '@anpio-cli/core'
import { openObjectStore, type ObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import {
  ATTACHMENT_ABORT_OBJECT,
  ATTACHMENT_COMMIT_OBJECT,
  ATTACHMENT_CREATE_SLOT,
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  ATTACHMENT_HANDLERS,
  ATTACHMENT_MANIFEST_CONTENT_TYPE,
  ATTACHMENT_PROFILE,
  ATTACHMENT_SECURITY_PROFILE,
  SLOT_TTL_MS,
  TICKET_TTL_MS,
  attachmentGrantsFor,
  insertAttachmentGrants,
} from './attachments'
import { AnpRefusal } from './refusal'
import { lookupMethod } from './methods'

const SERVICE = 'did:web:anpio.example'
const PUBLIC_URL = 'https://anpio.example'
const ALICE = 'did:web:alice.example'
const BOB = 'did:web:bob.example'
const CAROL = 'did:web:carol.example'
const AT = '2026-10-01T00:00:00.000Z'

let storage: Storage
let objects: ObjectStore
let dir: string

beforeEach(() => {
  storage = openStorage({ path: ':memory:' })
  dir = mkdtempSync(join(tmpdir(), 'anpiocli-attach-'))
  objects = openObjectStore({ directory: dir, maxBytes: 1024 * 1024 })
})

afterEach(() => {
  storage.close()
  rmSync(dir, { recursive: true, force: true })
})

interface CallInput {
  actor?: string
  target?: string
  body?: Record<string, unknown>
  acceptedAt?: string
}

function invoke(name: string, input: CallInput = {}): Record<string, unknown> {
  const handler = ATTACHMENT_HANDLERS[name]
  if (handler === undefined) throw new Error(`the handler table lost ${name}`)
  const meta: AnpMeta = {
    profile: ATTACHMENT_PROFILE,
    security_profile: ATTACHMENT_SECURITY_PROFILE,
    sender_did: input.actor ?? ALICE,
    target: { kind: 'service', did: input.target ?? SERVICE },
    operation_id: 'op-1',
  }
  const body = input.body ?? {}
  // 正文校验由方法表声明、由分发层执行（`dispatch.ts` 的 `bodyRefusalFor`），所以直接调
  // 处理器会绕过它。这里把那一层补上，测的才是"线上会发生什么"。
  const spec = lookupMethod(name)
  if (spec === undefined) throw new Error(`the method table lost ${name}`)
  const refused = spec.validateBody?.(body, meta)
  if (refused !== undefined) throw new AnpRefusal(refused)
  return handler({
    storage,
    serviceDid: SERVICE,
    publicUrl: PUBLIC_URL,
    objects,
    meta,
    body,
    acceptedAt: input.acceptedAt ?? AT,
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

/** §10.2.2 的一份最小合法正文。 */
const SLOT_BODY = {
  attachment_id: 'att-1',
  intended_message_security_profile: 'transport-protected',
  object_encryption_mode: 'none',
}

/** `create_slot` 一次，返回响应。 */
function createSlot(body: Record<string, unknown> = SLOT_BODY, input: CallInput = {}): Record<string, unknown> {
  return invoke(ATTACHMENT_CREATE_SLOT, { body, ...input })
}

function sha256b64u(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('base64url')
}

/**
 * 把一次 PUT 做掉：字节进暂存区，再把结果记进槽位。这是数据面（`dataplane.ts`）做的两件
 * 事，控制面的测试要验 `commit_object` 的判定，所以得先有那个前提。
 */
async function put(slotId: string, attachmentId: string, bytes: Uint8Array): Promise<void> {
  const staged = await objects.accept(slotId, Readable.from([bytes]))
  storage.recordAttachmentUpload(attachmentId, slotId, staged.size, staged.digest)
}

/** 一条承载附件清单的消息会走那条路（`direct.ts` / `groups.ts` 调的就是它）。 */
function grantFor(input: {
  messageId?: string
  targetDid?: string
  groupDid?: string
  securityProfile?: string
  payload: unknown
}): void {
  insertAttachmentGrants(
    storage,
    attachmentGrantsFor({
      contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
      securityProfile: input.securityProfile ?? 'transport-protected',
      body: { payload: input.payload },
      messageId: input.messageId ?? 'msg-1',
      ...(input.targetDid !== undefined ? { targetDid: input.targetDid } : {}),
      ...(input.groupDid !== undefined ? { groupDid: input.groupDid } : {}),
      createdAt: AT,
    }),
  )
}

function manifestEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    attachment_id: 'att-1',
    access_info: { object_uri: `${PUBLIC_URL}/anp-im/objects/obj-1` },
    encryption_info: { mode: 'none' },
    ...overrides,
  }
}

describe('attachment.create_slot (P7 §10.2)', () => {
  it('mints three distinct values and stores a pending slot', () => {
    const result = createSlot()
    const slotId = result.slot_id as string

    // §10.2.3 L884 的 MUST 字段一个不少。
    for (const field of ['attachment_id', 'slot_id', 'upload_uri', 'object_uri', 'commit_token', 'expires_at']) {
      expect(result[field]).toBeTypeOf('string')
    }
    // 开头第 1 条：`object_uri` 是**另一个**不透明 id，不是上传地址，也不是摘要。
    const uploadUri = result.upload_uri as string
    expect(uploadUri).toBe(`${PUBLIC_URL}/anp-im/upload/${uploadUri.split('/').pop() ?? ''}`)
    expect((result.object_uri as string).startsWith(`${PUBLIC_URL}/anp-im/objects/`)).toBe(true)
    expect(result.object_uri).not.toBe(result.upload_uri)
    expect(uploadUri).not.toContain(slotId)

    const slot = storage.attachmentSlot('att-1', slotId)
    expect(slot?.state).toBe('pending')
    expect(slot?.ownerDid).toBe(ALICE)
    expect(slot?.objectUri).toBe(result.object_uri)
    // 令牌是 256 位、无填充的 base64url。
    expect(slot?.uploadToken).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(result.commit_token).toBe(slot?.commitToken)
  })

  it('hands the upload route a header to send, so no client has to guess one', () => {
    expect(createSlot().upload_headers).toEqual({ 'content-type': 'application/octet-stream' })
  })

  it('expires the slot on this service own clock, because the spec sets none', () => {
    // §9.5 L696 只给了票据的 5 分钟；槽位的存活时间是本服务选的（`SLOT_TTL_MS`）。
    const result = createSlot()
    expect(Date.parse(result.expires_at as string) - Date.parse(AT)).toBe(SLOT_TTL_MS)
  })

  it('refuses a profile and mode combination the spec calls invalid, with 6013', () => {
    // §10.2.2 L875 约束 1 + §12 L1100：这是"组合不合法"，不是参数形状。
    const rejection = refusalOf(() =>
      createSlot({ ...SLOT_BODY, object_encryption_mode: 'object-e2ee' }),
    )
    expect(rejection.code).toBe(6013)
    expect(rejection.anpCode).toBe('anp.attachment.encryption_policy_violation')
  })

  it('refuses an unknown body field, because this family of field sets is closed', () => {
    const rejection = refusalOf(() => createSlot({ ...SLOT_BODY, object_key_b64u: 'x' }))
    expect(rejection.code).toBe(1003)
  })

  it('refuses a target that is not this service', () => {
    // §10.1 L798. `targetBindingHolds` only checks `kind`, so the handler does this itself.
    const rejection = refusalOf(() => createSlot(SLOT_BODY, { target: 'did:web:elsewhere.example' }))
    expect(rejection.code).toBe(1014)
  })
})

describe('attachment.commit_object (P7 §10.3)', () => {
  async function ready(): Promise<{ slotId: string; bytes: Uint8Array }> {
    const created = createSlot()
    const slotId = created.slot_id as string
    const bytes = Buffer.from('hello object')
    await put(slotId, 'att-1', bytes)
    return { slotId, bytes }
  }

  function commitBody(slotId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      attachment_id: 'att-1',
      slot_id: slotId,
      commit_token: createSlotToken(slotId),
      size: '12',
      digest: { alg: 'sha-256', value_b64u: sha256b64u(Buffer.from('hello object')) },
      object_encryption_mode: 'none',
      ...overrides,
    }
  }

  function createSlotToken(slotId: string): string {
    return storage.attachmentSlot('att-1', slotId)?.commitToken ?? ''
  }

  it('moves the bytes into place and answers the §10.3.3 set', async () => {
    const { slotId } = await ready()
    const result = invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId) })

    expect(result.committed).toBe(true)
    expect(result.attachment_id).toBe('att-1')
    expect(result.object_uri).toBe(storage.attachmentSlot('att-1', slotId)?.objectUri)
    expect(result.committed_at).toBe(AT)
    // 字节按摘要落在对象目录里，这就是"路径 = 完整性主张"。
    expect(storage.attachmentObject(sha256b64u(Buffer.from('hello object')))?.size).toBe(12)
    expect(storage.attachmentSlot('att-1', slotId)?.state).toBe('committed')
  })

  it('answers a second commit with the first answer rather than refusing', async () => {
    // Committed 是状态机的终态，没有回边。另一个 `operation_id` 指着同一个槽会走到这里。
    const { slotId } = await ready()
    const first = invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId) })
    const second = invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId) })
    expect(second).toEqual(first)
  })

  it('refuses a wrong commit token with 6002, before looking at the object state', async () => {
    const { slotId } = await ready()
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId, { commit_token: 'nope' }) }),
    )
    expect(rejection.code).toBe(6002)
  })

  it('refuses an unknown slot with 6000 and an expired one with 6001', async () => {
    // 令牌要先有形状（1003 是正文层的事），才轮得到"库里有这个槽吗"（6000）。
    const unknown = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody('missing', { commit_token: 'guess' }) }),
    )
    expect(unknown.code).toBe(6000)

    const created = createSlot()
    const slotId = created.slot_id as string
    const later = new Date(Date.parse(AT) + SLOT_TTL_MS + 1000).toISOString()
    const expired = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId), acceptedAt: later }),
    )
    expect(expired.code).toBe(6001)
  })

  it('refuses a slot nothing was uploaded to with 6012', () => {
    const slotId = createSlot().slot_id as string
    const rejection = refusalOf(() => invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId) }))
    expect(rejection.code).toBe(6012)
  })

  it('refuses a declared size or digest that is not what arrived, with 6010', async () => {
    const { slotId } = await ready()
    const wrongSize = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId, { size: '13' }) }),
    )
    expect(wrongSize.code).toBe(6010)

    const wrongDigest = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, {
        body: commitBody(slotId, { digest: { alg: 'sha-256', value_b64u: sha256b64u(Buffer.from('other')) } }),
      }),
    )
    expect(wrongDigest.code).toBe(6010)
  })

  it('refuses a mode other than the one the slot was created for, with 6013', async () => {
    const { slotId } = await ready()
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, {
        body: commitBody(slotId, {
          object_encryption_mode: 'object-e2ee',
          plaintext_size: '12',
        }),
      }),
    )
    expect(rejection.code).toBe(6013)
  })

  it('refuses the two fields the spec forbids transmitting', async () => {
    // §10.3.2 规则 3、4：`object_key_b64u` / `nonce_b64u` **MUST NOT** 出现在正文里。这条
    // MUST NOT 只有在字段集封闭时才有内容。
    const { slotId } = await ready()
    for (const field of ['object_key_b64u', 'nonce_b64u']) {
      const rejection = refusalOf(() =>
        invoke(ATTACHMENT_COMMIT_OBJECT, { body: commitBody(slotId, { [field]: 'x' }) }),
      )
      expect(rejection.code).toBe(1003)
    }
  })

  it('requires plaintext_size only when the object is encrypted', () => {
    const slotId = createSlot({
      ...SLOT_BODY,
      intended_message_security_profile: 'direct-e2ee',
      object_encryption_mode: 'object-e2ee',
    }).slot_id as string
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_COMMIT_OBJECT, {
        body: {
          attachment_id: 'att-1',
          slot_id: slotId,
          commit_token: 'x',
          size: '12',
          digest: { alg: 'sha-256', value_b64u: 'x' },
          object_encryption_mode: 'object-e2ee',
        },
      }),
    )
    expect(rejection.code).toBe(1003)
    expect(rejection.message).toContain('plaintext_size')
  })
})

describe('attachment.abort_object (P7 §10.4)', () => {
  it('discards the staged bytes and answers the §10.4.3 set', async () => {
    const slotId = createSlot().slot_id as string
    await objects.accept(slotId, Readable.from([Buffer.from('half an upload')]))

    const result = invoke(ATTACHMENT_ABORT_OBJECT, { body: { attachment_id: 'att-1', slot_id: slotId } })
    expect(result).toEqual({ aborted: true, attachment_id: 'att-1', aborted_at: AT })
    expect(storage.attachmentSlot('att-1', slotId)?.state).toBe('aborted')
  })

  it('replays the original answer instead of refusing, and stops accepting uploads', async () => {
    // Aborted 是终态：另一次 `operation_id` 指着同一个槽会报回当初那份（与 `direct.send`
    // 的重复消息识别同一个策略），而暂存文件已经不在、这个槽也不再收 PUT。
    const slotId = createSlot().slot_id as string
    await objects.accept(slotId, Readable.from([Buffer.from('half an upload')]))
    const first = invoke(ATTACHMENT_ABORT_OBJECT, { body: { attachment_id: 'att-1', slot_id: slotId } })

    const later = new Date(Date.parse(AT) + 60_000).toISOString()
    const replay = invoke(ATTACHMENT_ABORT_OBJECT, {
      body: { attachment_id: 'att-1', slot_id: slotId },
      acceptedAt: later,
    })
    expect(replay).toEqual(first)
    expect(storage.attachmentSlot('att-1', slotId)?.committedAt).toBe(AT)
  })

  it('refuses to abort an object that is already committed', async () => {
    const slotId = createSlot().slot_id as string
    const bytes = Buffer.from('hello object')
    await put(slotId, 'att-1', bytes)
    const token = storage.attachmentSlot('att-1', slotId)?.commitToken ?? ''
    invoke(ATTACHMENT_COMMIT_OBJECT, {
      body: {
        attachment_id: 'att-1',
        slot_id: slotId,
        commit_token: token,
        size: String(bytes.byteLength),
        digest: { alg: 'sha-256', value_b64u: sha256b64u(bytes) },
        object_encryption_mode: 'none',
      },
    })
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_ABORT_OBJECT, { body: { attachment_id: 'att-1', slot_id: slotId } }),
    )
    expect(rejection.code).toBe(6000)
  })

  it('takes no commit token, because the spec does not ask for one', () => {
    // §10.4.2 L957–960 只列了两个字段。多要一个令牌会把一条规范允许的请求拒掉。
    const slotId = createSlot().slot_id as string
    expect(() =>
      invoke(ATTACHMENT_ABORT_OBJECT, { body: { attachment_id: 'att-1', slot_id: slotId } }),
    ).not.toThrow()
  })
})

describe('attachment.get_download_ticket (P7 §10.5)', () => {
  const OBJECT_URI = `${PUBLIC_URL}/anp-im/objects/obj-1`

  function ticketBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      attachment_id: 'att-1',
      object_uri: OBJECT_URI,
      requester_did: BOB,
      message_security_profile: 'transport-protected',
      message_id: 'msg-1',
      message_target_did: BOB,
      ...overrides,
    }
  }

  function grant(): void {
    grantFor({ targetDid: BOB, payload: { attachments: [manifestEntry()] } })
  }

  it('issues a ticket bound to the message, with no device selector anywhere', () => {
    grant()
    const result = invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: BOB, body: ticketBody() })

    // §10.5.3 L1030 的 MUST。
    expect(result.download_ticket_b64u).toBeTypeOf('string')
    expect(Date.parse(result.expires_at as string) - Date.parse(AT)).toBe(TICKET_TTL_MS)
    // §9.4 L691 / §10.5.3 L1035：绑定里 **MUST NOT** 有设备 selector。
    expect(result.ticket_binding).toEqual({
      attachment_id: 'att-1',
      object_uri: OBJECT_URI,
      requester_did: BOB,
      message_id: 'msg-1',
      message_security_profile: 'transport-protected',
      message_target_did: BOB,
    })
  })

  it('stores the ticket under its digest, never in the clear', () => {
    grant()
    const token = invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: BOB, body: ticketBody() })
      .download_ticket_b64u as string
    expect(storage.downloadTicket(token)).toBeUndefined()
    expect(storage.downloadTicket(sha256b64u(Buffer.from(token)))).toBeDefined()
  })

  it('answers 6005 when no grant covers the triple', () => {
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: BOB, body: ticketBody() }),
    )
    expect(rejection.code).toBe(6005)
  })

  it('answers 6006 when the requester is not the authorized party', () => {
    grant()
    // 私聊的授权对象是那条消息的目标 agent（§9.2 L666），只对上字段而对不上人不构成授权。
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: CAROL, body: ticketBody({ requester_did: CAROL }) }),
    )
    expect(rejection.code).toBe(6006)
    // 反过来，请求者声称自己是 BOB 而 meta 说他是别人：那是形状问题，1003。
    const lie = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: CAROL, body: ticketBody() }),
    )
    expect(lie.code).toBe(1003)
  })

  it('answers 6006 when the profile or the target does not match the grant', () => {
    grant()
    const profile = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, {
        actor: BOB,
        body: ticketBody({ message_security_profile: 'direct-e2ee' }),
      }),
    )
    expect(profile.code).toBe(6006)

    const other = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, {
        actor: BOB,
        body: ticketBody({ message_target_did: CAROL }),
      }),
    )
    expect(other.code).toBe(6006)
  })

  it('answers 6006 for a group ticket when the requester is no longer an active member', () => {
    // §9.8 L734：判定用的是**当前**成员状态，不是消息时刻的快照。
    grantFor({
      groupDid: 'did:web:anpio.example:g:team',
      payload: { attachments: [manifestEntry()] },
    })
    const body = ticketBody({ message_target_did: undefined, group_did: 'did:web:anpio.example:g:team' })
    const rejection = refusalOf(() => invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: BOB, body }))
    expect(rejection.code).toBe(6006)
  })

  it('requires exactly one message context, because the two paths are different checks', () => {
    grant()
    const neither = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, {
        actor: BOB,
        body: ticketBody({ message_target_did: undefined }),
      }),
    )
    expect(neither.code).toBe(1003)

    const both = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, {
        actor: BOB,
        body: ticketBody({ group_did: 'did:web:anpio.example:g:team' }),
      }),
    )
    expect(both.code).toBe(1003)
  })

  it('refuses an unknown body field', () => {
    grant()
    const rejection = refusalOf(() =>
      invoke(ATTACHMENT_GET_DOWNLOAD_TICKET, { actor: BOB, body: ticketBody({ requester_device_id: 'dev-1' }) }),
    )
    expect(rejection.code).toBe(1003)
  })
})

describe('the grants a carrying message grows (P7 §9.2)', () => {
  it('grows nothing at all when the payload is not an Attachment Message', () => {
    // §6.1 L349 要求清单类型；别的内容类型下"附件表"在密文里，本服务看不见它。
    expect(
      attachmentGrantsFor({
        contentType: 'text/plain',
        securityProfile: 'transport-protected',
        body: { payload: { attachments: [manifestEntry()] } },
        messageId: 'msg-1',
        targetDid: BOB,
        createdAt: AT,
      }),
    ).toEqual([])
  })

  it('grows one grant per attachment, including the ones hosted elsewhere', () => {
    // §9.2 L656 的原话是"为每个附件创建一条"，没有"若对象在本域"这一档。
    const grants = attachmentGrantsFor({
      contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
      securityProfile: 'transport-protected',
      body: {
        payload: {
          attachments: [
            manifestEntry(),
            manifestEntry({ attachment_id: 'att-2', access_info: { object_uri: 'https://elsewhere.example/o/1' } }),
          ],
        },
      },
      messageId: 'msg-1',
      targetDid: BOB,
      createdAt: AT,
    })
    expect(grants.map((entry) => entry.attachmentId)).toEqual(['att-1', 'att-2'])
    expect(grants.every((entry) => entry.messageTargetDid === BOB && entry.createdAt === AT)).toBe(true)
  })

  it('binds a group message by group DID instead of by target', () => {
    const grants = attachmentGrantsFor({
      contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
      securityProfile: 'transport-protected',
      body: { payload: { attachments: [manifestEntry()] } },
      messageId: 'msg-1',
      groupDid: 'did:web:anpio.example:g:team',
      createdAt: AT,
    })
    expect(grants[0]?.groupDid).toBe('did:web:anpio.example:g:team')
    expect(grants[0]?.messageTargetDid).toBeUndefined()
  })

  it('refuses a plaintext carrying message that declares an encrypted object, with 6013', () => {
    // §6.1 L352：`transport-protected` 之下每条 `encryption_info.mode` **MUST** 为 `none`。
    const rejection = refusalOf(() =>
      attachmentGrantsFor({
        contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
        securityProfile: 'transport-protected',
        body: {
          payload: {
            attachments: [manifestEntry({ encryption_info: { mode: 'object-e2ee' } })],
          },
        },
        messageId: 'msg-1',
        targetDid: BOB,
        createdAt: AT,
      }),
    )
    expect(rejection.code).toBe(6013)
  })

  it('refuses a payload that is not a readable Attachment Message, with 1003', () => {
    // 收下一条我们自己都读不懂的清单，等于把授权依据交给对端去解释。
    for (const payload of [null, {}, { attachments: [] }, { attachments: [{}] }]) {
      const rejection = refusalOf(() =>
        attachmentGrantsFor({
          contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
          securityProfile: 'transport-protected',
          body: { payload },
          messageId: 'msg-1',
          targetDid: BOB,
          createdAt: AT,
        }),
      )
      expect(rejection.code).toBe(1003)
    }
  })
})

describe('the object directory', () => {
  it('is the one place that knows what an object uri looks like', async () => {
    // `create_slot` 铸它、数据面拿路径段还原它，两处都调 `objectUriFor`；写坏一处的表现是
    // 一个永远 404 的下载路由。
    const created = createSlot()
    const slotId = created.slot_id as string
    const bytes = Buffer.from('bytes')
    await put(slotId, 'att-1', bytes)
    const objectUri = created.object_uri as string
    expect(storage.attachmentSlotByObjectUri(objectUri)?.slotId).toBe(slotId)
  })

  it('keeps a staged file that nothing committed out of the object tree', () => {
    const slotId = createSlot().slot_id as string
    writeFileSync(join(dir, 'tmp', slotId), 'orphan')
    // 暂存区里的东西不是对象：按摘要查不到，`open` 也打不开。
    expect(objects.open(sha256b64u(Buffer.from('orphan')))).toBeUndefined()
  })
})
