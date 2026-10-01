// C10 —— P7 的两条字节路（`dataplane.ts`）。
//
// 它们不是 JSON-RPC：客户端是普通 HTTP 客户端，所以应答是**真的状态码**加一个 JSON 体里的
// `anp_code`。这一层要验的也是这个——每个拒绝用哪个状态码、哪张票能换哪份字节。

import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createHash } from 'node:crypto'
import type { AnpMeta } from '@agentx/core'
import { createDataPlane, type DataPlaneHandler } from './dataplane'
import { openObjectStore, type ObjectStore } from './objects'
import { openStorage } from './storage/sqlite'
import type { Storage } from './storage/types'
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
} from './rpc/attachments'

const SERVICE = 'did:web:agentx.example'
const PUBLIC_URL = 'https://agentx.example'
const ALICE = 'did:web:alice.example'
const BOB = 'did:web:bob.example'
const AT = '2026-10-01T00:00:00.000Z'
const BYTES = Buffer.from('hello')

let storage: Storage
let objects: ObjectStore
let dir: string
let clock: Date
let handleUpload: DataPlaneHandler
let handleObject: DataPlaneHandler

beforeEach(() => {
  storage = openStorage({ path: ':memory:' })
  dir = mkdtempSync(join(tmpdir(), 'agentx-plane-'))
  // 上限刻意设得很小：`BYTES` 5 字节过得去，超限那一条用一个更长的体就撞上，不必造一个
  // 真的 64 MiB 的缓冲区。
  objects = openObjectStore({ directory: dir, maxBytes: 8 })
  clock = new Date(AT)
  const plane = createDataPlane({ storage, objects, publicUrl: PUBLIC_URL, now: () => clock })
  handleUpload = plane.handleUpload
  handleObject = plane.handleObject
})

afterEach(() => {
  storage.close()
  rmSync(dir, { recursive: true, force: true })
})

function meta(actor: string = ALICE): AnpMeta {
  return {
    profile: ATTACHMENT_PROFILE,
    security_profile: ATTACHMENT_SECURITY_PROFILE,
    sender_did: actor,
    target: { kind: 'service', did: SERVICE },
    operation_id: 'op-1',
  }
}

function call(name: string, body: Record<string, unknown>, actor: string = ALICE): Record<string, unknown> {
  const handler = ATTACHMENT_HANDLERS[name]
  if (handler === undefined) throw new Error(`the handler table lost ${name}`)
  return handler({
    storage,
    serviceDid: SERVICE,
    publicUrl: PUBLIC_URL,
    objects,
    meta: meta(actor),
    body,
    acceptedAt: clock.toISOString(),
  })
}

/** 建一个槽，把 `bytes` PUT 上去，再提交。返回槽位 id 与它铸出来的 `object_uri`。 */
async function commitObject(bytes: Uint8Array = BYTES): Promise<{ slotId: string; objectUri: string }> {
  const created = call(ATTACHMENT_CREATE_SLOT, {
    attachment_id: 'att-1',
    intended_message_security_profile: 'transport-protected',
    object_encryption_mode: 'none',
  })
  const slotId = created.slot_id as string
  const upload = await handleUpload({ resource: resourceOf(String(created.upload_uri)), headers: {}, body: staged(bytes) })
  expect(upload.status).toBe(200)
  call(ATTACHMENT_COMMIT_OBJECT, {
    attachment_id: 'att-1',
    slot_id: slotId,
    commit_token: storage.attachmentSlot('att-1', slotId)?.commitToken ?? '',
    size: String(bytes.byteLength),
    digest: { alg: 'sha-256', value_b64u: createHash('sha256').update(bytes).digest('base64url') },
    object_encryption_mode: 'none',
  })
  return { slotId, objectUri: created.object_uri as string }
}

/** 下载路由那一段：`object_uri` 的最后一段就是它。 */
function resourceOf(objectUri: string): string {
  return objectUri.split('/').pop() ?? ''
}

/** 一次 PUT 的请求体。数据面用 `for await` 读它，所以这里必须给一个真的异步可迭代——
 *  数组不是，`Readable.from` 是。 */
function staged(...parts: Uint8Array[]): AsyncIterable<Uint8Array> {
  return Readable.from(parts)
}

function grantToBob(objectUri: string): void {
  insertAttachmentGrants(
    storage,
    attachmentGrantsFor({
      contentType: ATTACHMENT_MANIFEST_CONTENT_TYPE,
      securityProfile: 'transport-protected',
      body: {
        payload: {
          attachments: [
            {
              attachment_id: 'att-1',
              access_info: { object_uri: objectUri },
              encryption_info: { mode: 'none' },
            },
          ],
        },
      },
      messageId: 'msg-1',
      targetDid: BOB,
      createdAt: AT,
    }),
  )
}

function issueTicket(objectUri: string, overrides: Record<string, unknown> = {}): string {
  const result = call(
    ATTACHMENT_GET_DOWNLOAD_TICKET,
    {
      attachment_id: 'att-1',
      object_uri: objectUri,
      requester_did: BOB,
      message_security_profile: 'transport-protected',
      message_id: 'msg-1',
      message_target_did: BOB,
      ...overrides,
    },
    BOB,
  )
  return result.download_ticket_b64u as string
}

/** 把一条 200 的下载读完。不读的 `Readable` 会在测试目录被删掉之后才去 `open`，那次失败
 *  是一个无人认领的 'error' 事件——本文件里凡是拿到流的地方都读掉它。 */
async function drain(answer: { stream?: { read: Readable } }): Promise<void> {
  for await (const _chunk of answer.stream?.read ?? []) {
    // 只为把流走完。
  }
}

function problemBody(response: { body?: string }): { anp_code?: string; code?: number } {
  return JSON.parse(response.body ?? '{}') as { anp_code?: string; code?: number }
}

describe('PUT {upload_uri} (P7 §11.1)', () => {
  it('accepts the bytes and records what arrived', async () => {
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    const slotId = created.slot_id as string

    const answer = await handleUpload({
      resource: resourceOf(String(created.upload_uri)),
      headers: {},
      body: staged(Buffer.from('abc'), Buffer.from('de')),
    })
    expect(answer.status).toBe(200)
    const slot = storage.attachmentSlot('att-1', slotId)
    expect(slot?.state).toBe('uploaded')
    expect(slot?.size).toBe(5)
    expect(slot?.digest).toBe(createHash('sha256').update('abcde').digest('base64url'))
  })

  it('refuses a token that names no slot, with 404 and 6000', async () => {
    const answer = await handleUpload({ resource: 'never-issued', headers: {}, body: staged(BYTES) })
    expect(answer.status).toBe(404)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.slot_not_found')
  })

  it('refuses an expired slot with 410 and 6001', async () => {
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    clock = new Date(Date.parse(AT) + SLOT_TTL_MS + 1)
    const answer = await handleUpload({
      resource: resourceOf(String(created.upload_uri)),
      headers: {},
      body: staged(BYTES),
    })
    expect(answer.status).toBe(410)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.slot_expired')
  })

  it('refuses a second upload to the same slot, because the state machine has no such edge', async () => {
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    const resource = resourceOf(String(created.upload_uri))
    expect((await handleUpload({ resource, headers: {}, body: staged(BYTES) })).status).toBe(200)

    const again = await handleUpload({ resource, headers: {}, body: staged(Buffer.from('other')) })
    expect(again.status).toBe(404)
    expect(problemBody(again).anp_code).toBe('anp.attachment.slot_not_found')
  })

  it('refuses an aborted slot with 404, because "not found" is what the spec says for an unusable slot', async () => {
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    call(ATTACHMENT_ABORT_OBJECT, { attachment_id: 'att-1', slot_id: created.slot_id })

    const answer = await handleUpload({
      resource: resourceOf(String(created.upload_uri)),
      headers: {},
      body: staged(BYTES),
    })
    expect(answer.status).toBe(404)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.slot_not_found')
  })

  it('refuses an object past the limit with 413 and 6003, and leaves no half file behind', async () => {
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    const slotId = created.slot_id as string
    const answer = await handleUpload({
      resource: resourceOf(String(created.upload_uri)),
      headers: {},
      // 上限是 8：第一个块就已经超了，第二个块证明"超了就停"，不是"收完再算"。
      body: staged(Buffer.from('12345678'), Buffer.from('9')),
    })
    expect(answer.status).toBe(413)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.object_too_large')
    // 上限在收流的过程中判，所以半截的暂存文件必须被抹掉——否则它会永远占着那个槽的名字。
    expect(storage.attachmentSlot('att-1', slotId)?.state).toBe('pending')
    expect(existsSync(join(dir, 'tmp', slotId))).toBe(false)
  })
})

describe('GET {object_uri} (P7 §11.2)', () => {
  it('refuses a request with no bearer ticket', async () => {
    const answer = await handleObject({ resource: 'object-id', headers: {}, body: staged() })
    // §9.5 L704–705 只认 `Authorization` 头，所以 `?ticket=` 那种请求就是"没有凭据"。
    expect(answer.status).toBe(401)
    expect(answer.headers?.['www-authenticate']).toBe('Bearer')
  })

  it('refuses a ticket it never issued, with 401 and 6007', async () => {
    const answer = await handleObject({
      resource: 'object-id',
      headers: { authorization: 'Bearer made-up' },
      body: staged(),
    })
    expect(answer.status).toBe(401)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.download_ticket_invalid')
  })

  it('refuses an expired ticket with 410 and 6009', async () => {
    const { objectUri } = await commitObject()
    grantToBob(objectUri)
    const token = issueTicket(objectUri)
    clock = new Date(Date.parse(AT) + TICKET_TTL_MS + 1)

    const answer = await handleObject({
      resource: resourceOf(objectUri),
      headers: { authorization: `Bearer ${token}` },
      body: staged(),
    })
    expect(answer.status).toBe(410)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.ticket_expired')
  })

  it('refuses a ticket presented for a different object, with 403 and 6008', async () => {
    const { objectUri } = await commitObject()
    grantToBob(objectUri)
    const token = issueTicket(objectUri)

    const answer = await handleObject({
      resource: 'some-other-object',
      headers: { authorization: `Bearer ${token}` },
      body: staged(),
    })
    expect(answer.status).toBe(403)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.ticket_binding_mismatch')
  })

  it('streams the object back with the headers that stop it being a page in this origin', async () => {
    const { objectUri } = await commitObject()
    grantToBob(objectUri)
    const token = issueTicket(objectUri)

    const answer = await handleObject({
      resource: resourceOf(objectUri),
      headers: { authorization: `Bearer ${token}` },
      body: staged(),
    })
    expect(answer.status).toBe(200)
    // §7.3 的 `mime_type` 是对端给的，照它回 `content-type` 就是让对端挑渲染上下文。
    expect(answer.contentType).toBe('application/octet-stream')
    expect(answer.headers?.['x-content-type-options']).toBe('nosniff')
    expect(answer.headers?.['content-disposition']).toBe('attachment')
    expect(answer.stream?.length).toBe(BYTES.byteLength)

    const chunks: Buffer[] = []
    for await (const chunk of answer.stream?.read as Readable) chunks.push(chunk as Buffer)
    expect(Buffer.concat(chunks).equals(BYTES)).toBe(true)
  })
  it('lets a one-time ticket through exactly once, and the two racers cannot both win', async () => {
    const { objectUri } = await commitObject()
    grantToBob(objectUri)
    const token = issueTicket(objectUri, { one_time: true })
    const request = {
      resource: resourceOf(objectUri),
      headers: { authorization: `Bearer ${token}` },
      body: staged(),
    }

    const first = await handleObject(request)
    expect(first.status).toBe(200)
    await drain(first)

    const second = await handleObject(request)
    expect(second.status).toBe(401)
    expect(problemBody(second).anp_code).toBe('anp.attachment.download_ticket_invalid')
  })

  it('refuses a slot that was never committed, with 404 and 6012', async () => {
    // §10.1 L826：拿到 `object_uri` 不等于对象可用。票是真的，字节还不存在。
    const created = call(ATTACHMENT_CREATE_SLOT, {
      attachment_id: 'att-1',
      intended_message_security_profile: 'transport-protected',
      object_encryption_mode: 'none',
    })
    const objectUri = created.object_uri as string
    grantToBob(objectUri)
    const token = issueTicket(objectUri)

    const answer = await handleObject({
      resource: resourceOf(objectUri),
      headers: { authorization: `Bearer ${token}` },
      body: staged(),
    })
    expect(answer.status).toBe(404)
    expect(problemBody(answer).anp_code).toBe('anp.attachment.object_unavailable')
  })
})
