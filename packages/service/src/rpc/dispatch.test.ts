import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DidKeyResolver,
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  ed25519OriginProofSigner,
  JSON_RPC_ERROR,
  type AnpMeta,
  type AnpRequest,
  type AnpSigningIdentity,
  type KeyResolver,
  type LocateOptions,
} from '@agentx/core'
import { loadConfig } from '../config'
import { openObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import { createDispatch } from './dispatch'
import { buildServiceEntry } from '../well-known'
import type { RpcHandler, RpcRequest } from '../http/server'
import type { Storage } from '../storage/types'

const sender = createAnpIdentity('sender.example')
const second = createAnpIdentity('second.example')
const receiver = createAnpIdentity('receiver.example')

/** One instant for every request in this file, so `accepted_at` is a literal and the
 *  proof's window can be pinned around it. */
const NOW = new Date('2026-10-01T12:00:00Z')
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000)

/** 生产里文档来自对端自己的域；这里按 keyid 里的身份直接给一份，好让整条受理路径跑得
 *  起来又不起网络。 */
function inlineResolver(documents: Record<string, unknown>): KeyResolver {
  const base = new DidKeyResolver()
  return {
    resolve(identity: string, keyid: string, opts: LocateOptions = {}) {
      const bare = keyid.includes('#') ? keyid.slice(0, keyid.indexOf('#')) : keyid
      return base.resolve(identity, keyid, { ...opts, didDocument: documents[bare] })
    },
  }
}

const DOCUMENTS: Record<string, unknown> = {
  [sender.did]: sender.didDocument,
  [second.did]: second.didDocument,
  [receiver.did]: receiver.didDocument,
}

function meta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: sender.did,
    target: { kind: 'agent', did: receiver.did },
    operation_id: 'op-1',
    message_id: 'msg-1',
    content_type: 'text/plain',
    ...overrides,
  }
}

/** §9.1's on-the-wire shape for the pick-up surface: the extension's own profile, and
 *  `target.did` equal to `sender_did` because it is addressed to oneself. */
function inboxMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'x_agentx.inbox.v1',
    security_profile: 'transport-protected',
    sender_did: sender.did,
    target: { kind: 'agent', did: sender.did },
    operation_id: 'op-inbox',
    ...overrides,
  }
}

/** A really signed request. Only the key lookup is stubbed; the signature, the digest and
 *  the freshness window are the real code paths. */
async function signed(
  options: {
    method?: string
    meta?: AnpMeta
    body?: Record<string, unknown>
    signer?: AnpSigningIdentity
  } = {},
): Promise<AnpRequest> {
  const method = options.method ?? 'direct.send'
  const under = options.meta ?? meta()
  const body = options.body ?? { text: 'hello' }
  const signer = options.signer ?? sender
  const auth = await buildOriginProofAuth({
    method,
    meta: under,
    body,
    signer: ed25519OriginProofSigner(signer.priv, signer.keyid),
    created: NOW_SECONDS - 60,
    expires: NOW_SECONDS + 3600,
  })
  return buildMessageRequest({ id: 'req-1', method, meta: under, body, auth })
}

interface Outcome {
  status: number
  json: { id?: unknown; result?: Record<string, unknown>; error?: { code: number; data?: { anp_code?: string } } } | undefined
}

interface Harness {
  handle: RpcHandler
  storage: Storage
  logs: string[]
  call(payload: unknown): Promise<Outcome>
}

function harness(overrides: { storage?: Storage } = {}): Harness {
  const storage = overrides.storage ?? openStorage({ path: ':memory:' })
  const logs: string[] = []
  const handle = createDispatch({
    config: loadConfig({}),
    storage,
    // 这个文件里的方法没有一条会碰对象字节，但 `DispatchDeps` 要求它：一个广告了
    // `anp.attachment.v1` 的服务必须真的能存下字节（`dispatch.ts` 里有说明）。路径必须是
    // 真的可写目录，所以给一个系统临时目录；这个文件里没人往里写东西。
    objects: openObjectStore({ directory: mkdtempSync(join(tmpdir(), 'agentx-dispatch-')), maxBytes: 1024 }),
    resolver: inlineResolver(DOCUMENTS),
    log: (line) => logs.push(line),
    now: () => NOW,
  })
  return {
    handle,
    storage,
    logs,
    async call(payload: unknown): Promise<Outcome> {
      const request: RpcRequest = {
        body: typeof payload === 'string' ? payload : JSON.stringify(payload),
        headers: {},
        url: new URL('http://127.0.0.1:8787/anp-im/rpc'),
      }
      const response = await handle(request)
      return { status: response.status, json: response.body === '' ? undefined : JSON.parse(response.body) }
    },
  }
}

describe('malformed input', () => {
  it('answers text that is not JSON with -32700 and a null id', async () => {
    const h = harness()
    const outcome = await h.call('{not json')
    expect(outcome.status).toBe(200)
    expect(outcome.json?.id).toBeNull()
    expect(outcome.json?.error?.code).toBe(JSON_RPC_ERROR.PARSE_ERROR)
  })

  it('answers a Notification with nothing at all', async () => {
    const h = harness()
    const envelope = await signed()
    const { id, ...withoutId } = envelope
    void id
    const outcome = await h.call(withoutId)
    expect(outcome.status).toBe(200)
    expect(outcome.json).toBeUndefined()
    // Not merely unanswered: not acted on either.
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('answers a method it does not have with -32601', async () => {
    const h = harness()
    // P4 §8.12 L934：`group.member_did_update` 是保留的 Host 动作标识，不是 JSON-RPC 方法
    // ——正因为它像方法、又不该是可调用的，拿它当"表里没有"的例子最贴题。
    const envelope = { ...(await signed()), method: 'group.member_did_update' }
    const outcome = await h.call(envelope)
    expect(outcome.json?.error?.code).toBe(JSON_RPC_ERROR.METHOD_NOT_FOUND)
  })
})

describe('the method table decides what reaches the write', () => {
  it('refuses an unsupported profile with 1001 and stores nothing', async () => {
    const h = harness()
    const outcome = await h.call(await signed({ meta: meta({ profile: 'anp.direct.e2ee.v2' }) }))
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.unsupported_profile')
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('refuses a target kind that is not agent with 1014', async () => {
    const h = harness()
    const bad = meta({ target: { kind: 'group', did: receiver.did } })
    const outcome = await h.call(await signed({ meta: bad }))
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })
})

describe('authentication', () => {
  it('refuses a request with no auth at all, with the direct pair of codes', async () => {
    const h = harness()
    // `auth` is a member of `params`, not of the envelope.
    const envelope = await signed()
    const { auth, ...bareParams } = envelope.params
    void auth
    const outcome = await h.call({ ...envelope, params: bareParams })
    expect(outcome.json?.error?.code).toBe(2005)
    expect(outcome.json?.error?.data?.anp_code).toBe('direct.invalid_origin_proof')
  })

  it('refuses a proof whose signer is not the sender the request names, with 2006', async () => {
    const h = harness()
    // The keyid belongs to `sender`, the request claims somebody else is talking.
    const outcome = await h.call(await signed({ meta: meta({ sender_did: 'did:web:elsewhere.example' }) }))
    expect(outcome.json?.error?.code).toBe(2006)
    expect(outcome.json?.error?.data?.anp_code).toBe('direct.origin_did_mismatch')
  })

  it('logs the reason instead of putting it on the wire', async () => {
    const h = harness()
    await h.call(await signed({ signer: second }))
    expect(h.logs.join('\n')).toContain('not authenticated')
    // §10.2's error object has three fields plus `data`; the classification stays out.
    const outcome = await h.call(await signed({ signer: second }))
    expect(JSON.stringify(outcome.json?.error)).not.toContain('key_unresolved')
  })
})

describe('accepting a direct message', () => {
  it('stores the message, queues one delivery, and answers §7.1.3', async () => {
    const h = harness()
    const outcome = await h.call(await signed())
    expect(outcome.status).toBe(200)
    expect(outcome.json?.id).toBe('req-1')
    expect(outcome.json?.result).toEqual({
      accepted: true,
      message_id: 'msg-1',
      operation_id: 'op-1',
      target_did: receiver.did,
      accepted_at: NOW.toISOString(),
    })
    expect(h.storage.message(sender.did, receiver.did, 'msg-1')?.bodyJson).toBe('{"text":"hello"}')
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })

  it('queues the outbound push as the notification P3 §7.2.3 describes', async () => {
    const h = harness()
    await h.call(await signed())

    const due = h.storage.dueOutbox(NOW.toISOString(), 10)
    expect(due).toHaveLength(1)
    expect(due[0]?.recipientDid).toBe(receiver.did)
    // Due immediately: accepting and pushing are the same moment; backoff only starts
    // after the first failure.
    expect(due[0]?.nextAttemptAt).toBe(NOW.toISOString())

    const notification = JSON.parse(due[0]?.payloadJson ?? '{}') as {
      jsonrpc: string
      id?: unknown
      method: string
      params: { meta: Record<string, unknown>; auth?: unknown; body: Record<string, unknown> }
    }
    expect(notification.jsonrpc).toBe('2.0')
    // §5.3 L162: a push is a Notification, so it carries no id and asks for no answer.
    expect('id' in notification).toBe(false)
    expect(notification.method).toBe('direct.incoming')
    expect(notification.params.body).toEqual({ text: 'hello' })
    // §7.2.3 L411–418: exactly these seven, and meta.target is the RECIPIENT.
    expect(notification.params.meta).toEqual({
      profile: 'anp.direct.base.v1',
      security_profile: 'transport-protected',
      sender_did: sender.did,
      target: { kind: 'agent', did: receiver.did },
      operation_id: 'op-1',
      message_id: 'msg-1',
      content_type: 'text/plain',
    })
    // L421: device selectors MUST NOT appear, even as undefined-valued keys.
    expect(Object.keys(notification.params.meta)).not.toContain('sender_device_id')
    expect(Object.keys(notification.params.meta)).not.toContain('recipient_device_id')
  })

  it('forwards the original origin proof rather than signing its own (P3 §7.2.3 L420)', async () => {
    const h = harness()
    const request = await signed()
    await h.call(request)
    const notification = JSON.parse(h.storage.dueOutbox(NOW.toISOString(), 1)[0]?.payloadJson ?? '{}') as {
      params: { auth?: unknown }
    }
    expect(notification.params.auth).toEqual(request.params.auth)
  })

  it('queues no second push when the operation is replayed', async () => {
    const h = harness()
    await h.call(await signed())
    const retry = await h.call({ ...(await signed()), id: 'req-2' })
    expect(retry.json?.result?.accepted).toBe(true)
    // Two rows here would mean two identical pushes to the peer, which §8.4 tolerates
    // but which the accept path has no reason to cause.
    const stored = h.storage.dueOutbox(NOW.toISOString(), 10)
    expect(stored).toHaveLength(1)
  })

  it('carries conversation_id through to the result when the body has one', async () => {
    const h = harness()
    const outcome = await h.call(await signed({ body: { text: 'hi', conversation_id: 'conv-1' } }))
    expect(outcome.json?.result?.conversation_id).toBe('conv-1')
    expect(h.storage.message(sender.did, receiver.did, 'msg-1')?.conversationId).toBe('conv-1')
  })

  it('reports §7.1.3 with no device selector and no per-device results', async () => {
    const h = harness()
    const outcome = await h.call(await signed())
    expect(Object.keys(outcome.json?.result ?? {}).sort()).toEqual([
      'accepted',
      'accepted_at',
      'message_id',
      'operation_id',
      'target_did',
    ])
  })
})

describe('the body rules of P3 §6', () => {
  it.each([
    ['none of the three payload fields', {}, 'text/plain'],
    ['two of them', { text: 'a', payload: {} }, 'text/plain'],
    ['a text body declared as json', { text: 'a' }, 'application/json'],
    ['a json body declared as text', { payload: {} }, 'text/plain'],
    ['padded base64url', { payload_b64u: 'AAAA=' }, 'application/octet-stream'],
    ['a payload that is not an object', { payload: 'nope' }, 'application/json'],
  ])('refuses %s with 1003', async (_label, body, contentType) => {
    const h = harness()
    const outcome = await h.call(await signed({ meta: meta({ content_type: contentType }), body }))
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('accepts an unpadded payload_b64u', async () => {
    const h = harness()
    const outcome = await h.call(
      await signed({ meta: meta({ content_type: 'application/octet-stream' }), body: { payload_b64u: 'AAAA' } }),
    )
    expect(outcome.json?.result?.accepted).toBe(true)
  })
})

describe('idempotency', () => {
  it('replays the same result for the same operation without a second delivery', async () => {
    const h = harness()
    const first = await h.call(await signed())
    // A retry is a different request: it has its own `id`, and a freshly signed proof.
    const retry = await h.call({ ...(await signed()), id: 'req-2' })
    expect(retry.json?.id).toBe('req-2')
    expect(retry.json?.result).toEqual(first.json?.result)
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })

  it('refuses the same operation id with a different body, with 1008', async () => {
    const h = harness()
    await h.call(await signed())
    const outcome = await h.call(await signed({ body: { text: 'something else' } }))
    expect(outcome.json?.error?.code).toBe(1008)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.idempotency_conflict')
  })

  it('treats a new operation id naming an accepted message as the same message', async () => {
    // §8.2 L444–450's message-level recognition, which the flowchart orders AFTER the
    // operation-level one (§9.2 L650). A caller that follows §8.4 L465–466 never gets
    // here; one that re-sends under a new operation id gets the message it already has.
    const h = harness()
    const first = await h.call(await signed())
    const second = await h.call(await signed({ meta: meta({ operation_id: 'op-2' }) }))
    expect(second.json?.result?.accepted).toBe(true)
    expect(second.json?.result?.operation_id).toBe('op-2')
    expect(second.json?.result?.accepted_at).toBe(first.json?.result?.accepted_at)
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })

  it('lets two senders use the same message id', async () => {
    // `message_id` is the sender's own label (P1 §6.2.7 L402), so this is legal and the
    // table's key has to allow it.
    const h = harness()
    const fromSecond = await signed({
      signer: second,
      meta: meta({ sender_did: second.did, operation_id: 'op-2' }),
    })
    await h.call(await signed())
    const outcome = await h.call(fromSecond)
    expect(outcome.json?.result?.accepted).toBe(true)
    expect(h.storage.message(sender.did, receiver.did, 'msg-1')).toBeDefined()
    expect(h.storage.message(second.did, receiver.did, 'msg-1')).toBeDefined()
    expect(h.storage.headSeq(receiver.did)).toBe(2)
  })
})

describe('the pick-up extension surface (§9)', () => {
  /** Read one's own mailbox: signed by the owner, addressed to the owner. */
  async function asOwner(
    h: Harness,
    method: string,
    body: Record<string, unknown>,
    overrides: Partial<AnpMeta> = {},
  ): Promise<Outcome> {
    return h.call(
      await signed({
        method,
        meta: inboxMeta({ sender_did: receiver.did, target: { kind: 'agent', did: receiver.did }, ...overrides }),
        body,
        signer: receiver,
      }),
    )
  }

  /** One accepted message from `sender` to `receiver`, so the inbox is not empty. */
  async function seed(h: Harness): Promise<void> {
    await h.call(await signed())
  }

  it('returns a delivered message as an incoming row with the §9.3 fields', async () => {
    const h = harness()
    await seed(h)

    const outcome = await asOwner(h, 'inbox.get', { limit: 20 })

    expect(outcome.json?.result?.total).toBe(1)
    expect(outcome.json?.result?.has_more).toBe(false)
    expect(outcome.json?.result?.messages).toEqual([
      {
        message_id: 'msg-1',
        sender_did: sender.did,
        recipient_did: receiver.did,
        content_type: 'text/plain',
        direction: 'incoming',
        created_at: NOW.toISOString(),
        read_at: null,
        body: { text: 'hello' },
      },
    ])
  })

  it('shows the same message in the sender own mailbox as outgoing', async () => {
    const h = harness()
    await seed(h)

    const outcome = await h.call(
      await signed({ method: 'inbox.get', meta: inboxMeta(), body: { limit: 20 } }),
    )
    const [row] = (outcome.json?.result?.messages ?? []) as { direction: string; recipient_did: string }[]
    expect(row?.direction).toBe('outgoing')
    expect(row?.recipient_did).toBe(receiver.did)
  })

  it('drops what has been read only when include_read is not asked for', async () => {
    const h = harness()
    await seed(h)

    await asOwner(h, 'inbox.mark_read', { message_ids: ['msg-1'] }, { operation_id: 'op-read' })
    expect((await asOwner(h, 'inbox.get', { limit: 20 })).json?.result?.total).toBe(0)

    const all = await asOwner(h, 'inbox.get', { limit: 20, include_read: true })
    const [row] = (all.json?.result?.messages ?? []) as { read_at: string | null }[]
    expect(row?.read_at).toBe(NOW.toISOString())
  })

  it('reports only the ids it actually marked, with the instant it marked them', async () => {
    const h = harness()
    await seed(h)

    const outcome = await asOwner(h, 'inbox.mark_read', { message_ids: ['msg-1', 'not-mine'] })
    expect(outcome.json?.result).toEqual({
      updated_count: 1,
      message_ids: ['msg-1'],
      read_at: NOW.toISOString(),
    })
  })

  it('cannot mark a message in somebody else mailbox', async () => {
    const h = harness()
    // `msg-1` exists, but it belongs to `sender` + `receiver`; `second` is neither, so
    // there is no row in its mailbox and nothing to mark.
    await seed(h)
    const outcome = await h.call(
      await signed({
        method: 'inbox.mark_read',
        meta: inboxMeta({
          sender_did: second.did,
          target: { kind: 'agent', did: second.did },
          operation_id: 'op-read',
        }),
        body: { message_ids: ['msg-1'] },
        signer: second,
      }),
    )
    expect(outcome.json?.result).toEqual({ updated_count: 0, message_ids: [], read_at: null })
  })

  it('answers message.get_batch with items and the ids it could not resolve', async () => {
    const h = harness()
    await seed(h)

    const outcome = await asOwner(h, 'message.get_batch', { message_ids: ['msg-1', 'nowhere'] })
    const result = outcome.json?.result as { items: { message_id: string }[]; unavailable: string[] }
    expect(result.items.map((item) => item.message_id)).toEqual(['msg-1'])
    // The id is the one `msg show` takes, and it is `inbox.get` that printed it.
    expect(result.unavailable).toEqual(['nowhere'])
  })

  it('refuses a batch larger than the cap', async () => {
    const h = harness()
    const ids = Array.from({ length: 101 }, (_, i) => `m-${i}`)
    const outcome = await asOwner(h, 'message.get_batch', { message_ids: ids })
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
  })

  it('replays the delivery log with the seq the sender of the frame never sees', async () => {
    const h = harness()
    await seed(h)

    const outcome = await asOwner(h, 'sync.delta', { since: 0 })
    expect(outcome.json?.result).toEqual({
      messages: [
        {
          seq: 1,
          method: 'direct.incoming',
          params: {
            meta: {
              profile: 'anp.direct.base.v1',
              security_profile: 'transport-protected',
              sender_did: sender.did,
              target: { kind: 'agent', did: receiver.did },
              operation_id: 'op-1',
              message_id: 'msg-1',
              content_type: 'text/plain',
            },
            auth: expect.anything(),
            body: { text: 'hello' },
          },
        },
      ],
      next_since: 1,
      has_more: false,
    })
  })

  it('refuses a target that is not the signer, with 1014', async () => {
    const h = harness()
    // Reading somebody else's mailbox is not an operation this surface has, so it is a
    // target-binding failure rather than a "you would have seen nothing anyway".
    const outcome = await asOwner(h, 'inbox.get', { limit: 20 }, { target: { kind: 'agent', did: second.did } })
    expect(outcome.json?.error?.code).toBe(1014)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })

  it('refuses a group target rather than treating it as one of the four modes', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'inbox.get', { limit: 20 }, { target: { kind: 'group', did: receiver.did } })
    expect(outcome.json?.error?.code).toBe(1014)
  })

  it('refuses the direct profile on an extension method, with 1001', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'inbox.get', { limit: 20 }, { profile: 'anp.direct.base.v1' })
    expect(outcome.json?.error?.code).toBe(1001)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.unsupported_profile')
  })

  it('requires an origin proof, with the P1 public code', async () => {
    const h = harness()
    const envelope = await signed({
      method: 'inbox.get',
      meta: inboxMeta({ sender_did: receiver.did, target: { kind: 'agent', did: receiver.did } }),
      body: { limit: 20 },
      signer: receiver,
    })
    const { auth, ...bare } = envelope.params
    void auth
    const outcome = await h.call({ ...envelope, params: bare })
    // This surface has no codes of its own, so failure is P1 §10.3 L706's public pair.
    expect(outcome.json?.error?.code).toBe(1005)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.unauthorized')
  })

  it('refuses a body field it does not know instead of ignoring it', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'inbox.get', { 'include-read': true })
    expect(outcome.json?.error?.code).toBe(1003)
  })
})

describe('capability discovery (P1 §8.2)', () => {
  /** §8.2.1 L524–538's request verbatim, minus `sender_did`: anonymous is the whole point of
   *  this method (L543–544), so it is not built through `signed()` — there is no proof. */
  const anonymous = {
    jsonrpc: '2.0',
    id: 'req-cap',
    method: 'anp.get_capabilities',
    params: {
      meta: { profile: 'anp.core.binding.v1', security_profile: 'transport-protected', operation_id: 'op-cap' },
      body: {},
    },
  }

  it('answers an unsigned caller, because discovery cannot require trust it does not have', async () => {
    const h = harness()
    const outcome = await h.call(anonymous)
    expect(outcome.status).toBe(200)
    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toMatchObject({
      service_did: 'did:web:127.0.0.1%3A8787',
      supported_profiles: [
        'anp.attachment.v1',
        'anp.core.binding.v1',
        'anp.direct.base.v1',
        'anp.group.base.v2',
      ],
      supported_security_profiles: ['transport-protected'],
    })
  })

  it('reports its limits as decimal strings, and its content types as an array', async () => {
    const h = harness()
    const result = (await h.call(anonymous)).json?.result
    // §8.2.2 L570–573 + §7.3 L491: counting values are strings, so a client that does
    // arithmetic on them has to say so.
    expect(result?.limits).toEqual({ max_request_bytes: '1048576', max_message_bytes: '1048576' })
    expect(result?.supported_content_types).toEqual([
      'text/plain',
      'application/json',
      'application/anp-attachment-manifest+json',
    ])
  })

  it('agrees with the static hint the well-known document hands out', async () => {
    // The two are the same fact in two places (§8.3 L591–593 says the runtime one wins on a
    // conflict — which means a conflict must be impossible, not merely resolved).
    const h = harness()
    const config = loadConfig({})
    const result = (await h.call(anonymous)).json?.result
    const entry = buildServiceEntry(config)
    expect(result?.supported_profiles).toEqual(entry.profiles)
    expect(result?.supported_security_profiles).toEqual(entry.securityProfiles)
    expect(result?.limits).toMatchObject({ max_request_bytes: String(config.maxBody) })
  })

  it('does not name a single extension among the spec profiles', async () => {
    const h = harness()
    const result = (await h.call(anonymous)).json?.result
    for (const profile of (result?.supported_profiles ?? []) as string[]) {
      expect(profile.startsWith('x_')).toBe(false)
    }
  })

  it('still refuses an unknown profile, so a wrong call is not answered as if it were right', async () => {
    const h = harness()
    const outcome = await h.call({
      ...anonymous,
      params: { ...anonymous.params, meta: { ...anonymous.params.meta, profile: 'anp.nonexistent.v9' } },
    })
    expect(outcome.json?.error?.code).toBe(1001)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.unsupported_profile')
  })

  it('takes a target when one is offered, rather than refusing the shape §8.2.1 does not forbid', async () => {
    const h = harness()
    const outcome = await h.call({
      ...anonymous,
      params: {
        ...anonymous.params,
        meta: { ...anonymous.params.meta, target: { kind: 'agent', did: sender.did } },
      },
    })
    // `endpoint-local` only means the target may be absent; nothing says it may not be sent.
    expect(outcome.json?.error).toBeUndefined()
  })
})

describe('an unexpected failure', () => {
  it('becomes -32603 with the stack in the log and nothing on the wire', async () => {
    const real = openStorage({ path: ':memory:' })
    // `Object.create` rather than a spread: `Storage`'s methods live on the prototype.
    const broken = Object.create(real) as Storage
    broken.insertMessage = () => {
      throw new Error('disk on fire')
    }
    const h = harness({ storage: broken })

    const outcome = await h.call(await signed())
    expect(outcome.json?.error?.code).toBe(JSON_RPC_ERROR.INTERNAL_ERROR)
    expect(JSON.stringify(outcome.json)).not.toContain('disk on fire')
    expect(h.logs.join('\n')).toContain('disk on fire')
    // The whole operation rolled back, so a later retry is not answered from a record
    // for an operation that never completed.
    expect(h.storage.idempotentRow('message:op-1')).toBeUndefined()
    // …and nothing went to the outbox either: a push for a message that was never stored
    // would deliver a payload the accept path has no record of.
    expect(h.storage.dueOutbox(NOW.toISOString(), 10)).toEqual([])
  })
})

// ---- C9：群组 -----------------------------------------------------------------
//
// 处理器本身在 `groups.test.ts` 里逐个验；这里验的是**接线**——方法表认得它们、目标建模
// 那一关、以及处理器在事务里抛出的拒绝要变成它自己那个码，而不是 -32603。

const SERVICE_DID = 'did:web:127.0.0.1%3A8787'

/** §7.1 L347–358 的最小合法策略。 */
const GROUP_POLICY = {
  admission_mode: 'open-join',
  permissions: {
    send: 'member',
    add: 'admin',
    remove: 'admin',
    update_profile: 'admin',
    update_policy: 'owner',
  },
}

function groupMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.group.base.v2',
    security_profile: 'transport-protected',
    sender_did: sender.did,
    target: { kind: 'group', did: `${SERVICE_DID}:g:placeholder` },
    operation_id: 'op-group',
    ...overrides,
  }
}

/** 创建一个群，返回它的 `group_did`。`group.create` 的目标是**服务**（§8.1.2 L626）。 */
async function mintGroup(h: Harness, profile: Record<string, unknown> = {}): Promise<string> {
  const envelope = await signed({
    method: 'group.create',
    meta: groupMeta({ target: { kind: 'service', did: SERVICE_DID } }),
    body: { group_policy: GROUP_POLICY, ...(Object.keys(profile).length > 0 ? { group_profile: profile } : {}) },
  })
  const outcome = await h.call(envelope)
  const groupDid = outcome.json?.result?.group_did
  if (typeof groupDid !== 'string') throw new Error(`group.create failed: ${JSON.stringify(outcome.json)}`)
  return groupDid
}

describe('group.* over the wire (P4)', () => {
  it('creates a group, and replays the same operation idempotently', async () => {
    const h = harness()
    const meta = groupMeta({ target: { kind: 'service', did: SERVICE_DID } })
    const body = { group_policy: GROUP_POLICY }
    const first = await h.call(await signed({ method: 'group.create', meta, body }))

    expect(first.json?.error).toBeUndefined()
    expect(first.json?.result?.group_receipt).toMatchObject({ subject_method: 'group.create' })

    const retry = await h.call(await signed({ method: 'group.create', meta, body }))
    // §9.1 L630：同一个 `operation_id` 回同一个结果，不建第二个群。
    expect(retry.json?.result).toEqual(first.json?.result)
  })

  it('refuses a target that is not this service with 1014', async () => {
    const h = harness()
    const outcome = await h.call(
      await signed({
        method: 'group.create',
        meta: groupMeta({ target: { kind: 'service', did: 'did:web:elsewhere.example' } }),
        body: { group_policy: GROUP_POLICY },
      }),
    )
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })

  it('answers a non-member of group.send with 3000, not -32603', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    const outcome = await h.call(
      await signed({
        method: 'group.send',
        meta: groupMeta({
          target: { kind: 'group', did: groupDid },
          // 签名的是 `second`，所以 `sender_did` 也得是他——两者不一致会先撞上 3009。
          sender_did: second.did,
          operation_id: 'op-send',
          message_id: 'm-1',
          content_type: 'text/plain',
        }),
        body: { text: 'hello' },
        signer: second,
      }),
    )
    expect(outcome.json?.error?.code).toBe(3000)
    expect(outcome.json?.error?.data?.anp_code).toBe('group.not_member')
  })

  it('requires a proof from a caller that names itself, and none from a caller that does not', async () => {
    const h = harness()
    const groupDid = await mintGroup(h, { discoverability: 'public' })
    const target = { kind: 'group' as const, did: groupDid }

    // 带上 `sender_did` 而不带 proof：不能拿一个未经验证的身份去读（groups.md §5）。
    const claiming = buildMessageRequest({
      id: 'req-claim',
      method: 'group.get_info',
      meta: groupMeta({ target }),
      body: {},
    })
    const refused = await h.call(claiming)
    expect(refused.json?.error?.code).toBe(3008)
    expect(refused.json?.error?.data?.anp_code).toBe('group.invalid_origin_proof')

    // 匿名（§8.2.2 L658）：`public` 群只给资料快照。
    const anonymous = buildMessageRequest({
      id: 'req-anon',
      method: 'group.get_info',
      meta: { profile: 'anp.group.base.v2', security_profile: 'transport-protected', target },
      body: {},
    })
    const outcome = await h.call(anonymous)
    expect(outcome.json?.result).toEqual({
      group_did: groupDid,
      group_state_version: '1',
      group_profile: { discoverability: 'public' },
    })
  })
})
