import { describe, expect, it } from 'vitest'
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
import { openStorage } from '../storage/sqlite'
import { createDispatch } from './dispatch'
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

/** A really signed request. Only the key lookup is stubbed; the signature, the digest and
 *  the freshness window are the real code paths. */
async function signed(
  options: { meta?: AnpMeta; body?: Record<string, unknown>; signer?: AnpSigningIdentity } = {},
): Promise<AnpRequest> {
  const under = options.meta ?? meta()
  const body = options.body ?? { text: 'hello' }
  const signer = options.signer ?? sender
  const auth = await buildOriginProofAuth({
    method: 'direct.send',
    meta: under,
    body,
    signer: ed25519OriginProofSigner(signer.priv, signer.keyid),
    created: NOW_SECONDS - 60,
    expires: NOW_SECONDS + 3600,
  })
  return buildMessageRequest({ id: 'req-1', method: 'direct.send', meta: under, body, auth })
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
    const envelope = { ...(await signed()), method: 'group.create' }
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
  })
})
