import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DidDeviceResolver,
  DidKeyResolver,
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  ed25519OriginProofSigner,
  idempotencyKey,
  JSON_RPC_ERROR,
  stableSubjectId,
  subjectOf,
  type AnpMeta,
  type AnpRequest,
  type AnpSigningIdentity,
  type DeviceResolver,
  type DidChain,
  type DidChainAssurance,
  type KeyResolver,
  type LocateOptions,
  type NonceStore,
  type ServiceEntry,
  type ServiceLocator,
} from '@agentx/core'
import {
  ANP_COMPONENTS,
  buildContentDigestValue,
  buildSignatureBase,
  bytesToBase64,
  serializeSignatureParams,
  signatureBaseBytes,
  utf8,
} from '@agentx/core/advanced'
import { loadConfig, type Config } from '../config'
import type { ForwardOutcome, Relay } from '../federation/forward'
import { createHttpNonceStore } from '../federation/nonces'
import { openObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import { createDispatch } from './dispatch'
import { buildServiceEntry } from '../well-known'
import type { RpcHandler, RpcRequest } from '../http/server'
import type { Storage } from '../storage/types'
import type { DidChainResolver } from './memberDidUpdate'

const sender = createAnpIdentity('sender.example')
const second = createAnpIdentity('second.example')
/** 与 `second` **同域同路径、不同一把钥**——一次 DID 轮换之后的样子：主体没变，指纹变了。
 *  §8.12 要的正是从名册里那个旧的 DID 走到这一个。 */
const successor = createAnpIdentity('second.example')
const receiver = createAnpIdentity('receiver.example')
/** `receiver` **换过钥之后**的那个 DID：主体路径一样，指纹不一样。TODO7 §3 第 4 条问的就是
 *  旧投递在新名字下还取不取得到。 */
const receiverRotated = createAnpIdentity('receiver.example')
/** 发送方域里那个对外入口的服务身份。外层请求由它签，与业务发送者是两个人——
 *  §3.6 L90–98 说的两层身份，这里就是这个区别。 */
const service = createAnpIdentity('service.example')
const impostor = createAnpIdentity('evil.example')

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
  [successor.did]: successor.didDocument,
  [receiver.did]: receiver.didDocument,
  [receiverRotated.did]: receiverRotated.didDocument,
  [service.did]: service.didDocument,
}

// ---- 外层身份（C11）-----------------------------------------------------------
// 这一层要跑真的签名，所以测试自己拼一份跨域请求：覆盖集合取自核验侧读的同一个
// `ANP_COMPONENTS`，摘要与签名都是真算的。

/** 本服务在 `loadConfig({})` 下的公网地址（`config.ts` 的 loopback 默认）。 */
const AUTHORITY = '127.0.0.1:8787'
const RPC_PATH = '/anp-im/rpc'
const TARGET_URI = `http://${AUTHORITY}${RPC_PATH}`

/** 锚点发布的那唯一一个入口。`serviceDid` 指的是别的域——这正是第 6 步要比的东西。 */
function entryFor(serviceDid?: string): ServiceEntry {
  const entry: ServiceEntry = {
    id: '#anp-message-service',
    type: 'ANPMessageService',
    serviceEndpoint: 'https://sender.example/anp-im/rpc',
  }
  if (serviceDid !== undefined) entry.serviceDid = serviceDid
  return entry
}

function locator(published: Record<string, ServiceEntry[]>): ServiceLocator {
  return {
    async locate(identity: string): Promise<ServiceEntry[]> {
      return published[identity] ?? []
    },
  }
}

/** `signed()` 的正文原样签一遍外层。`created` 用真实时钟：这一层的时间窗在 core 里，
 *  没有注入点（`verify.ts` 的 `VerifyHttpSignatureInput` 里没有 `now`）。 */
async function outerHeaders(
  bodyText: string,
  options: { signer?: AnpSigningIdentity; nonce?: string } = {},
): Promise<Record<string, string>> {
  const signer = options.signer ?? service
  const created = Math.floor(Date.now() / 1000)
  const contentDigest = await buildContentDigestValue(utf8(bodyText))
  const signatureParams = serializeSignatureParams(ANP_COMPONENTS, {
    created,
    expires: created + 300,
    nonce: options.nonce ?? 'outer-nonce-1',
    keyid: signer.keyid,
  })
  const base = buildSignatureBase({
    method: 'POST',
    path: RPC_PATH,
    authority: AUTHORITY,
    targetUri: TARGET_URI,
    headers: { 'content-digest': contentDigest },
    components: ANP_COMPONENTS,
    signatureParams,
  })
  const signature = await ed25519OriginProofSigner(signer.priv, signer.keyid).sign(signatureBaseBytes(base))
  return {
    'content-type': 'application/json',
    host: AUTHORITY,
    'content-digest': contentDigest,
    'signature-input': `sig1=${signatureParams}`,
    signature: `sig1=:${bytesToBase64(signature)}:`,
  }
}

/** 常走的装配：`sender.did` 发布的入口指向 `service.did`。 */
function publishedBySender(serviceDid: string = service.did): Record<string, ServiceEntry[]> {
  return { [sender.did]: [entryFor(serviceDid)] }
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

// ---- P5 `anp.direct.e2ee.v2`（C12）---------------------------------------------
// 这一族要的文档与上面那份**不是**同一个用途：v2 的调用不带 `origin_proof`（§3.8 L140），
// 所以不验签，也就不需要 `DidKeyResolver` 认得它。这两份只服务设备资格——`deviceManifest`
// 与它引用的两个关系在就行。

const SENDER_DEVICE = 'dev-sender-7N3KQ2'
const RECEIVER_DEVICE = 'dev-receiver-4B8XT'

/** P2 §5.5 L236–268 那份文档的最小形状：两个验证方法，一个落在 `assertionMethod`（Bundle
 *  证明用），一个落在 `keyAgreement`（建链用），清单把两者绑在这台设备上。 */
function deviceDocument(did: string, deviceId: string): Record<string, unknown> {
  const signing = `${did}#${deviceId}-sign`
  const e2ee = `${did}#${deviceId}-e2ee`
  return {
    id: did,
    verificationMethod: [
      { id: signing, type: 'Multikey', controller: did, publicKeyMultibase: 'z6Mkexample' },
      { id: e2ee, type: 'Multikey', controller: did, publicKeyMultibase: 'z6LSexample' },
    ],
    assertionMethod: [signing],
    keyAgreement: [e2ee],
    deviceManifest: {
      type: 'ANPDeviceManifest',
      devices: [
        {
          device_id: deviceId,
          signing_key_id: signing,
          e2ee_key_id: e2ee,
          profiles: [
            'anp.core.binding.v1',
            'anp.identity.discovery.v1',
            'anp.direct.base.v1',
            'anp.direct.e2ee.v2',
          ],
        },
      ],
    },
  }
}

/** 文档在、清单空：§4.1.1 第 1 项要看到的那种"当前清单里没有它"。
 *
 *  用空清单而不是**缺**文档：缺文档会让 `DidDeviceResolver` 回落到真的去解析这个 DID，
 *  在这条路径上就是一次网络请求，而测试要证的是判定，不是解析。 */
function noDevices(did: string): Record<string, unknown> {
  return { id: did, deviceManifest: { type: 'ANPDeviceManifest', devices: [] } }
}

function deviceDocuments(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    [sender.did]: deviceDocument(sender.did, SENDER_DEVICE),
    [receiver.did]: deviceDocument(receiver.did, RECEIVER_DEVICE),
    ...overrides,
  }
}

/** 与 `inlineResolver` 同一个手法：清单来自调用方的表，所以受理路径跑得起来又不起网络。 */
function inlineDeviceResolver(documents: Record<string, unknown> = deviceDocuments()): DeviceResolver {
  const base = new DidDeviceResolver()
  return {
    resolveDevice(identity: string, deviceId: string, opts: LocateOptions = {}) {
      return base.resolveDevice(identity, deviceId, { ...opts, didDocument: documents[identity] })
    },
  }
}

/** §9.3 L819–825 那个形状：`operation_id` **等于** `message_id`（§3.7 L134），两个设备
 *  selector 都在，安全模式是 `direct-e2ee`。 */
function e2eeMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.e2ee.v2',
    security_profile: 'direct-e2ee',
    sender_did: sender.did,
    target: { kind: 'agent', did: receiver.did },
    operation_id: 'op-e2ee-1',
    message_id: 'op-e2ee-1',
    content_type: 'application/anp-direct-init+json',
    sender_device_id: SENDER_DEVICE,
    recipient_device_id: RECEIVER_DEVICE,
    ...overrides,
  }
}

/** v2 的请求**没有 `auth`**（§3.8 L140），所以不能走 `signed()`——它每次都造一份证明，
 *  而在这里那正是要被拒的东西。 */
function e2eeRequest(options: { meta?: AnpMeta; body?: Record<string, unknown>; id?: string } = {}): AnpRequest {
  return buildMessageRequest({
    id: options.id ?? 'req-e2ee',
    method: 'direct.send',
    meta: options.meta ?? e2eeMeta(),
    // §16.1–16.4：E2EE 承载对象在 `body` **顶层**，没有 `payload` 这个键。本服务不看它。
    body: options.body ?? { session_id: 'sess-1', suite: 'x25519-chacha20poly1305', ciphertext_b64u: 'AAAA' },
  })
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
  /** 外层认证的失败形态走响应头（ANP-02 §3.2.4.1），所以它得能被读到。 */
  headers: Record<string, string>
}

interface Harness {
  handle: RpcHandler
  storage: Storage
  logs: string[]
  call(payload: unknown): Promise<Outcome>
  /** 一次真的 HTTP POST：带上方法与头，外层八步读的就是它们。 */
  post(bodyText: string, headers: Record<string, string>): Promise<Outcome>
}

function harness(
  overrides: {
    storage?: Storage
    config?: Config
    locator?: ServiceLocator
    nonceStore?: NonceStore
    relay?: Relay
    deviceResolver?: DeviceResolver
    chainResolver?: DidChainResolver
  } = {},
): Harness {
  const storage = overrides.storage ?? openStorage({ path: ':memory:' })
  const logs: string[] = []
  const handle = createDispatch({
    config: overrides.config ?? loadConfig({}),
    storage,
    // 这个文件里的方法没有一条会碰对象字节，但 `DispatchDeps` 要求它：一个广告了
    // `anp.attachment.v1` 的服务必须真的能存下字节（`dispatch.ts` 里有说明）。路径必须是
    // 真的可写目录，所以给一个系统临时目录；这个文件里没人往里写东西。
    objects: openObjectStore({ directory: mkdtempSync(join(tmpdir(), 'agentx-dispatch-')), maxBytes: 1024 }),
    resolver: inlineResolver(DOCUMENTS),
    locator: overrides.locator ?? locator(publishedBySender()),
    deviceResolver: overrides.deviceResolver ?? inlineDeviceResolver(),
    nonceStore: overrides.nonceStore ?? createHttpNonceStore(storage),
    ...(overrides.relay !== undefined ? { relay: overrides.relay } : {}),
    ...(overrides.chainResolver !== undefined ? { chainResolver: overrides.chainResolver } : {}),
    log: (line) => logs.push(line),
    now: () => NOW,
  })

  async function send(body: string, headers: Record<string, string>, method?: string): Promise<Outcome> {
    const request: RpcRequest = {
      body,
      headers,
      url: new URL(`http://${AUTHORITY}${RPC_PATH}`),
      ...(method !== undefined ? { method } : {}),
    }
    const response = await handle(request)
    return {
      status: response.status,
      json: response.body === '' ? undefined : (JSON.parse(response.body) as Outcome['json']),
      headers: response.headers ?? {},
    }
  }

  return {
    handle,
    storage,
    logs,
    async call(payload: unknown): Promise<Outcome> {
      return send(typeof payload === 'string' ? payload : JSON.stringify(payload), {})
    },
    async post(bodyText: string, headers: Record<string, string>): Promise<Outcome> {
      return send(bodyText, headers, 'POST')
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
    // C12 put `anp.direct.e2ee.v2` into this method's `profiles`, so the counterexample has
    // to be one that is genuinely not implemented.
    const outcome = await h.call(await signed({ meta: meta({ profile: 'anp.direct.e2ee.v3' }) }))
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

  it('carries the P3 §7.2.3 fields on the delivery, which is where the message ends', async () => {
    // C11 之后这条消息在域内的终点就是这一行投递（§3.1：`direct.incoming` 是"已被目标
    // ingress 接受"之后的那一跳，而收件人就住在本服务上）。C11 之前这里还会往 outbox 排
    // 一条通知，由后台 worker 再发一次 HTTP 到自家入口——那一条从来只是白跑一趟。
    const h = harness()
    await h.call(await signed())

    expect(h.storage.dueOutbox(NOW.toISOString(), 10)).toEqual([])

    const delivered = h.storage.deliveriesSince(receiver.did, '', 0, 10, undefined)
    expect(delivered).toHaveLength(1)
    expect(delivered[0]?.method).toBe('direct.incoming')

    const params = JSON.parse(delivered[0]?.paramsJson ?? '{}') as {
      meta: Record<string, unknown>
      body: Record<string, unknown>
    }
    expect(params.body).toEqual({ text: 'hello' })
    // §7.2.3 L411–418: exactly these seven, and meta.target is the RECIPIENT.
    expect(params.meta).toEqual({
      profile: 'anp.direct.base.v1',
      security_profile: 'transport-protected',
      sender_did: sender.did,
      target: { kind: 'agent', did: receiver.did },
      operation_id: 'op-1',
      message_id: 'msg-1',
      content_type: 'text/plain',
    })
    // L421: device selectors MUST NOT appear, even as undefined-valued keys.
    expect(Object.keys(params.meta)).not.toContain('sender_device_id')
    expect(Object.keys(params.meta)).not.toContain('recipient_device_id')
  })

  it('forwards the original origin proof rather than signing its own (P3 §7.2.3 L420)', async () => {
    const h = harness()
    const request = await signed()
    await h.call(request)
    const delivered = h.storage.deliveriesSince(receiver.did, '', 0, 1, undefined)[0]
    const params = JSON.parse(delivered?.paramsJson ?? '{}') as { auth?: unknown }
    expect(params.auth).toEqual(request.params.auth)
  })

  it('appends no second delivery when the operation is replayed', async () => {
    const h = harness()
    await h.call(await signed())
    const retry = await h.call({ ...(await signed()), id: 'req-2' })
    expect(retry.json?.result?.accepted).toBe(true)
    // 两行意味着收件人会读两遍同一条消息，而这正是 §8.2 L444–450 要避免的。
    expect(h.storage.deliveriesSince(receiver.did, '', 0, 10, undefined)).toHaveLength(1)
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

/** 一条不落库、只记下被问了什么的 relay：这里要证的是**顺序**与**该不该出站**（转发在
 *  事务外、拒绝不落库、本地的调用不出站），不是转发本身——那是 `federation/forward.test.ts`
 *  的事。 */
function recording(outcome: ForwardOutcome): { relay: Relay; asked: string[] } {
  const asked: string[] = []
  return {
    asked,
    relay: {
      async forward(_request, targetDid): Promise<ForwardOutcome> {
        asked.push(targetDid)
        return outcome
      },
    },
  }
}

describe('a direct message whose recipient lives elsewhere (P8 §3.2)', () => {
  it('answers with the peer result, and files no delivery of its own', async () => {
    // 收件人不在本服务上：投递行与附件授权都是**目标 ingress** 的事（§3.1 把
    // `direct.incoming` 定成"已被目标 ingress 接受"之后的那一跳）。我们这边留下的只有
    // 台账——消息行与幂等记录，所以 §8.2 的重复识别与 §9.1 的重放都还成立。
    const { relay, asked } = recording({
      kind: 'answered',
      result: { accepted: true, message_id: 'msg-1', operation_id: 'op-1', target_did: receiver.did, accepted_at: '2026-10-01T00:00:00Z' },
    })
    const h = harness({ relay })
    const outcome = await h.call(await signed())

    expect(asked).toEqual([receiver.did])
    expect(outcome.json?.result?.accepted_at).toBe('2026-10-01T00:00:00Z')
    expect(h.storage.message(sender.did, receiver.did, 'msg-1')).toBeDefined()
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('stores nothing at all when the peer refuses', async () => {
    // §3.2 的原话："对端拒绝时**不落库**，调用方用同一个 `operation_id` 重试即可干净地
    // 再来一次。" 落一半才是最坏的中间态：调用方以为被拒了，我们这边却已经收下。
    const { relay } = recording({
      kind: 'refused',
      rejection: {
        code: 1012,
        anpCode: 'anp.temporarily_unavailable',
        retryable: true,
        message: 'the target service answered HTTP 503',
        details: { status: 503 },
      },
    })
    const h = harness({ relay })
    const outcome = await h.call(await signed())

    expect(outcome.json?.error?.code).toBe(1012)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.temporarily_unavailable')
    expect(h.storage.message(sender.did, receiver.did, 'msg-1')).toBeUndefined()
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('does not forward a retry of an operation it already answered', async () => {
    // 转发必须在事务外，所以它排在 `acceptOperation` 之前；挡住第二次出站的是一个显式的
    // 预查（`relayFor` 里的 `idempotentRow`）。少了它，重试就等于再打扰对端一次——对端
    // 恰好不可达时，"已经受理过"的重试会回 1012，把一次成功说成失败。
    const { relay, asked } = recording({
      kind: 'answered',
      result: { accepted: true, message_id: 'msg-1', operation_id: 'op-1', target_did: receiver.did, accepted_at: NOW.toISOString() },
    })
    const h = harness({ relay })
    await h.call(await signed())
    const retry = await h.call({ ...(await signed()), id: 'req-2' })

    expect(retry.json?.result?.accepted).toBe(true)
    expect(asked).toEqual([receiver.did])
  })
})

describe('an attachment control call whose object service lives elsewhere (P8 §5.3)', () => {
  const OBJECT_SERVICE = 'did:web:objects.example'
  /** §10.2.2 的一份最小合法正文（与 `attachments.test.ts` 的 `SLOT_BODY` 同源）。 */
  const SLOT_BODY = {
    attachment_id: 'att-1',
    intended_message_security_profile: 'transport-protected',
    object_encryption_mode: 'none',
  }

  function slotRequest(did: string): Promise<AnpRequest> {
    return signed({
      method: 'attachment.create_slot',
      meta: {
        profile: 'anp.attachment.v1',
        security_profile: 'transport-protected',
        sender_did: sender.did,
        target: { kind: 'service', did },
        operation_id: 'op-att-1',
      },
      body: SLOT_BODY,
    })
  }

  it('forwards to the object service the request names, and mints nothing locally', async () => {
    // 对象在对端，本地那一趟什么都不该做：落一行槽位只会造出一颗谁也 download 不到的对象。
    // 判断"办没办"看答复里的基址——本地经手时 `upload_uri` 一定挂在本服务的 `publicUrl`
    // 下，而对端那一份挂在它自己那里。
    const { relay, asked } = recording({
      kind: 'answered',
      result: {
        attachment_id: 'att-1',
        slot_id: 'slot-elsewhere',
        upload_uri: 'https://objects.example/anp-im/upload/tok',
        object_uri: 'https://objects.example/anp-im/objects/obj',
        commit_token: 'ct-elsewhere',
        expires_at: NOW.toISOString(),
      },
    })
    const h = harness({ relay })
    const outcome = await h.call(await slotRequest(OBJECT_SERVICE))

    expect(asked).toEqual([OBJECT_SERVICE])
    expect(outcome.json?.result?.slot_id).toBe('slot-elsewhere')
    expect(outcome.json?.result?.upload_uri).toBe('https://objects.example/anp-im/upload/tok')
  })

  it('handles a call naming its own service locally, without resolving its own document', async () => {
    // 同域这一档不能出站，也不能靠"我们的文档解析得到我们自己的入口"——那份文档不在本服务
    // 手里（message-service.md §13）。短路由 `relayFor` 里那次 `serviceDid` 比较给出。
    const { relay, asked } = recording({ kind: 'answered', result: { slot_id: 'never' } })
    const h = harness({ relay })
    const outcome = await h.call(await slotRequest(loadConfig({}).serviceDid))

    expect(asked).toEqual([])
    expect(outcome.json?.result?.slot_id).not.toBe('never')
    expect(String(outcome.json?.result?.upload_uri)).toMatch(/^http:\/\/127\.0\.0\.1:8787\/anp-im\/upload\//)
  })

  it('does not forward a retry of an operation it already answered', async () => {
    const { relay, asked } = recording({
      kind: 'answered',
      result: {
        attachment_id: 'att-1',
        slot_id: 'slot-elsewhere',
        upload_uri: 'https://objects.example/anp-im/upload/tok',
        object_uri: 'https://objects.example/anp-im/objects/obj',
        commit_token: 'ct-elsewhere',
        expires_at: NOW.toISOString(),
      },
    })
    const h = harness({ relay })
    await h.call(await slotRequest(OBJECT_SERVICE))
    const retry = await h.call({ ...(await slotRequest(OBJECT_SERVICE)), id: 'req-att-2' })

    expect(retry.json?.result?.slot_id).toBe('slot-elsewhere')
    expect(asked).toEqual([OBJECT_SERVICE])
  })

  it('returns the object service refusal unchanged, and records nothing', async () => {
    const { relay } = recording({
      kind: 'refused',
      rejection: {
        code: 6012,
        anpCode: 'anp.attachment.object_unavailable',
        retryable: false,
        message: 'the object is gone',
      },
    })
    const h = harness({ relay })
    const outcome = await h.call(await slotRequest(OBJECT_SERVICE))

    expect(outcome.json?.error?.code).toBe(6012)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.attachment.object_unavailable')
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

/**
 * P5 §10.7：本地受理一颗 v2 密文时要做的四件事——验两台设备的资格、按设备寻址落投递、
 * 让幂等键带上设备段、把 `recipient_device_id` 回显出去。正文本身不在这里：本服务不解密
 * （§10.7 L1392），`body` 是什么由收件设备判。
 */
describe('a device-addressed direct message (P5 anp.direct.e2ee.v2)', () => {
  it('accepts the §9.3 init without an origin proof, and files no device-less delivery', async () => {
    // §3.8 L140 禁 `auth`，所以这条请求是**没有证明**被受理的。放行它的不是"免认证"，
    // 而是这个 Profile 不要求业务层证明（§4.3 L161）——它能收下的理由写在下面两条。
    const h = harness()
    const outcome = await h.call(e2eeRequest())

    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toMatchObject({
      accepted: true,
      message_id: 'op-e2ee-1',
      operation_id: 'op-e2ee-1',
      target_did: receiver.did,
      recipient_device_id: RECEIVER_DEVICE,
    })
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })

  it('files the delivery against the named device, so a sibling device never sees it', async () => {
    // §10.7 L1391：密文只进 `(recipient_did, recipient_device_id)` 这一个信箱，§10.7.1
    // L1407 禁止 fan-out。推送那一步按这一列筛连接（C12 的前一块），所以这里验的是它的来源。
    const h = harness()
    await h.call(e2eeRequest())
    const [delivered] = h.storage.deliveriesSince(receiver.did, RECEIVER_DEVICE, 0, 10, undefined)
    expect(delivered?.recipientDeviceId).toBe(RECEIVER_DEVICE)
  })

  it('refuses a sender device the DID no longer lists, with 1017 and nothing stored', async () => {
    // §4.1.1 第 1 项在**每次操作**的前置上（L171），不是启动时校验一次。这里把清单换空
    // 就是"设备被摘了"，而它不能静默变成一次成功——投递行落下去就没有撤回的办法。
    const h = harness({
      deviceResolver: inlineDeviceResolver(deviceDocuments({ [sender.did]: noDevices(sender.did) })),
    })
    const outcome = await h.call(e2eeRequest())

    expect(outcome.json?.error?.data?.anp_code).toBe('anp.device_not_eligible')
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('refuses a recipient device whose key binding does not hold, with 1016', async () => {
    // 收件人的设备**由我们自己**解释（收件人住在本服务上），所以这一半也是我们的判断。
    // 条目还在清单里，坏的是它的 `e2ee_key_id` 没有被 `keyAgreement` 引用——所以这不是
    // 1017（"没有这台设备"），是 1016（"引用关系不成立"）。
    const broken = deviceDocument(receiver.did, RECEIVER_DEVICE)
    broken.keyAgreement = [`${receiver.did}#some-other-key`]
    const h = harness({ deviceResolver: inlineDeviceResolver(deviceDocuments({ [receiver.did]: broken })) })

    const outcome = await h.call(e2eeRequest())
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.device_binding_invalid')
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('puts both device selectors in the idempotency key (§10.7 L1391 第 3 项)', async () => {
    // 用键本身来断言，而不是编一个"同一个 operation_id 发往两台设备"的场景——§3.7 L134
    // 要求 `operation_id` **等于** `message_id`，而 P5 的每份密文都带自己那一对 id，
    // 所以那样两个请求在规范里根本不存在。能观察到的事实是键，那就直接看键。
    const h = harness()
    const outcome = await h.call(e2eeRequest())
    expect(outcome.json?.error).toBeUndefined()

    const scope = {
      senderDid: sender.did,
      targetScope: receiver.did,
      method: 'direct.send',
      operationId: 'op-e2ee-1',
    }
    const withDevices = idempotencyKey({
      ...scope,
      // 每一段都带 owner：`device_id` 是不透明字符串（P2 §5.5 L263），两侧各自取名撞上
      // 同一个值是可能的，只写设备 id 会让两台不同设备的调用共用一条键（`deviceSelector`）。
      deviceSelectors: [`${sender.did}#${SENDER_DEVICE}`, `${receiver.did}#${RECEIVER_DEVICE}`],
    })
    expect(h.storage.idempotentRow(withDevices)).toBeDefined()
    // 少了设备段的那个键必须**不在**库里。它若在，说明键退回到 Base 的四段形状，
    // 而那正是"设备定址不被计入"的定义。
    expect(h.storage.idempotentRow(idempotencyKey(scope))).toBeUndefined()
  })

  it('replays a retry of an operation it already accepted, device check and all', async () => {
    // §9.1 L630：重放要得到**同一个**结果。资格是当下的事实（§4.1.1 L171），所以一次早就
    // 受理过的重试不会因为设备后来被摘掉而变成错误——那会让"重试"变成另一件事，而调用方
    // 手里没有任何东西能区分这两种结局。
    const h = harness()
    const first = await h.call(e2eeRequest())

    const bothGone = deviceDocuments({ [sender.did]: noDevices(sender.did), [receiver.did]: noDevices(receiver.did) })
    const stripped = harness({ storage: h.storage, deviceResolver: inlineDeviceResolver(bothGone) })
    const retry = await stripped.call(e2eeRequest({ id: 'req-e2ee-2' }))

    expect(retry.json?.error).toBeUndefined()
    expect(retry.json?.result).toEqual(first.json?.result)
    expect(h.storage.deliveriesSince(receiver.did, RECEIVER_DEVICE, 0, 10, undefined)).toHaveLength(1)
  })

  it('does not verify the peer devices when the recipient lives elsewhere', async () => {
    // §10.7 L1388 把"验两台设备"写成**目标服务**的 MUST。我们在这里再查一遍，等于拿一份
    // 我们无权解释的清单替对端做主。本用例让双方设备都不在本地清单里，但请求照样转发出去
    // 并拿到对端的答复——所以"受理了"这件事本身就是那个断言的证据。
    const asked: string[] = []
    const bothGone = deviceDocuments({ [sender.did]: noDevices(sender.did), [receiver.did]: noDevices(receiver.did) })
    const h = harness({
      deviceResolver: inlineDeviceResolver(bothGone),
      relay: {
        async forward(_request, targetDid) {
          asked.push(targetDid)
          return {
            kind: 'answered',
            result: {
              accepted: true,
              message_id: 'op-e2ee-1',
              operation_id: 'op-e2ee-1',
              target_did: receiver.did,
              recipient_device_id: RECEIVER_DEVICE,
              accepted_at: NOW.toISOString(),
            },
          }
        },
      },
    })
    const outcome = await h.call(e2eeRequest())

    expect(asked).toEqual([receiver.did])
    expect(outcome.json?.result?.recipient_device_id).toBe(RECEIVER_DEVICE)
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('never runs the P3 payload rule on a v2 body', async () => {
    // §16.1–16.4 的正文在顶层，没有 `body.payload`。让它跑，等于每一条合法的 v2 请求都被
    // 自己的正文校验拒掉——所以这条用例只要"受理了"就是那个断言的证据。
    const h = harness()
    const outcome = await h.call(e2eeRequest({ body: { session_id: 's', recipient_bundle_id: 'b' } }))
    expect(outcome.json?.error).toBeUndefined()
    expect(h.storage.deliveriesSince(receiver.did, RECEIVER_DEVICE, 0, 10, undefined)[0]?.paramsJson).toContain('"session_id":"s"')
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

  // ---- 取件面的可读窗口（2026-10-03 裁定：不删，但只答 30 天内的）-------------------
  //
  // 这一族验的是"**看得见**"与"**还在**"是两件事：窗口把行挡在答案之外，而它一条都没少。
  // 窗口下界按**这次请求自己的** `acceptedAt` 算，所以一个固定的 `NOW` 就够把两侧都钉住。

  /** 一条落在 `receiver` 信箱里、受理时间由调用方指定的行。
   *
   *  绕过受理路直接写：受理路给每一条行盖的都是**这次请求的**时刻（`NOW`），也就是读的
   *  时候会用的那一个，所以"一条过期的行"根本没法从受理路造出来——而"过期的行还在表上"
   *  恰恰是这几条要说的状态。 */
  function seedAt(h: Harness, acceptedAt: string, messageId: string): void {
    h.storage.appendDelivery({
      ownerDid: receiver.did,
      messageId,
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt,
    })
  }

  it('answers only the deliveries the read window still covers', async () => {
    const h = harness()
    seedAt(h, '2026-08-01T00:00:00.000Z', 'long-ago') // NOW 之前 61 天，缺省窗口 30 天
    seedAt(h, '2026-09-30T00:00:00.000Z', 'recent') // NOW 之前 1 天

    const outcome = await asOwner(h, 'sync.delta', { since: 0 })
    const result = outcome.json?.result as { messages: { seq: number }[]; next_since: number }

    // `seq` 1 被挡在外面，而且**不被重新编号**：窗口是"不说"，不是"当作那一条没发生过"。
    expect(result.messages.map((message) => message.seq)).toEqual([2])
    expect(result.next_since).toBe(2)
    // 窗口没删任何东西——表的头还是 2，两条行都在。
    expect(h.storage.headSeq(receiver.did)).toBe(2)
  })

  it('leaves the cursor where the caller put it when the whole log is past the window', async () => {
    const h = harness()
    seedAt(h, '2026-08-01T00:00:00.000Z', 'long-ago')

    const outcome = await asOwner(h, 'sync.delta', { since: 7 })
    // 空页回调用方给的那个 `since`，不是 `headSeq`：窗口是序列的一个**前缀**，把游标推过
    // 客户端没看见的那一段，等于替它宣告"这一段你看过了"——那是服务端在替客户端撒谎。
    expect(outcome.json?.result).toEqual({ messages: [], next_since: 7, has_more: false })
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })

  it('takes the window from the deployment rather than a built-in number', async () => {
    // 一分钟的窗口：`NOW` 之前 1 天的那一条也落在外面了。数值来自 config，验的是
    // `dispatch` 把它交给了 `readDelta`，而不是那里写死了一个 30 天。
    const h = harness({ config: loadConfig({ AGENTX_DELIVERY_READ_WINDOW_MS: '60000' }) })
    seedAt(h, '2026-09-30T00:00:00.000Z', 'recent')

    const outcome = await asOwner(h, 'sync.delta', { since: 0 })
    expect(outcome.json?.result).toEqual({ messages: [], next_since: 0, has_more: false })
  })

  it('refuses a target that is not the signer, with 1014', async () => {
    const h = harness()
    // Reading somebody else's mailbox is not an operation this surface has, so it is a
    // target-binding failure rather than a "you would have seen nothing anyway".
    const outcome = await asOwner(h, 'sync.delta', { since: 0 }, { target: { kind: 'agent', did: second.did } })
    expect(outcome.json?.error?.code).toBe(1014)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })

  it('refuses a group target rather than treating it as one of the four modes', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'sync.delta', { since: 0 }, { target: { kind: 'group', did: receiver.did } })
    expect(outcome.json?.error?.code).toBe(1014)
  })

  it('refuses the direct profile on an extension method, with 1001', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'sync.delta', { since: 0 }, { profile: 'anp.direct.base.v1' })
    expect(outcome.json?.error?.code).toBe(1001)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.unsupported_profile')
  })

  it('requires an origin proof, with the P1 public code', async () => {
    const h = harness()
    const envelope = await signed({
      method: 'sync.delta',
      meta: inboxMeta({ sender_did: receiver.did, target: { kind: 'agent', did: receiver.did } }),
      body: { since: 0 },
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
    const outcome = await asOwner(h, 'sync.delta', { since: 0, 'include-read': true })
    expect(outcome.json?.error?.code).toBe(1003)
  })

  it('refuses a device_id that is not a usable device name', async () => {
    const h = harness()
    const outcome = await asOwner(h, 'sync.delta', { since: 0, device_id: '' })
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
  })

  // ---- 设备维度（P5 §10.7.1 L1407 的读侧）---------------------------------------
  //
  // 订阅路早就按设备筛连接了（`stream/registry.ts` 的 `reaches`）。这两条验的是同一条信箱
  // 的**另一半**：拉取。不筛就是"密文进了正确的设备、又从这一侧泄给整台账号"——比推送那侧
  // 更糟，因为读者把它收下了。筛的只是**投给某台设备的那一条**：账号级的行两台都该看见，
  // 否则这条 MUST 就变成了"多设备账号看不到自己收到的明信片"。

  /** 一条投给 `RECEIVER_DEVICE` 的 v2 密文，落在 `receiver` 的信箱里。 */
  async function seedCipher(h: Harness): Promise<void> {
    const accepted = await h.call(e2eeRequest())
    expect(accepted.json?.error).toBeUndefined()
  }

  it('replays a device-addressed delivery to that device, and only to it', async () => {
    const h = harness()
    await seedCipher(h)

    const mine = await asOwner(h, 'sync.delta', { since: 0, device_id: RECEIVER_DEVICE })
    const rows = (mine.json?.result?.messages ?? []) as { params: { meta: { recipient_device_id?: string } } }[]
    expect(rows).toHaveLength(1)
    expect(rows[0]?.params.meta.recipient_device_id).toBe(RECEIVER_DEVICE)

    // 兄弟设备：同一封信箱、同一个 `since`，什么都拿不到。
    const sibling = await asOwner(h, 'sync.delta', { since: 0, device_id: 'dev-some-other' })
    expect(sibling.json?.result?.messages).toEqual([])
    // 没声明设备的调用方也一样。**缺席不是"没有限制"**——那正是这条 MUST 要堵的口子。
    const undeclared = await asOwner(h, 'sync.delta', { since: 0 })
    expect(undeclared.json?.result?.messages).toEqual([])
  })

  it('keeps a device-addressed message out of a sibling device, without hiding account-level ones', async () => {
    const h = harness()
    // 一条账号级的 P3 消息打底：两种调用方都该看见它，差别只在密文那一条。
    await seed(h)
    await seedCipher(h)

    const ids = async (body: Record<string, unknown>): Promise<string[]> => {
      const outcome = await asOwner(h, 'sync.delta', body)
      const rows = (outcome.json?.result?.messages ?? []) as { params: { meta: { message_id: string } } }[]
      return rows.map((row) => row.params.meta.message_id).sort()
    }

    expect(await ids({ since: 0, device_id: RECEIVER_DEVICE })).toEqual(['msg-1', 'op-e2ee-1'])
    expect(await ids({ since: 0, device_id: 'dev-some-other' })).toEqual(['msg-1'])
    expect(await ids({ since: 0 })).toEqual(['msg-1'])
  })
})

// ---- 通讯录扩展面（TODO6 §3）---------------------------------------------------
//
// 与取件面同形：自己给自己签名、`target.did == sender_did`。这一层的规矩不是规范给的
// （规范里没有"备注"），是 TODO6 §3 定的，而它要挡住的具体事故有名字——换钥后备注消失。
// 所以下面那条"同一主体、两把钥"的用例才是这一族里最重要的，其余是它的边界。

/** 一次自签名的通讯录调用。`target` 默认是签名者自己，只有"地址绑定"那几条要改成别人。 */
async function selfCall(
  h: Harness,
  signer: AnpSigningIdentity,
  method: string,
  body: Record<string, unknown>,
  overrides: Partial<AnpMeta> = {},
): Promise<Outcome> {
  return h.call(
    await signed({
      method,
      meta: {
        profile: 'x_agentx.contacts.v1',
        security_profile: 'transport-protected',
        sender_did: signer.did,
        target: { kind: 'agent', did: signer.did },
        operation_id: `op-${method}`,
        ...overrides,
      },
      body,
      signer,
    }),
  )
}

describe('the address book extension surface (TODO6 §3)', () => {
  it('stores a row and hands it back with the subject it derived', async () => {
    const h = harness()
    const outcome = await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' })

    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toEqual({
      contact: {
        subject: subjectOf(second.did),
        did: second.did,
        remark: 'Bob',
        created_at: NOW.toISOString(),
        updated_at: NOW.toISOString(),
      },
      created: true,
    })

    const listed = await selfCall(h, receiver, 'contacts.list', {})
    expect(listed.json?.result?.contacts).toHaveLength(1)
  })

  it('keeps the first created_at and moves updated_at when the same subject is put again', async () => {
    const h = harness()
    await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' }, { operation_id: 'op-p1' })
    const again = await selfCall(
      h,
      receiver,
      'contacts.put',
      { did: second.did, remark: 'Bobby' },
      { operation_id: 'op-p2' },
    )

    // `created` 是给人的一句话（"加好了" vs "更新了"），不是存储层的分工；`created_at`
    // 由存储层在冲突时保留，所以它还是第一次那个瞬间。
    expect(again.json?.result?.created).toBe(false)
    expect((again.json?.result?.contact as { created_at: string }).created_at).toBe(NOW.toISOString())
    expect((again.json?.result?.contact as { remark: string }).remark).toBe('Bobby')
  })

  it('recognises the same person across a key change, because the key is the subject', async () => {
    const h = harness()
    // `second` 与 `successor` 同域同路径、不同一把钥——`did update` 之后的样子。挂在
    // `did` 上的备注会在这一刻变成孤儿行；挂在 subject 上的两行合成一行。
    await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' }, { operation_id: 'op-p1' })
    const after = await selfCall(
      h,
      receiver,
      'contacts.put',
      { did: successor.did, remark: 'Bob' },
      { operation_id: 'op-p2' },
    )

    expect(after.json?.result?.created).toBe(false)
    const listed = await selfCall(h, receiver, 'contacts.list', {})
    const rows = listed.json?.result?.contacts as { did: string; subject: string }[]
    expect(rows).toHaveLength(1)
    expect(rows[0]?.did).toBe(successor.did)
    expect(rows[0]?.subject).toBe(subjectOf(second.did))
  })

  it('clears a remark by putting the row without one', async () => {
    const h = harness()
    await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' }, { operation_id: 'op-p1' })
    const cleared = await selfCall(h, receiver, 'contacts.put', { did: second.did }, { operation_id: 'op-p2' })

    // 缺席报 `null` 而不是省略这个键：省略会让"没有备注"和"这版服务端不返回备注"长得一样。
    expect(cleared.json?.result?.contact).toMatchObject({ remark: null })
  })

  it('removes by subject and says whether there was anything to remove', async () => {
    const h = harness()
    await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' })

    const removed = await selfCall(h, receiver, 'contacts.remove', { subject: subjectOf(second.did) })
    expect(removed.json?.result).toEqual({ subject: subjectOf(second.did), removed: true })

    const again = await selfCall(h, receiver, 'contacts.remove', { subject: subjectOf(second.did) }, {
      operation_id: 'op-again',
    })
    expect(again.json?.result?.removed).toBe(false)
  })

  it('keeps one owner out of another owner book', async () => {
    const h = harness()
    await selfCall(h, receiver, 'contacts.put', { did: second.did, remark: 'Bob' })

    // 同一本书、同一个被备注的人，换个签名者就是另一本。`owner_did` 来自验过签的
    // `sender_did`，不是请求里某个可改的字段。
    const other = await selfCall(h, sender, 'contacts.list', {})
    expect(other.json?.result?.contacts).toEqual([])
  })

  it('refuses a target that is not the signer, with 1014', async () => {
    const h = harness()
    // 往别人的通讯录里写备注不是这个面有的操作，所以是地址绑定失败，不是"反正你也没写进去"。
    const outcome = await selfCall(
      h,
      receiver,
      'contacts.put',
      { did: second.did },
      { target: { kind: 'agent', did: second.did } },
    )
    expect(outcome.json?.error?.code).toBe(1014)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })

  it('refuses a body field it does not know, and an empty did', async () => {
    const h = harness()
    expect((await selfCall(h, receiver, 'contacts.list', { extra: 1 })).json?.error?.code).toBe(1003)

    const empty = await selfCall(h, receiver, 'contacts.put', { did: '' }, { operation_id: 'op-empty' })
    expect(empty.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
  })

  // —— 写入路径 ②：收到消息时把发件人落一行（TODO6 §3.3） --------------------------

  it('files the sender of an arriving message, with no remark', async () => {
    const h = harness()
    // 这封是 `sender` 发给 `receiver` 的（`signed()` 的默认形状）。
    const delivered = await h.call(await signed())
    expect(delivered.json?.result?.accepted).toBe(true)

    // 收件人的通讯录里多了一个人，且**没有名字**——"认识一下"与"起个名字"是两件事。
    const listed = await selfCall(h, receiver, 'contacts.list', {})
    expect(listed.json?.result?.contacts).toEqual([
      {
        subject: subjectOf(sender.did),
        did: sender.did,
        remark: null,
        created_at: NOW.toISOString(),
        updated_at: NOW.toISOString(),
      },
    ])
  })

  it('does not let an arriving message touch the name I gave the sender', async () => {
    // 这一条是 ② 的整个理由。`contacts.put` 的线上规则是"缺字段即清空"，而"收到一条消息"
    // 对名字没有说任何话——照搬那条规则，就会在被我起过名的人下次来信时把名字抹掉，
    // 而那正是"发错人"的另一种形态：名字没了之后，`msg send --to Alice` 就找不到人。
    const h = harness()
    await selfCall(h, receiver, 'contacts.put', { did: sender.did, remark: 'Alice' })

    await h.call(await signed())

    const listed = await selfCall(h, receiver, 'contacts.list', {})
    const rows = listed.json?.result?.contacts as { did: string; remark: string }[]
    expect(rows).toHaveLength(1)
    expect(rows[0]?.remark).toBe('Alice')
  })

  it('keeps one row as the same peer writes again', async () => {
    const h = harness()
    await h.call(await signed({ meta: meta({ operation_id: 'op-a', message_id: 'msg-a' }) }))
    await h.call(await signed({ meta: meta({ operation_id: 'op-b', message_id: 'msg-b' }) }))

    // 键是 subject，所以第二封落回同一行，不是第二个 Alice。
    const listed = await selfCall(h, receiver, 'contacts.list', {})
    expect(listed.json?.result?.contacts).toHaveLength(1)
  })
})

// ---- 群备注扩展面（TODO6 §4.2）-------------------------------------------------
//
// 通讯录那半的另一半，形状与它逐条同构；这里要咬住的是**两者不混**——一本是"我能
// `msg send` 给谁"，一本是"我给哪个群起了什么名"。用户裁定这两套名字不能互相污染，
// 所以下面那条"两个书架"的用例是这一族里最重要的，其余是它的边界。

describe('the group-remark extension surface (TODO6 §4.2)', () => {
  /** 一次自签名的群备注调用。Profile 是 `x_agentx.group_remarks.v1`，与 `selfCall` 只差这一处。 */
  async function remarkCall(
    h: Harness,
    signer: AnpSigningIdentity,
    method: string,
    body: Record<string, unknown>,
    overrides: Partial<AnpMeta> = {},
  ): Promise<Outcome> {
    return h.call(
      await signed({
        method,
        meta: {
          profile: 'x_agentx.group_remarks.v1',
          security_profile: 'transport-protected',
          sender_did: signer.did,
          target: { kind: 'agent', did: signer.did },
          operation_id: `op-${method}`,
          ...overrides,
        },
        body,
        signer,
      }),
    )
  }

  it('stores a name for a group and hands the row back', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    const outcome = await remarkCall(h, receiver, 'group_remarks.put', {
      group_did: groupDid,
      remark: 'Team',
    })

    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toEqual({
      group_remark: {
        group_did: groupDid,
        remark: 'Team',
        created_at: NOW.toISOString(),
        updated_at: NOW.toISOString(),
      },
      created: true,
    })

    const listed = await remarkCall(h, receiver, 'group_remarks.list', {})
    expect(listed.json?.result?.group_remarks).toHaveLength(1)
  })

  it('renames a group in place, keeping the first created_at', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    await remarkCall(h, receiver, 'group_remarks.put', { group_did: groupDid, remark: 'Team' })
    const again = await remarkCall(
      h,
      receiver,
      'group_remarks.put',
      { group_did: groupDid, remark: 'Work' },
      { operation_id: 'op-again' },
    )

    // 键是 `group_did`，所以改的是同一行，不是第二个名字。
    expect(again.json?.result?.created).toBe(false)
    expect(again.json?.result?.group_remark).toMatchObject({
      remark: 'Work',
      created_at: NOW.toISOString(),
    })
    const listed = await remarkCall(h, receiver, 'group_remarks.list', {})
    expect(listed.json?.result?.group_remarks).toHaveLength(1)
  })

  it('lets a group live elsewhere: the name is mine, not the group host business', async () => {
    // 本服务**没有**这个群，名字照样存得下——群在 P8 的跨域那一侧时，这正是一本本地名册
    // 该有的行为。要"先问群在不在"就得先去它的 Host 问一次，而那是 `group info` 的事，
    // 不是起名的事。
    const h = harness()
    const outcome = await remarkCall(h, receiver, 'group_remarks.put', {
      group_did: 'did:web:groups.example:g:REMOTE',
      remark: 'Their team',
    })
    expect(outcome.json?.result?.created).toBe(true)
  })

  it('keeps the two books apart: a group name is not a contact, and a contact is not a group name', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    // `contacts` 那一本记的是**能 `msg send` 的人**；群是 `group` 寻址，另一种东西。并成
    // 一本会让 `contacts resolve <名字>` 返回一个群 DID，再让 `msg send --to` 走上一条
    // 通往群的 `direct.send`——而群读不了那条消息。
    await remarkCall(h, receiver, 'group_remarks.put', { group_did: groupDid, remark: 'Team' })
    await selfCall(h, receiver, 'contacts.put', { did: groupDid, remark: 'Team' })

    const groups = await remarkCall(h, receiver, 'group_remarks.list', {})
    expect(groups.json?.result?.group_remarks).toHaveLength(1)
    const people = await selfCall(h, receiver, 'contacts.list', {})
    expect(people.json?.result?.contacts).toHaveLength(1)

    // 删掉群名，人的那一行不动（两条路走的是两张表，不是一行的两种写法）。
    await remarkCall(h, receiver, 'group_remarks.remove', { group_did: groupDid })
    const after = await selfCall(h, receiver, 'contacts.list', {})
    expect(after.json?.result?.contacts).toHaveLength(1)
  })

  it('keeps one owner out of another owner group book', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    await remarkCall(h, receiver, 'group_remarks.put', { group_did: groupDid, remark: 'Team' })

    // `owner_did` 来自验过签的 `sender_did`，不是请求里某个可改的字段。
    const other = await remarkCall(h, sender, 'group_remarks.list', {})
    expect(other.json?.result?.group_remarks).toEqual([])
  })

  it('removes by group did and says whether there was anything to remove', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    await remarkCall(h, receiver, 'group_remarks.put', { group_did: groupDid, remark: 'Team' })

    const removed = await remarkCall(h, receiver, 'group_remarks.remove', { group_did: groupDid })
    expect(removed.json?.result).toEqual({ group_did: groupDid, removed: true })

    const again = await remarkCall(
      h,
      receiver,
      'group_remarks.remove',
      { group_did: groupDid },
      { operation_id: 'op-again' },
    )
    expect(again.json?.result?.removed).toBe(false)
  })

  it('refuses a target that is not the signer, with 1014', async () => {
    const h = harness()
    const outcome = await remarkCall(
      h,
      receiver,
      'group_remarks.put',
      { group_did: `${SERVICE_DID}:g:x`, remark: 'Team' },
      { target: { kind: 'agent', did: second.did } },
    )
    expect(outcome.json?.error?.code).toBe(1014)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.invalid_target_binding')
  })

  it('refuses a body field it does not know, an empty group did, and a put without a remark', async () => {
    const h = harness()
    expect((await remarkCall(h, receiver, 'group_remarks.list', { extra: 1 })).json?.error?.code).toBe(1003)

    const empty = await remarkCall(h, receiver, 'group_remarks.put', { group_did: '', remark: 'Team' })
    expect(empty.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')

    // 与 `contacts.put` 不同：那边缺席的 `remark` 是"没有名字"这个正常状态，这边缺席就是
    // 什么都没说——这一族没有"先记下群、还没起名"的路径。
    const unnamed = await remarkCall(
      h,
      receiver,
      'group_remarks.put',
      { group_did: `${SERVICE_DID}:g:x` },
      { operation_id: 'op-unnamed' },
    )
    expect(unnamed.json?.error?.data?.anp_code).toBe('anp.invalid_params_shape')
  })

  it('replays a put under the same operation id instead of naming the group twice', async () => {
    const h = harness()
    const groupDid = await mintGroup(h)
    const body = { group_did: groupDid, remark: 'Team' }
    await remarkCall(h, receiver, 'group_remarks.put', body, { operation_id: 'op-p1' })
    const replay = await remarkCall(h, receiver, 'group_remarks.put', body, { operation_id: 'op-p1' })

    // 台账里的那份答复原样还回来。这一条真正咬住的是 `targetScope` 接上了：没有它，第二次
    // 会**真的执行**一遍，`created` 就会是 `false`（那一行已经在了）。
    expect(replay.json?.result?.created).toBe(true)
    const listed = await remarkCall(h, receiver, 'group_remarks.list', {})
    expect(listed.json?.result?.group_remarks).toHaveLength(1)
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
        'anp.direct.e2ee.v2',
        'anp.group.base.v2',
      ],
      supported_security_profiles: ['direct-e2ee', 'group-e2ee', 'transport-protected'],
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
      'application/anp-direct-init+json',
      'application/anp-direct-cipher+json',
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

// B1b-A4 —— 群族的出站接线。两批分开验，因为它们的 `meta.target` 不是一回事：
// `group.create` 那一批指着一个 `serviceDid`（与附件同形），其余十一条指着一个 `group_did`。
//
// 这里验的是**路由**，不是转发本身（那是 `federation/forward.test.ts` 的事）：谁被问了、
// 什么被原样传回去，以及——本轮新加的那一处判据——住在**自己命名空间**里的群会不会被误
// 当成对端送出去。
describe('a group call whose group lives elsewhere (P8 §5.4)', () => {
  const REMOTE_GROUP = 'did:web:groups.example:g:REMOTE'
  const PEER_SERVICE = 'did:web:groups.example'

  it('forwards a group.send to the remote group, and files nothing of its own', async () => {
    const { relay, asked } = recording({
      kind: 'answered',
      result: { accepted: true, message_id: 'm-1', operation_id: 'op-send', seq: 4 },
    })
    const h = harness({ relay })
    const outcome = await h.call(
      await signed({
        method: 'group.send',
        meta: groupMeta({
          target: { kind: 'group', did: REMOTE_GROUP },
          operation_id: 'op-send',
          message_id: 'm-1',
          content_type: 'text/plain',
        }),
        body: { text: 'hello group' },
      }),
    )

    expect(asked).toEqual([REMOTE_GROUP])
    expect(outcome.json?.result?.seq).toBe(4)
    // 群不在本服务上，所以本地一个群行都不该有：落了就是替对端记了一笔它自己的账。
    expect(h.storage.group(REMOTE_GROUP)).toBeUndefined()
  })

  it('returns the peer refusal unchanged', async () => {
    const { relay } = recording({
      kind: 'refused',
      rejection: { code: 3000, anpCode: 'group.not_member', retryable: false, message: 'not a member' },
    })
    const h = harness({ relay })
    const outcome = await h.call(
      await signed({
        method: 'group.get_info',
        meta: groupMeta({ target: { kind: 'group', did: REMOTE_GROUP } }),
        body: {},
      }),
    )

    expect(outcome.json?.error?.code).toBe(3000)
    expect(outcome.json?.error?.data?.anp_code).toBe('group.not_member')
  })

  it('keeps a group in its own namespace local, without asking the network', async () => {
    // 本服务亲手建的群住在 `serviceDid:g:<id>` 里，它的文档也由**本服务**发布（groups.md
    // §2.2/§2.3）——"入口在哪"是本地常量。**这一档不是优化**：放它出站，那趟解析要么被
    // `AGENTX_ALLOWED_DID_HOSTS` 拒（那份清单写的是对端域，不写自己），要么要求本服务的
    // `publicUrl` 是 https，于是一个自家的群会在自己的 `group.send` 上报 1012。
    const { relay, asked } = recording({ kind: 'answered', result: { accepted: true, seq: 99 } })
    const h = harness({ relay })
    const groupDid = await mintGroup(h)

    const outcome = await h.call(
      await signed({
        method: 'group.send',
        meta: groupMeta({
          target: { kind: 'group', did: groupDid },
          sender_did: second.did,
          operation_id: 'op-send',
          message_id: 'm-1',
          content_type: 'text/plain',
        }),
        body: { text: 'hello' },
        signer: second,
      }),
    )

    expect(asked).toEqual([])
    // 本地受理而不是转发：`second` 不是成员，所以答案是本地那一关的 3000，而不是对端那份。
    expect(outcome.json?.error?.code).toBe(3000)
    expect(outcome.json?.error?.data?.anp_code).toBe('group.not_member')
  })

  it('forwards a group.create whose target is another service (§8.1.2)', async () => {
    // 这一批的目标是一个 `serviceDid`，与 `attachment.*` 完全同形——连"目标写着自己就本地办"
    // 那次短路都共用（`relayFor` 里那次 `serviceDid` 比较）。
    const { relay, asked } = recording({
      kind: 'answered',
      result: { group_did: `${PEER_SERVICE}:g:THEIRS`, group_receipt: { subject_method: 'group.create' } },
    })
    const h = harness({ relay })
    const outcome = await h.call(
      await signed({
        method: 'group.create',
        meta: groupMeta({ target: { kind: 'service', did: PEER_SERVICE } }),
        body: { group_policy: GROUP_POLICY },
      }),
    )

    expect(asked).toEqual([PEER_SERVICE])
    expect(outcome.json?.result?.group_did).toBe(`${PEER_SERVICE}:g:THEIRS`)
  })
})

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

// A3c —— P4 §8.12 的两条触发路里**请求触发**的那一条。
//
// 这里测的是**接线**：一次来自"可能是某个成员后继"的调用，会不会在它自己被受理之前先把名册
// 补上、把 `member-did-updated` 排出去，以及哪些情形**不**该补。转移链本身的判别在 core 的
// 用例里，所以这里的解析器交出去的是一份已经判好的结果。
describe('adopting a member DID change on the request path (§8.12)', () => {
  /** 一份"已经判好的"链：`previousDid` 走到了 `currentDid`。 */
  function chainTo(currentDid: string, assurance: DidChainAssurance = 'verified'): DidChainResolver {
    return async (did: string): Promise<DidChain> => ({
      did,
      subject: subjectOf(currentDid),
      stableSubjectId: stableSubjectId(currentDid),
      currentDid,
      superseded: currentDid !== did,
      assurance,
      document: {},
      docUrl: `https://peer.example/${currentDid}`,
      hops: [],
    })
  }

  async function addMember(h: Harness, groupDid: string, memberDid: string, opId: string, role?: string): Promise<void> {
    const outcome = await h.call(
      await signed({
        method: 'group.add',
        meta: groupMeta({ target: { kind: 'group', did: groupDid }, operation_id: opId }),
        body: { member_did: memberDid, ...(role !== undefined ? { role } : {}) },
      }),
    )
    if (outcome.json?.error !== undefined) throw new Error(`group.add failed: ${JSON.stringify(outcome.json)}`)
  }

  /** 一个成员收到的 `member-did-updated` 事件正文（§8.11 的通知里那一份）。 */
  function didUpdateEvents(h: Harness, recipient: string): Record<string, unknown>[] {
    return h.storage
      .deliveriesSince(recipient, '', 0, 100, undefined)
      .filter((row) => row.method === 'group.state_changed')
      .map((row) => (JSON.parse(row.paramsJson) as { body: Record<string, unknown> }).body)
      .filter((body) => body.event_type === 'member-did-updated')
  }

  /** 从 `successor` 发一次群内调用。`method` 决定它走的是哪条触发条件。 */
  async function callAsSuccessor(
    h: Harness,
    groupDid: string,
    method: string,
    body: Record<string, unknown>,
    extra: Partial<AnpMeta> = {},
  ): Promise<Outcome> {
    return h.call(
      await signed({
        method,
        meta: groupMeta({ target: { kind: 'group', did: groupDid }, sender_did: successor.did, ...extra }),
        body,
        signer: successor,
      }),
    )
  }

  it('completes the update before authorizing the request, and keeps the role', async () => {
    // §8.12 L946：新 DID 发起一次调用时，Host **先**把这次更新做完、排好 `member-did-updated`，
    // **然后**才按**保留下来的角色**受理。这里让被换掉的那个 DID 是 admin，再让后继做一件只有
    // admin 才做得成的事——角色没保住的话，这次调用会撞上 3003。
    const h = harness({ chainResolver: chainTo(successor.did) })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1', 'admin')
    expect(h.storage.groupMember(groupDid, second.did)?.role).toBe('admin')
    const before = h.storage.group(groupDid)?.groupStateVersion ?? 0

    const outcome = await callAsSuccessor(
      h,
      groupDid,
      'group.update_profile',
      { group_profile_patch: { name: 'renamed' } },
      { operation_id: 'op-profile-1' },
    )

    expect(outcome.json?.error).toBeUndefined()
    // 名册上只有一条记录，而且挂在**新** DID 上，角色与加入时间原样（§8.12 L958–L961）。
    expect(h.storage.groupMember(groupDid, second.did)).toBeUndefined()
    const moved = h.storage.groupMember(groupDid, successor.did)
    expect(moved?.membershipStatus).toBe('active')
    expect(moved?.role).toBe('admin')
    expect(h.storage.countActiveMembers(groupDid)).toBe(2)
    // §7.10.2 L590：事件正文必须带 `previous_subject_did` 与 `subject_did`。
    const events = didUpdateEvents(h, sender.did)
    // 两次状态变更：先是 §8.12 的改名那一步，然后才是这次调用自己被受理。
    // 事件里的 `group_state_version` 记的是**前**一步，也就是改名那一步。
    expect(events[0]?.group_state_version).toBe(String(before + 1))
    expect(h.storage.group(groupDid)?.groupStateVersion).toBe(before + 2)
    // 这次调用真的**按保留的角色**受理了，而不只是名册改对了。
    expect(JSON.parse(h.storage.group(groupDid)?.groupProfileJson ?? '{}').name).toBe('renamed')

    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      event_type: 'member-did-updated',
      subject_method: 'group.member_did_update',
      actor_did: SERVICE_DID,
      previous_subject_did: second.did,
      subject_did: successor.did,
      membership_status: 'active',
    })
  })

  it('converges: a second call from the same DID does not update anything again', async () => {
    // §8.12 L964：操作标识是那三个值的确定性摘要，所以三条触发路**幂等收敛**。第二条来自同一
    // 个 DID 的调用看到的名册已经是它自己了，不该再落一个事件、再推一次版本号。
    const h = harness({ chainResolver: chainTo(successor.did) })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1')

    await callAsSuccessor(h, groupDid, 'group.send', { text: 'first' }, {
      operation_id: 'op-send-1',
      message_id: 'm-1',
      content_type: 'text/plain',
    })
    const after = h.storage.group(groupDid)?.groupStateVersion

    const again = await callAsSuccessor(h, groupDid, 'group.send', { text: 'second' }, {
      operation_id: 'op-send-2',
      message_id: 'm-2',
      content_type: 'text/plain',
    })

    expect(again.json?.error).toBeUndefined()
    expect(h.storage.group(groupDid)?.groupStateVersion).toBe(after)
    expect(didUpdateEvents(h, sender.did)).toHaveLength(1)
  })

  it('refuses a provider_asserted chain (the ruling is 甲)', async () => {
    // 规范把这一档写成"由自己的业务策略决定"，本服务的选择是不收。它 MUST NOT 被悄悄接受：
    // 那样一来换个 DID 就只需要一个上游供应商的一句话。
    const h = harness({ chainResolver: chainTo(successor.did, 'provider_asserted') })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1')

    const outcome = await callAsSuccessor(h, groupDid, 'group.send', { text: 'hi' }, {
      operation_id: 'op-send-1',
      message_id: 'm-1',
      content_type: 'text/plain',
    })

    expect(outcome.json?.error?.code).toBe(3000)
    expect(h.storage.groupMember(groupDid, second.did)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(groupDid, successor.did)).toBeUndefined()
    expect(didUpdateEvents(h, sender.did)).toHaveLength(0)
    expect(h.logs.some((line) => line.includes('assurance provider_asserted'))).toBe(true)
  })

  it('does not adopt a chain that ends at somebody else', async () => {
    // 前身确实换了 DID，但换成的是别人。这次调用不是那个后继，名册不动。
    const h = harness({ chainResolver: chainTo(receiver.did) })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1')

    const outcome = await callAsSuccessor(h, groupDid, 'group.send', { text: 'hi' }, {
      operation_id: 'op-send-1',
      message_id: 'm-1',
      content_type: 'text/plain',
    })

    expect(outcome.json?.error?.code).toBe(3000)
    expect(h.storage.groupMember(groupDid, second.did)?.membershipStatus).toBe('active')
  })

  it('refuses to guess when two active members share a stable subject path', async () => {
    // §8.12 第 4 条的 "no candidate ambiguity"：两行 active 成员共享一个稳定主体路径时，本服务
    // 无从判断来的是哪一行的后继。不猜——不采纳，这次调用落回它本来的拒绝。
    const rival = createAnpIdentity('second.example')
    const h = harness({ chainResolver: chainTo(successor.did) })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1')
    await addMember(h, groupDid, rival.did, 'op-add-2')

    const outcome = await callAsSuccessor(h, groupDid, 'group.send', { text: 'hi' }, {
      operation_id: 'op-send-1',
      message_id: 'm-1',
      content_type: 'text/plain',
    })

    expect(outcome.json?.error?.code).toBe(3000)
    expect(h.storage.groupMember(groupDid, second.did)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(groupDid, rival.did)?.membershipStatus).toBe('active')
    expect(h.logs.some((line) => line.includes('candidate predecessors'))).toBe(true)
  })

  it('adopts ahead of a private group.get_info but not ahead of a public one', async () => {
    // §8.12 L946 把 `group.get_info` 单列，而它是**有条件的**：公开群的资料快照谁都能读，换没换
    // DID 与这次读取无关；私有群才要求调用方是成员，于是新 DID 得先入册。
    const privateGroup = await (async (): Promise<string> => {
      const h = harness({ chainResolver: chainTo(successor.did) })
      const groupDid = await mintGroup(h)
      await addMember(h, groupDid, second.did, 'op-add-1')
      const outcome = await callAsSuccessor(h, groupDid, 'group.get_info', {})
      expect(outcome.json?.error).toBeUndefined()
      expect(h.storage.groupMember(groupDid, successor.did)?.membershipStatus).toBe('active')
      return groupDid
    })()
    expect(typeof privateGroup).toBe('string')

    const h = harness({ chainResolver: chainTo(successor.did) })
    const publicDid = await mintGroup(h, { discoverability: 'public' })
    await addMember(h, publicDid, second.did, 'op-add-1')
    const outcome = await callAsSuccessor(h, publicDid, 'group.get_info', {})

    expect(outcome.json?.error).toBeUndefined()
    // 读到了资料快照，但名册一行没动——公开群这条路不该顺手改成员状态。
    expect(h.storage.groupMember(publicDid, second.did)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(publicDid, successor.did)).toBeUndefined()
  })

  it('leaves group.join and group.remove out of the trigger surface', async () => {
    // 规范点名的只有五个方法。`group.remove` 要的是调用方**已有**的权限，`group.join` 的目标
    // 是调用方自己还不在名册里的情形——两者都不该让这个 DID 顺路被认成别人的后继。
    const h = harness({ chainResolver: chainTo(successor.did) })
    const groupDid = await mintGroup(h)
    await addMember(h, groupDid, second.did, 'op-add-1')

    const outcome = await callAsSuccessor(h, groupDid, 'group.remove', { member_did: second.did }, {
      operation_id: 'op-remove-1',
    })

    expect(outcome.json?.error?.code).toBe(3000)
    expect(h.storage.groupMember(groupDid, successor.did)).toBeUndefined()
  })
})

// C11 —— 外层身份接进受理路径。
//
// 这里测的不是八步本身（`federation/outer.test.ts` 逐个覆盖了），而是**接线**：它跑在
// 信封之后、JSON-RPC 之前，失败形态是 HTTP 401/503 而不是 JSON-RPC 错误，以及它只在
// 这次调用真的是一次 HTTP 请求时才跑。
describe('the outer identity on the request path', () => {
  async function envelopeText(options: Parameters<typeof signed>[0] = {}): Promise<string> {
    return JSON.stringify(await signed(options))
  }

  it('accepts a cross-domain request whose outer signature verifies', async () => {
    const h = harness()
    const text = await envelopeText()
    const outcome = await h.post(text, await outerHeaders(text))
    expect(outcome.status).toBe(200)
    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toBeDefined()
  })

  it('answers 401 with a WWW-Authenticate challenge, and no id in the body', async () => {
    // §2.4：这一步跑在 JSON-RPC 之前，所以**没有 `id` 可答**——正文是 §4.2.2 L377–383 的
    // 那个镜像形状，不是一份 JSON-RPC 响应。
    const h = harness()
    const text = await envelopeText()
    const outcome = await h.post(text, await outerHeaders(text, { signer: impostor }))
    expect(outcome.status).toBe(401)
    expect(outcome.headers['www-authenticate']).toBe('DIDWba realm="127.0.0.1", error="forbidden_did"')
    expect(outcome.json).toEqual({ code: 401, error: 'forbidden_did' })
    expect(outcome.json).not.toHaveProperty('id')
    // 外层拒了就没有业务动作发生。
    expect(h.storage.headSeq(receiver.did)).toBe(0)
  })

  it('refuses a replayed nonce on the second delivery of the same request', async () => {
    const h = harness()
    const text = await envelopeText()
    const headers = await outerHeaders(text, { nonce: 'replayed' })
    expect((await h.post(text, headers)).status).toBe(200)
    const again = await h.post(text, headers)
    expect(again.status).toBe(401)
    expect(again.json).toEqual({ code: 401, error: 'invalid_nonce' })
  })

  it('answers 503 when our own nonce store is down, and keeps the internal word off the wire', async () => {
    // `unverifiable` 是"我们得不出结论"，回 401 会把对端送去重签一份本来没问题的东西；
    // ANP-02 §3.2.4.1 的九个 `error` 值里也没有它，所以它连挑战头都不该出现。
    const h = harness({
      nonceStore: {
        consume(): never {
          throw new Error('nonce store is down')
        },
      },
    })
    const text = await envelopeText()
    const outcome = await h.post(text, await outerHeaders(text))
    expect(outcome.status).toBe(503)
    expect(outcome.json).toEqual({ code: 503 })
    expect(outcome.headers['www-authenticate']).toBeUndefined()
  })

  it('stands down when the call did not arrive as an HTTP request', async () => {
    // 流式那条路的帧就是这样：它借了升级请求的头，但帧本身不是 HTTP 请求，`@method` /
    // `@target-uri` 无从谈起。头里带着一份**属于别人**的签名，这一层也不该看它。
    const h = harness()
    const text = await envelopeText()
    const outcome = await h.call(text)
    expect(outcome.status).toBe(200)
    expect(outcome.json?.result).toBeDefined()
  })

  it('refuses a cross-domain notification at the outer layer instead of just not answering it', async () => {
    // 顺序的全部意义（§2.4）：通知本来就没有响应，但外层没过时对端要拿到 401，
    // 而不是一个"没有响应"。
    const h = harness()
    const { id, ...withoutId } = await signed()
    void id
    const text = JSON.stringify(withoutId)
    const outcome = await h.post(text, await outerHeaders(text, { signer: impostor }))
    expect(outcome.status).toBe(401)
    expect(outcome.headers['www-authenticate']).toContain('error="forbidden_did"')
  })
})

// TODO7 §3 第 4 条 —— 换钥之后那批投递的归属（用户 2026-10-03 裁定：
// 「服务端换钥时把投递挪到新 DID 名下」）。
//
// 这里测的是**触发与采信**：一次自址的 `sync.delta` 会不会把旧 DID 名下的信箱搬到调用方
// 这个新 DID 上、什么时候**不**搬，以及水位线怎么维护。搬家本身（序号、游标、设备队列）
// 在 `storage/sqlite.test.ts` 里量；转移链的判别在 core 的用例里，所以解析器交给这里的
// 是一份**已经判好的**结果。
describe('moving an account mailbox to its new DID on the request path (TODO7 §3)', () => {
  type Resolution = { currentDid: string; assurance?: DidChainAssurance } | 'throws'

  /** 一份"已经判好的"链，外加它被问过几次——水位线跟上之后就不该再解析。 */
  function chainRecorder(
    answers: Record<string, Resolution>,
    calls: string[],
  ): DidChainResolver {
    return async (did: string): Promise<DidChain> => {
      calls.push(did)
      const answer = answers[did]
      if (answer === undefined || answer === 'throws') throw new Error(`no chain for ${did}`)
      return {
        did,
        subject: subjectOf(answer.currentDid),
        stableSubjectId: stableSubjectId(answer.currentDid),
        currentDid: answer.currentDid,
        superseded: answer.currentDid !== did,
        assurance: answer.assurance ?? 'verified',
        document: {},
        docUrl: `https://peer.example/${answer.currentDid}`,
        hops: [],
      }
    }
  }

  /** 一次以 `did` 自己身份、对自己信箱发起的读。 */
  async function readAs(
    h: Harness,
    did: AnpSigningIdentity,
    body: Record<string, unknown> = { since: 0 },
  ): Promise<Outcome> {
    return h.call(
      await signed({
        method: 'sync.delta',
        meta: inboxMeta({ sender_did: did.did, target: { kind: 'agent', did: did.did } }),
        body,
        signer: did,
      }),
    )
  }

  /** `receiver` 名下的投递，绕开受理路直接写（不需要第二台服务就有一条"旧信"）。 */
  function seedFor(h: Harness, ownerDid: string, messageId: string): void {
    h.storage.appendDelivery({
      ownerDid,
      messageId,
      method: 'direct.incoming',
      paramsJson: JSON.stringify({ body: { message_id: messageId } }),
      acceptedAt: NOW.toISOString(),
    })
  }

  function messageIds(outcome: Outcome): unknown[] {
    const messages = outcome.json?.result?.messages as { params: { body: { message_id?: string } } }[] | undefined
    return (messages ?? []).map((frame) => frame.params.body.message_id)
  }

  it('moves the old DID\'s mail onto the new DID and answers it in the same call', async () => {
    // 这条就是那个"退出 0 的空搬"的反面：搬之前 `sync.delta` 在新 DID 下一行都答不出，
    // 搬之后同一次调用就把它交出来了。
    const calls: string[] = []
    const h = harness({ chainResolver: chainRecorder({ [receiver.did]: { currentDid: receiverRotated.did } }, calls) })
    // 水位线先落在旧 DID 上——它是上一次这个账号出面时记下的。没有这一步就没有"前身"可谈。
    h.storage.rememberAccountDid(subjectOf(receiverRotated.did), receiver.did, NOW.toISOString())
    seedFor(h, receiver.did, 'old-mail')

    const outcome = await readAs(h, receiverRotated)

    expect(messageIds(outcome)).toEqual(['old-mail'])
    // 行没有删，只是换了名字；而且水位线跟上了，所以第二次读不再解析。
    expect(h.storage.headSeq(receiver.did)).toBe(0)
    expect(h.storage.headSeq(receiverRotated.did)).toBe(1)
    expect(h.storage.accountDid(subjectOf(receiverRotated.did))).toBe(receiverRotated.did)
    await readAs(h, receiverRotated)
    expect(calls).toEqual([receiver.did])
  })

  it('records the watermark on a subject it has never seen, and does not resolve', async () => {
    const calls: string[] = []
    const h = harness({ chainResolver: chainRecorder({}, calls) })
    seedFor(h, receiver.did, 'old-mail')

    // 第一次见这个主体：没有前身可谈，只记下水印，也不解析（那行信本来就在它名下）。
    const outcome = await readAs(h, receiver)
    expect(messageIds(outcome)).toEqual(['old-mail'])
    expect(h.storage.accountDid(subjectOf(receiver.did))).toBe(receiver.did)
    expect(calls).toEqual([])
  })

  it('leaves the mail where it is when the chain does not reach the caller', async () => {
    // 链上那个旧 DID 有后继，但**不是**眼前这个 DID——两个人在用同一个主体路径，本服务
    // 无从判断谁是谁。不猜：一行不搬，水位线也不动。
    const h = harness({
      chainResolver: chainRecorder({ [receiver.did]: { currentDid: second.did } }, []),
    })
    h.storage.rememberAccountDid(subjectOf(receiverRotated.did), receiver.did, NOW.toISOString())
    seedFor(h, receiver.did, 'old-mail')

    const outcome = await readAs(h, receiverRotated)
    expect(outcome.json?.result?.messages).toEqual([])
    expect(h.storage.headSeq(receiver.did)).toBe(1)
    expect(h.storage.accountDid(subjectOf(receiverRotated.did))).toBe(receiver.did)
  })

  it('leaves the mail where it is when the chain cannot be resolved at all', async () => {
    // 对端 DID 服务器不可达：判不了就不采纳，而且**水位线不动**——动了下一次就没得对照了。
    const h = harness({ chainResolver: chainRecorder({}, []) })
    h.storage.rememberAccountDid(subjectOf(receiverRotated.did), receiver.did, NOW.toISOString())
    seedFor(h, receiver.did, 'old-mail')

    await readAs(h, receiverRotated)
    expect(h.storage.headSeq(receiver.did)).toBe(1)
    expect(h.storage.accountDid(subjectOf(receiverRotated.did))).toBe(receiver.did)
  })

  it('refuses a chain whose assurance is below policy, the same way §8.12 does', async () => {
    const h = harness({
      chainResolver: chainRecorder(
        { [receiver.did]: { currentDid: receiverRotated.did, assurance: 'provider_asserted' } },
        [],
      ),
    })
    h.storage.rememberAccountDid(subjectOf(receiverRotated.did), receiver.did, NOW.toISOString())
    seedFor(h, receiver.did, 'old-mail')

    await readAs(h, receiverRotated)
    expect(h.storage.headSeq(receiver.did)).toBe(1)
    expect(h.storage.accountDid(subjectOf(receiverRotated.did))).toBe(receiver.did)
  })

  it('does not touch an account when the call is not addressed to itself', async () => {
    // 自址是触发条件：一次投给**对端**的调用（`direct.send` 那条路）不该在这里动账号的归属，
    // 否则一个同主体路径的 DID 只要给别人发封信就能把别人的信箱搬走。
    const calls: string[] = []
    const h = harness({ chainResolver: chainRecorder({ [receiver.did]: { currentDid: receiverRotated.did } }, calls) })
    h.storage.rememberAccountDid(subjectOf(receiverRotated.did), receiver.did, NOW.toISOString())
    seedFor(h, receiver.did, 'old-mail')

    await h.call(
      await signed({
        method: 'direct.send',
        meta: meta({ sender_did: receiverRotated.did, target: { kind: 'agent', did: second.did } }),
        body: { text: 'hi' },
        signer: receiverRotated,
      }),
    )

    expect(calls).toEqual([])
    expect(h.storage.headSeq(receiver.did)).toBe(1)
  })
})
