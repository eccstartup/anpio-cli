import { describe, expect, it } from 'vitest'
import {
  DidKeyResolver,
  buildMessageRequest,
  createAnpIdentity,
  ed25519OriginProofSigner,
  type AnpMeta,
  type AnpSigningIdentity,
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
import { openStorage } from '../storage/sqlite'
import { createHttpNonceStore } from './nonces'
import { verifyOuterIdentity } from './outer'

// 八步里要跑真的密码学：桩只负责把**钥**和**服务条目**交出来，签名与摘要都是真算的。
// 一份桩签名验证的是桩，不是这套流程。
const anchor = createAnpIdentity('sender.example')
const other = createAnpIdentity('other.example')
const group = createAnpIdentity('group.example')
const service = createAnpIdentity('service.example')
const impostor = createAnpIdentity('evil.example')

const METHOD = 'POST'
const PATH = '/anp'
const AUTHORITY = 'receiver.example'
const SCHEME = 'https'
const TARGET_URI = `${SCHEME}://${AUTHORITY}${PATH}`

const resolver = new DidKeyResolver()
/** 只喂给第 7 步：`serviceDid` 自己的文档。生产里它来自对端的 `.well-known`。 */
const serviceOptions: LocateOptions = { didDocument: service.didDocument }

function entryFor(serviceDid?: string): ServiceEntry {
  const entry: ServiceEntry = {
    id: `#${AUTHORITY}`,
    type: 'ANPMessageService',
    serviceEndpoint: `https://${AUTHORITY}${PATH}`,
  }
  if (serviceDid !== undefined) entry.serviceDid = serviceDid
  return entry
}

/** 定位器是**注入端口**，所以按身份喂条目不算作弊——它就是 `DidServiceLocator` 会把
 *  结果交回来的那一处。锚点文档本身在 `rpc/auth.test.ts` 里已经测过解析。 */
function locator(published: Record<string, ServiceEntry[]>): ServiceLocator {
  return {
    async locate(identity: string): Promise<ServiceEntry[]> {
      return published[identity] ?? []
    },
  }
}

function meta(senderDid: string = anchor.did): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: senderDid,
    target: { kind: 'agent', did: other.did },
  }
}

function nonceStore(): NonceStore {
  return createHttpNonceStore(openStorage({ path: ':memory:' }))
}

interface OuterCallOptions {
  method?: string
  meta?: AnpMeta
  body?: Record<string, unknown>
  signer?: AnpSigningIdentity
  keyid?: string
  nonce?: string
  created?: number
}

/** 一份真的签过名的跨域请求。签的是 `ANP_COMPONENTS` 那个覆盖集合，
 *  与 core 验签侧读到的集合是同一份常量，所以两侧不可能签出两种底。 */
async function outerCall(options: OuterCallOptions = {}) {
  const method = options.method ?? 'direct.send'
  const under = options.meta ?? meta()
  const body = options.body ?? {}
  const signer = options.signer ?? service
  const keyid = options.keyid ?? signer.keyid
  const nonce = options.nonce ?? 'nonce-1'
  const created = options.created ?? Math.floor(Date.now() / 1000)

  const envelope = buildMessageRequest({ id: 'req-1', method, meta: under, body })
  const bodyText = JSON.stringify(envelope)
  const contentDigest = await buildContentDigestValue(utf8(bodyText))
  const signatureParams = serializeSignatureParams(ANP_COMPONENTS, {
    created,
    expires: created + 300,
    nonce,
    keyid,
  })
  const base = buildSignatureBase({
    method: METHOD,
    path: PATH,
    authority: AUTHORITY,
    targetUri: TARGET_URI,
    headers: { 'content-digest': contentDigest },
    components: ANP_COMPONENTS,
    signatureParams,
  })
  const signature = await ed25519OriginProofSigner(signer.priv, keyid).sign(signatureBaseBytes(base))

  return {
    params: { meta: under, body },
    http: {
      method: METHOD,
      path: PATH,
      search: '',
      authority: AUTHORITY,
      headers: {
        'content-digest': contentDigest,
        'signature-input': `sig1=${signatureParams}`,
        signature: `sig1=:${bytesToBase64(signature)}:`,
      },
      body: bodyText,
    },
  }
}

/** 常走的装配：`direct.send`，锚点发布的就是 `service`。 */
function call(overrides: Partial<OuterCallOptions> = {}) {
  return outerCall(overrides)
}

async function verify(
  input: Awaited<ReturnType<typeof outerCall>>,
  published: Record<string, ServiceEntry[]> = { [anchor.did]: [entryFor(service.did)] },
  method = 'direct.send',
  scheme = SCHEME,
) {
  return verifyOuterIdentity({
    method,
    params: input.params,
    http: input.http,
    scheme,
    resolver,
    locator: locator(published),
    locateOptions: serviceOptions,
    nonceStore: nonceStore(),
  })
}

describe('verifyOuterIdentity', () => {
  it('treats a request with no outer identity as a local call', async () => {
    // §2.3：触发条件是「有没有 `Signature-Input`」。这不是失败，是另一条路——
    // 所以它不能走 `refused` 那一支，否则调用点会把本地调用也回成 401。
    const input = await call()
    const result = await verifyOuterIdentity({
      method: 'direct.send',
      params: input.params,
      http: { ...input.http, headers: { 'content-digest': input.http.headers['content-digest'] } },
      scheme: SCHEME,
      resolver,
      locator: locator({ [anchor.did]: [entryFor(service.did)] }),
      locateOptions: serviceOptions,
      nonceStore: nonceStore(),
    })
    expect(result.kind).toBe('absent')
  })

  it('refuses when the method names no anchor to check the caller against', async () => {
    // `direct.send` 的锚点是 `meta.sender_did`，这里没有它。方法要外层身份而承载锚点的
    // 字段不在——这不是"不用验"，是"验不了"，所以拒绝而不是放过。
    const input = await call({ meta: { ...meta(), sender_did: '' } as AnpMeta })
    const result = await verify(input)
    expect(result.kind).toBe('refused')
    if (result.kind !== 'refused') return
    expect(result.error).toBe('invalid_request')
  })

  it('refuses when the anchor publishes an ANPMessageService without a serviceDid', async () => {
    // L385：条目没有 `serviceDid` 就失败。不许回落到锚点本身——那等于把第 6 步删掉。
    const input = await call()
    const result = await verify(input, { [anchor.did]: [entryFor()] })
    expect(result.kind).toBe('refused')
    if (result.kind !== 'refused') return
    expect(result.error).toBe('invalid_did')
  })

  it('refuses a keyid that belongs to another DID than the published serviceDid', async () => {
    // 第 6 步：签得再完美也没用，`keyid` 指的不是这个锚点宣告的那个域服务。
    const input = await call({ signer: impostor })
    expect(input.http.headers['signature-input']).toContain(impostor.did)
    const result = await verify(input)
    expect(result.kind).toBe('refused')
    if (result.kind !== 'refused') return
    expect(result.error).toBe('forbidden_did')
  })

  it('refuses a replayed nonce even though the signature itself is valid', async () => {
    // §2.2：验签成功**不是**重放防护。同一份请求走两遍，第二遍必须在 nonce store 上撞墙。
    const input = await call({ nonce: 'replay-me' })
    const store = nonceStore()
    const run = () =>
      verifyOuterIdentity({
        method: 'direct.send',
        params: input.params,
        http: input.http,
        scheme: SCHEME,
        resolver,
        locator: locator({ [anchor.did]: [entryFor(service.did)] }),
        locateOptions: serviceOptions,
        nonceStore: store,
      })
    expect((await run()).kind).toBe('verified')
    const replay = await run()
    expect(replay.kind).toBe('refused')
    if (replay.kind !== 'refused') return
    expect(replay.error).toBe('invalid_nonce')
  })

  it('accepts a signed request and reports the service identity it verified', async () => {
    const input = await call()
    const result = await verify(input)
    expect(result.kind).toBe('verified')
    if (result.kind !== 'verified') return
    expect(result.serviceDid).toBe(service.did)
    expect(result.keyid).toBe(service.keyid)
    expect(result.key.identity).toBe(service.did)
  })

  it('anchors a group notification on body.group_did, not meta.sender_did', async () => {
    // 这是 §6.2.2 L387 那句话的全部内容：群通知的「原始发送者」与「当前跨域调用者」是
    // 两个人。发送者那个 DID 也发布了一个域服务（`impostor`），如果锚点取错了字段，
    // 用 `service` 签的这份请求会因为 keyid 对不上 `impostor` 而被拒——反过来，用
    // `impostor` 签的会被放行。两个方向都钉住。
    const body = { group_did: group.did, event: 'member-removed' }
    const under = meta(other.did)
    const published = {
      [group.did]: [entryFor(service.did)],
      [other.did]: [entryFor(impostor.did)],
    }

    const good = await outerCall({ method: 'group.state_changed', meta: under, body, signer: service })
    const accepted = await verify(good, published, 'group.state_changed')
    expect(accepted.kind).toBe('verified')

    const forged = await outerCall({ method: 'group.state_changed', meta: under, body, signer: impostor })
    const rejected = await verify(forged, published, 'group.state_changed')
    expect(rejected.kind).toBe('refused')
    if (rejected.kind !== 'refused') return
    expect(rejected.error).toBe('forbidden_did')
  })

  it('accepts the scheme with its colon, the form `new URL(...).protocol` returns', async () => {
    // 组装 `@target-uri` 时少一个冒号就会拼出 `https//host/path`，core 的 `new URL` 解析
    // 失败 → `request_malformed`，一份完全合法的签名被读成"请求不成形"。scheme 的两种
    // 写法都要能过，因为部署方最自然的取法是 `new URL(publicUrl).protocol`。
    const input = await call({ nonce: 'colon-form' })
    const result = await verify(input, undefined, 'direct.send', `${SCHEME}:`)
    expect(result.kind).toBe('verified')
  })

  it('refuses when the body does not match the content digest', async () => {
    // 覆盖集合里有 `content-digest`，所以换掉正文就该在验签前被摘要抓住。
    const input = await call()
    const tampered = { ...input, http: { ...input.http, body: '{"jsonrpc":"2.0","id":"x"}' } }
    const result = await verify(tampered)
    expect(result.kind).toBe('refused')
    if (result.kind !== 'refused') return
    expect(result.error).toBe('invalid_content_digest')
  })

  it('reports our own nonce-store outage as unverifiable, not as a bad proof', async () => {
    // `store_failed` 是"我们得不出结论"。回 401 会把对端送去重签一个本来没问题的东西，
    // 所以它必须落在 `unverifiable` 上——调用点据此回 5xx，且这个值不许进挑战头。
    const input = await call()
    const broken: NonceStore = {
      consume() {
        throw new Error('nonce store is down')
      },
    }
    const result = await verifyOuterIdentity({
      method: 'direct.send',
      params: input.params,
      http: input.http,
      scheme: SCHEME,
      resolver,
      locator: locator({ [anchor.did]: [entryFor(service.did)] }),
      locateOptions: serviceOptions,
      nonceStore: broken,
    })
    expect(result.kind).toBe('refused')
    if (result.kind !== 'refused') return
    expect(result.error).toBe('unverifiable')
  })
})
