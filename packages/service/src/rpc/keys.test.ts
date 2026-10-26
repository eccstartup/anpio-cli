// P5 §7 的两条密钥控制面方法（C12），走**整条**受理路径跑——方法表、分发、存储都在这条路上，
// 而这一块的正确性大半在"哪一步先判"上，只测处理器会把顺序测掉。
//
// Bundle 的 proof 是**真的签**的（`signDidDocumentProofSync`，即附录 B 的产出侧），因为
// §6.2.3 L379 要求的正是"这份证明算不算数"；换成一个假对象，被测的那一条就退化成"字段在
// 不在"。设备文档里那把签名钥就是签发身份自己的钥，两者都从 `createAnpIdentity` 来——
// 这条链上的每一段都必须是同一颗钥，编一份假的会让验签这一步悄悄失效。

import { describe, expect, it } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  buildMessageRequest,
  ConnectxError,
  createAnpIdentity,
  DidDeviceResolver,
  type AnpMeta,
  type AnpRequest,
  type AnpSigningIdentity,
  type DeviceResolver,
  type LocateOptions,
} from '@anpio-cli/core'
import { signDidDocumentProofSync } from '@anpio-cli/core/advanced'
import { loadConfig } from '../config'
import { createHttpNonceStore } from '../federation/nonces'
import { openObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import { createDispatch } from './dispatch'
import type { RpcHandler, RpcRequest } from '../http/server'
import { GET_PREKEY_BUNDLE, PUBLISH_PREKEY_BUNDLE } from './keys'
import { lookupMethod } from './methods'
import { callerKeyOf, createRateLimiter } from './rateLimit'

const config = loadConfig({})
const SERVICE_DID = config.serviceDid

/** 发布方与调用方是两个人，这样"Bundle 的 owner 与 meta.sender_did 不符"那条才有得测。 */
const publisher = createAnpIdentity('publisher.example')
const asker = createAnpIdentity('asker.example')

const PUB_DEVICE = 'dev-pub-7N3KQ2'
const ASK_DEVICE = 'dev-ask-4B8XT'

/** 一个时刻，让 `published_at` 与 `retry_after` 都是字面量。 */
const NOW = new Date('2026-10-01T12:00:00Z')

/** 设备在这份文档里的两个 keyid。e2ee 那个写成**相对形式**（`#…`），因为"同一颗钥的两种
 *  拼法"正是 `canonicalDidUrl` 存在的理由——这里写相对形式，Bundle 里写完整形式，两边比的
 *  是规范化之后的值。 */
function keysOf(did: string, deviceId: string) {
  return { signing: `${did}#key-1`, e2eeFull: `${did}#${deviceId}-e2ee` }
}

/**
 * 一份够 §4.1.1 判定的设备文档：`assertionMethod` 上是身份自己的钥（Bundle 的证明用它签），
 * `keyAgreement` 上是这台设备的 X25519，清单把两者绑在 `device_id` 上。
 *
 * 与 `identity.didDocument` 的差别就是补了 `keyAgreement` 与那颗 e2ee 钥——`buildBaseDidDocument`
 * 只管签名钥。文档自己那份 `proof` 不重签：本服务读文档时不解那份证明（`DidDeviceResolver`
 * 只读形状与关系），重签只会让这个夹具看起来像在证明什么。
 */
function deviceDocument(
  identity: AnpSigningIdentity,
  deviceId: string,
  patch: { e2eeKeyId?: string } = {},
): Record<string, unknown> {
  const e2eeKeyId = patch.e2eeKeyId ?? keysOf(identity.did, deviceId).e2eeFull
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
            'anp.direct.base.v1',
            'anp.direct.e2ee.v2',
          ],
        },
      ],
    },
  }
}

function deviceResolverFor(documents: Record<string, unknown>): DeviceResolver {
  const base = new DidDeviceResolver()
  return {
    resolveDevice(identity: string, deviceId: string, opts: LocateOptions = {}) {
      return base.resolveDevice(identity, deviceId, { ...opts, didDocument: documents[identity] })
    },
  }
}

/** 给一份"被证明对象"盖章。`signDidDocumentProofSync` 交回的**只是证明本身**——它不知道
 *  证明该挂在哪个键上（`dataIntegrity.ts` 上写了：公钥不在被证明对象里），所以装配这一步
 *  由调用方做。 */
function stamp(
  document: Record<string, unknown>,
  keyid: string,
  priv: Uint8Array,
): Record<string, unknown> {
  return { ...document, proof: signDidDocumentProofSync(document, keyid, priv) }
}

/** 去掉顶层 `proof`，好把它换成另一份证明。 */
function stripProof(document: Record<string, unknown>): Record<string, unknown> {
  const { proof: _proof, ...rest } = document
  void _proof
  return rest
}

/** §6.3 那份 Bundle。`proof` 由**发布设备的那把钥**真签。 */
function bundle(
  overrides: Record<string, unknown> = {},
  signer: AnpSigningIdentity = publisher,
  deviceId: string = PUB_DEVICE,
): Record<string, unknown> {
  return stamp(
    {
      bundle_id: 'bundle-1',
      owner_did: signer.did,
      owner_device_id: deviceId,
      suite: 'x25519-chacha20poly1305',
      static_key_agreement_id: keysOf(signer.did, deviceId).e2eeFull,
      signed_prekey: { key_id: 'spk-1', public_key_b64u: 'AAAA', expires_at: '2027-01-01T00:00:00Z' },
      ...overrides,
    },
    signer.keyid,
    signer.priv,
  )
}

function publishMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.e2ee.v2',
    security_profile: 'transport-protected',
    sender_did: publisher.did,
    sender_device_id: PUB_DEVICE,
    target: { kind: 'service', did: SERVICE_DID },
    operation_id: 'op-publish-1',
    ...overrides,
  }
}

/** §7.1 那个形状：只有 `prekey_bundle` 与可选的一批 OPK，没有 `auth`。 */
function publishRequest(
  options: { meta?: AnpMeta; body?: Record<string, unknown>; id?: string } = {},
): AnpRequest {
  return buildMessageRequest({
    id: options.id ?? 'req-publish',
    method: PUBLISH_PREKEY_BUNDLE,
    meta: options.meta ?? publishMeta(),
    body: options.body ?? { prekey_bundle: bundle() },
  })
}

function getMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.e2ee.v2',
    security_profile: 'transport-protected',
    sender_did: asker.did,
    sender_device_id: ASK_DEVICE,
    target: { kind: 'service', did: SERVICE_DID },
    operation_id: 'op-get-1',
    ...overrides,
  }
}

function getRequest(
  options: { meta?: AnpMeta; body?: Record<string, unknown>; id?: string } = {},
): AnpRequest {
  return buildMessageRequest({
    id: options.id ?? 'req-get',
    method: GET_PREKEY_BUNDLE,
    meta: options.meta ?? getMeta(),
    body: options.body ?? { target_did: publisher.did, target_device_id: PUB_DEVICE },
  })
}

/** §10.2 L681–693：`anp_code` 与 `retryable` 在 `data` 上，而 Profile 自己的细节收在
 *  `data.details` 里（`toErrorObject`）——`retry_after` 就在那儿。 */
interface ErrorBody {
  code: number
  message: string
  data?: { anp_code?: string; retryable?: boolean; details?: Record<string, unknown> }
}

interface Outcome {
  json: { result?: Record<string, unknown>; error?: ErrorBody } | undefined
}

interface Harness {
  call(payload: unknown): Promise<Outcome>
  storage: Storage
}

/** 默认的设备文档：两个身份各自一台设备。 */
function defaultDocuments(): Record<string, unknown> {
  return {
    [publisher.did]: deviceDocument(publisher, PUB_DEVICE),
    [asker.did]: deviceDocument(asker, ASK_DEVICE),
  }
}

function harness(
  overrides: {
    storage?: Storage
    config?: ReturnType<typeof loadConfig>
    documents?: Record<string, unknown>
  } = {},
): Harness {
  const storage = overrides.storage ?? openStorage({ path: ':memory:' })
  const handle: RpcHandler = createDispatch({
    config: overrides.config ?? config,
    storage,
    objects: openObjectStore({ directory: mkdtempSync(join(tmpdir(), 'anpiocli-keys-')), maxBytes: 1024 }),
    deviceResolver: deviceResolverFor(overrides.documents ?? defaultDocuments()),
    nonceStore: createHttpNonceStore(storage),
    log: () => undefined,
    now: () => NOW,
  })
  return {
    storage,
    async call(payload: unknown): Promise<Outcome> {
      // 不带 `method`：这一层走的是**同域明文**那条路，外层认证整段跳过。那正是这两条方法
      // 唯一能走的路——它们的认证在 Bundle 的证明里，不在信封上。
      const request: RpcRequest = {
        body: typeof payload === 'string' ? payload : JSON.stringify(payload),
        headers: {},
        url: new URL(`${config.publicUrl}/anp-im/rpc`),
      }
      const response = await handle(request)
      return { json: response.body === '' ? undefined : (JSON.parse(response.body) as Outcome['json']) }
    },
  }
}

describe(`${PUBLISH_PREKEY_BUNDLE} (§7.1)`, () => {
  it('accepts a Bundle signed by the publishing device, and reports the OPK count', async () => {
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: {
        prekey_bundle: bundle(),
        // §7.1 L472：这一批是**可选**的，一次补进池子。
        one_time_prekeys: [
          { key_id: 'opk-1', public_key_b64u: 'AA' },
          { key_id: 'opk-2', public_key_b64u: 'BB' },
        ],
      },
    }))
    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result).toMatchObject({
      published: true,
      owner_did: publisher.did,
      owner_device_id: PUB_DEVICE,
      bundle_id: 'bundle-1',
      published_at: NOW.toISOString(),
      published_opk_count: 2,
    })
    expect(h.storage.availableOneTimePrekeys(publisher.did, PUB_DEVICE)).toBe(2)
  })

  it('counts only the OPKs it actually put in the pool', async () => {
    // §7.1 L485 的 `published_opk_count` 说的是"这次发布**加进去**多少"，不是"你送了多少"
    // ——客户端重发同一批不该报成"又发了这么多"。
    //
    // 第二次必须是**另一次操作**（换个 `operation_id`）：同一个 `operation_id` 会命中幂等
    // 台账，那时 `perform` 根本不跑，回的是第一次那份响应（里面写着 1）——那测的是回放，
    // 不是计数。
    const h = harness()
    const body = {
      prekey_bundle: bundle(),
      one_time_prekeys: [{ key_id: 'opk-1', public_key_b64u: 'AA' }],
    }
    await h.call(publishRequest({ id: 'req-1', body }))
    const again = await h.call(publishRequest({
      id: 'req-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
      body,
    }))
    expect(again.json?.error).toBeUndefined()
    expect(again.json?.result?.published_opk_count).toBe(0)
    expect(h.storage.availableOneTimePrekeys(publisher.did, PUB_DEVICE)).toBe(1)
  })

  it('refuses a proof the publishing device did not make, with 4001', async () => {
    // §6.2.3 L379 逐字：不合附录 B 的 proof → `bundle_invalid`。这里把一份**有效**的证明
    // 搬到另一个被证明对象上，于是签名对不上——第三方能做的正是这个：他签不出那颗钥，只能
    // 改一改别人的东西。
    //
    // 这也是这条方法**唯一的认证**（`keys.ts` 的文件头写了理由）。
    const tampered = {
      ...bundle(),
      signed_prekey: { key_id: 'spk-1', public_key_b64u: 'ZZZZ' },
    }
    const h = harness()
    const outcome = await h.call(publishRequest({ body: { prekey_bundle: tampered } }))
    expect(outcome.json?.error?.code).toBe(4001)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.direct.e2ee.bundle_invalid')
    expect(h.storage.prekeyBundle(publisher.did, PUB_DEVICE)).toBeUndefined()
  })

  it("refuses a proof made with another of the DID's own keys, with 4012", async () => {
    // §6.5 第 2 项要的是"清单里那条 `signing_key_id`"，而 §13 L1547 把"Core 资格通过之后
    // 的密钥引用不一致"归给 `invalid_security_binding`。
    //
    // 这份 Bundle 的证明本身**完全合规**——它由本 DID 文档里一颗被 `assertionMethod` 授权
    // 的钥签出、签名验得过。错的是它不是**这台设备**那颗钥，而这一点只有读过清单才知道。
    // 所以必须是 4012 而不是 4001：附录 B 说"这是一份有效证明"，清单说"这不是它的证明"。
    const second = createAnpIdentity('second-key.example')
    const secondKeyId = `${publisher.did}#key-2`
    const doc = deviceDocument(publisher, PUB_DEVICE)
    // `DidPublicKey` 是一个联合（Ed25519 走 multibase，secp256k1 走 JWK），而
    // `createAnpIdentity` 造的必定是前者——这里把那个事实收窄出来，而不是断言一个类型。
    const secondKey = 'publicKeyMultibase' in second.publicKey ? second.publicKey.publicKeyMultibase : ''
    ;(doc.verificationMethod as unknown[]).push({
      id: secondKeyId,
      type: 'Multikey',
      controller: publisher.did,
      publicKeyMultibase: secondKey,
    })
    ;(doc.assertionMethod as unknown[]).push(secondKeyId)

    const wrongKey = stamp(stripProof(bundle()), secondKeyId, second.priv)
    const h = harness({
      documents: { [publisher.did]: doc, [asker.did]: deviceDocument(asker, ASK_DEVICE) },
    })
    const outcome = await h.call(publishRequest({ body: { prekey_bundle: wrongKey } }))
    expect(outcome.json?.error?.code).toBe(4012)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.direct.e2ee.invalid_security_binding')
  })

  it('refuses a Bundle whose owner is somebody else, with 4012', async () => {
    // §13 L1547 的 "P5 Bundle owner" 那一项。Bundle 自身可以完全合规——错的是它不属于送它
    // 来的那个人。这条判定排在验签之前，所以那份证明根本没被读。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { prekey_bundle: bundle({ owner_did: asker.did }) },
    }))
    expect(outcome.json?.error?.code).toBe(4012)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.direct.e2ee.invalid_security_binding')
  })

  it('refuses a static_key_agreement_id that is not the device e2ee_key_id, with 4012', async () => {
    // §4.1.1 L178 第 4 项（"the Bundle … use the same … key references"）。proof 指向的是
    // 签名钥，这里判的是 DH 那把。两边拼法不同（文档写相对形式）仍然要判成同一个标识符
    // ——`canonicalDidUrl` 就是为这个存在的。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { prekey_bundle: bundle({ static_key_agreement_id: `${publisher.did}#someone-elses-ka` }) },
    }))
    expect(outcome.json?.error?.code).toBe(4012)
  })

  it('refuses an embedded one_time_prekey, with 4001', async () => {
    // §6.3 L393–395 逐字：`prekey_bundle` **MUST NOT** directly contain `one_time_prekey`。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { prekey_bundle: bundle({ one_time_prekey: { key_id: 'opk-1', public_key_b64u: 'AA' } }) },
    }))
    expect(outcome.json?.error?.code).toBe(4001)
  })

  it('refuses a redefined bundle_id, but accepts a different one (§6.2.2 L371)', async () => {
    const h = harness()
    expect((await h.call(publishRequest({ id: 'req-1' }))).json?.error).toBeUndefined()

    // 同一个 `bundle_id` 指向了不同的 `signed_prekey`——§6.2.2 L371 的 MUST NOT。
    const redefined = await h.call(publishRequest({
      id: 'req-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
      body: { prekey_bundle: bundle({ signed_prekey: { key_id: 'spk-2', public_key_b64u: 'CCCC' } }) },
    }))
    expect(redefined.json?.error?.code).toBe(4001)

    // 换一个 `bundle_id` 就是另一份 Bundle——同一行规定的另一半（"MAY accept multiple
    // different bundle_id values concurrently"）。本服务每设备只留最新一份，所以那个 MAY
    // 在存储上表现为覆盖。
    const fresh = await h.call(publishRequest({
      id: 'req-3',
      meta: publishMeta({ operation_id: 'op-publish-3' }),
      body: {
        prekey_bundle: bundle({
          bundle_id: 'bundle-2',
          signed_prekey: { key_id: 'spk-2', public_key_b64u: 'CCCC' },
        }),
      },
    }))
    expect(fresh.json?.error).toBeUndefined()
    expect(h.storage.prekeyBundle(publisher.did, PUB_DEVICE)?.bundleId).toBe('bundle-2')
  })

  it('refuses a request that carries params.auth (§7.1 L472)', async () => {
    const h = harness()
    const request = publishRequest()
    const outcome = await h.call({
      ...request,
      params: { ...request.params, auth: { scheme: 'x', origin_proof: {} } },
    })
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('auth')
  })

  it('refuses a target that is not this service, with 1014', async () => {
    const h = harness()
    const outcome = await h.call(publishRequest({
      meta: publishMeta({ target: { kind: 'service', did: 'did:web:elsewhere.example' } }),
    }))
    expect(outcome.json?.error?.code).toBe(1014)
  })

  it('refuses one_time_prekeys that is not a non-empty array, with 1003', async () => {
    // §7.1 L472：存在时 MUST 是非空数组。"空数组"不是"这次没带 OPK"的写法。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { prekey_bundle: bundle(), one_time_prekeys: [] },
    }))
    expect(outcome.json?.error?.code).toBe(1003)
  })
})

describe(`${GET_PREKEY_BUNDLE} (§7.2)`, () => {
  /** 发布一台设备的 Bundle 与两枚 OPK，返回接下来可以直接问的那套东西。 */
  async function published(): Promise<Harness> {
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: {
        prekey_bundle: bundle(),
        one_time_prekeys: [
          { key_id: 'opk-1', public_key_b64u: 'AA' },
          { key_id: 'opk-2', public_key_b64u: 'BB' },
        ],
      },
    }))
    expect(outcome.json?.error).toBeUndefined()
    return h
  }

  function ask(h: Harness, options: { meta?: AnpMeta; body?: Record<string, unknown>; id?: string } = {}) {
    return h.call(getRequest(options))
  }

  it('hands back the bundle and one OPK, which leaves the pool (§7.2 L563)', async () => {
    const h = await published()
    const outcome = await ask(h)
    expect(outcome.json?.error).toBeUndefined()
    expect(outcome.json?.result?.target_did).toBe(publisher.did)
    expect(outcome.json?.result?.target_device_id).toBe(PUB_DEVICE)
    expect(outcome.json?.result?.prekey_bundle).toMatchObject({ bundle_id: 'bundle-1' })
    // FIFO：先发进去的那枚先出。
    expect(outcome.json?.result?.one_time_prekey).toEqual({ key_id: 'opk-1', public_key_b64u: 'AA' })
    // 取用即标记已分配，所以池子里只剩一枚。
    expect(h.storage.availableOneTimePrekeys(publisher.did, PUB_DEVICE)).toBe(1)
  })

  it('returns the same bundle and the same OPK to a retry (§7.2 L578)', async () => {
    // §9.1 L630 与 §7.2 L578：同一幂等键重试必须拿到**同一个** `prekey_bundle` 与**同一枚**
    // `one_time_prekey`，而且不得因此再分配一枚。实现上这不是"把分配键存下来"，而是命中同键
    // 时 `acceptOperation` 根本不调 `perform`（`accept.ts`），回放上次那份响应。
    const h = await published()
    const first = await ask(h)
    const retry = await ask(h, { id: 'req-get-2' })
    expect(retry.json?.result?.one_time_prekey).toEqual(first.json?.result?.one_time_prekey)
    expect(h.storage.availableOneTimePrekeys(publisher.did, PUB_DEVICE)).toBe(1)
  })

  it('does not answer another device out of the same record (§11.5 L1458)', async () => {
    // 幂等键里带着设备段，所以"另一台设备来问"是另一件事。这里那台设备不在清单里，于是它先
    // 是拿不到资格——那个码说明了"这一次的点名被当成了新的一次"，而不是命中了回放。
    const h = await published()
    await ask(h)
    const other = await ask(h, {
      id: 'req-get-3',
      meta: getMeta({ operation_id: 'op-get-2', sender_device_id: 'dev-ask-other' }),
    })
    expect(other.json?.error?.code).toBe(1017)
  })

  it('hands out no OPK when the pool is empty and require_opk is absent (§6.6 L852)', async () => {
    // 池空且调用方没要求 OPK 就是**正常返回静态 Bundle**，不是错误。
    const h = await published()
    await ask(h, { meta: getMeta({ operation_id: 'op-get-1' }) })
    await ask(h, { meta: getMeta({ operation_id: 'op-get-2' }) })
    const third = await ask(h, { meta: getMeta({ operation_id: 'op-get-3' }) })
    expect(third.json?.error).toBeUndefined()
    expect(third.json?.result?.prekey_bundle).toBeDefined()
    expect(third.json?.result?.one_time_prekey).toBeUndefined()
  })

  it('refuses require_opk with an empty pool, with 4003 (§7.2 L576)', async () => {
    const h = await published()
    await ask(h, { meta: getMeta({ operation_id: 'op-get-1' }) })
    await ask(h, { meta: getMeta({ operation_id: 'op-get-2' }) })
    const third = await ask(h, {
      meta: getMeta({ operation_id: 'op-get-3' }),
      body: { target_did: publisher.did, target_device_id: PUB_DEVICE, require_opk: true },
    })
    expect(third.json?.error?.code).toBe(4003)
    expect(third.json?.error?.data?.anp_code).toBe('anp.direct.e2ee.opk_unavailable')
  })

  it('answers 4000 for a device that never published', async () => {
    const h = harness()
    const outcome = await ask(h)
    expect(outcome.json?.error?.code).toBe(4000)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.direct.e2ee.bundle_not_found')
  })

  it('stops returning a bundle the device has since re-keyed, with 1018 (§4.1.1 L178)', async () => {
    // §4.1.1 L178 第 4 项点的是 "Before publishing, **returning**, or using P5 material"——
    // 设备还在、但换了 DH 钥之后，存着的那份已经绑在旧钥上，§6.5 第 4 项会让每个合规发送方
    // 拒掉它。§12.4 L1515 对这种情形的要求是 MUST stop returning it，而这个窗口正是发布新
    // Bundle 之前的那一小段。
    //
    // 码取 1018 而不是 4012：§13 L1547 把 "current Manifest changes" 归给 Core 那几个共享
    // 错误（`anp.device_state_changed` 逐字在列），4012 留给"调用方送来的东西绑错了"——这里
    // 调用方什么都没做错。
    const h = await published()
    const rekeyed = deviceDocument(publisher, PUB_DEVICE, { e2eeKeyId: `${publisher.did}#other-e2ee` })
    const moved = harness({
      storage: h.storage,
      documents: { [publisher.did]: rekeyed, [asker.did]: deviceDocument(asker, ASK_DEVICE) },
    })
    const outcome = await ask(moved)
    expect(outcome.json?.error?.code).toBe(1018)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.device_state_changed')
  })

  it('refuses an ineligible target device before returning any material, with 1017 (§7.2 L572)', async () => {
    // §7.2 L572 那条 MUST 的落点：返回材料**之前**要按 §4.1.1 验精确的
    // `(target_did, target_device_id)`。清单里没有这台设备时，一枚字节都不该出去。
    const h = await published()
    const stripped = harness({
      storage: h.storage,
      documents: {
        [publisher.did]: {
          ...deviceDocument(publisher, PUB_DEVICE),
          deviceManifest: { type: 'ANPDeviceManifest', devices: [] },
        },
        [asker.did]: deviceDocument(asker, ASK_DEVICE),
      },
    })
    const outcome = await ask(stripped)
    expect(outcome.json?.error?.code).toBe(1017)
  })
})

describe('rate limiting (§7.3 L598)', () => {
  it('answers 1011 once the caller runs out of tokens, and does not write a ledger row', async () => {
    const tight = loadConfig({ ANPIOCLI_PREKEY_BURST: '1', ANPIOCLI_PREKEY_PER_MINUTE: '1' })
    const h = harness({ config: tight })
    const first = await h.call(publishRequest({ id: 'req-1' }))
    expect(first.json?.error).toBeUndefined()

    const second = await h.call(publishRequest({
      id: 'req-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
      body: { prekey_bundle: bundle({ bundle_id: 'bundle-2' }) },
    }))
    expect(second.json?.error?.code).toBe(1011)
    expect(second.json?.error?.data?.anp_code).toBe('anp.rate_limited')
    // 每秒补 1/60 枚，缺 1 枚 → 60 秒。一个不说什么时候能再来的 `retryable` 让调用方只能盲试。
    expect(second.json?.error?.data?.retryable).toBe(true)
    expect(second.json?.error?.data?.details?.retry_after).toBe(60)
    // 被限流的调用**不写台账**：它不是一次"被受理的操作"，调用方拿着同一个 `operation_id`
    // 稍后重试走的正是同一条路（这里就是"池子里还是那一份"）。
    expect(h.storage.prekeyBundle(publisher.did, PUB_DEVICE)?.bundleId).toBe('bundle-1')
  })

  it('counts each caller separately, and takes the authenticated identity first', () => {
    // 跨域那一侧的身份是外层签名验出来的，别人伪造不了；同域明文只能退到自报的
    // `meta.sender_did`——两个不同的 DID 各自算一份，所以洪泛一个身份不会连带另一个。
    expect(callerKeyOf('did:web:peer.example', publisher.did)).toBe('service:did:web:peer.example')
    expect(callerKeyOf(undefined, publisher.did)).toBe(`did:${publisher.did}`)
    expect(callerKeyOf(undefined, publisher.did)).not.toBe(callerKeyOf(undefined, asker.did))
  })

  it('refills continuously, and keeps a bucket per caller', () => {
    const limiter = createRateLimiter({ burst: 2, perMinute: 60 })
    const t0 = NOW.getTime()
    expect(limiter.take('a', t0).allowed).toBe(true)
    expect(limiter.take('a', t0).allowed).toBe(true)
    // 桶空了：缺 1 枚，每秒补 1 枚，所以是 1 秒后。
    expect(limiter.take('a', t0)).toEqual({ allowed: false, retryAfterSeconds: 1 })
    // 另一个调用方不受影响。
    expect(limiter.take('b', t0).allowed).toBe(true)
    // 一秒补一枚，正好够下一次。
    expect(limiter.take('a', t0 + 1000).allowed).toBe(true)
  })
})

describe('the method table entries (§7.1 / §7.2)', () => {
  it('keeps the two key methods service-scoped with two different target scopes', () => {
    const publishSpec = lookupMethod(PUBLISH_PREKEY_BUNDLE)
    const getSpec = lookupMethod(GET_PREKEY_BUNDLE)
    expect(publishSpec?.targetMode).toBe('service-scoped')
    expect(getSpec?.targetMode).toBe('service-scoped')
    // §7.2 的键元组比 §7.1 多一个 `target_did`——"问谁要"是这一次操作的一部分，而两条方法
    // 各自取自己规范里逐字给出的那一段，不复用看起来差不多的那一份。
    expect(publishSpec?.targetScope?.(publishMeta(), {})).toBe(SERVICE_DID)
    expect(
      getSpec?.targetScope?.(getMeta(), { target_did: publisher.did, target_device_id: PUB_DEVICE }),
    ).toBe(`${SERVICE_DID}/${publisher.did}`)
    // 发布只点自己一台（§7.1 L476：这条路上没有收件人），领取点两台。
    expect(publishSpec?.deviceAddressed?.(publishMeta(), {})?.pairs).toHaveLength(1)
    expect(
      getSpec?.deviceAddressed?.(getMeta(), { target_did: publisher.did, target_device_id: PUB_DEVICE })?.pairs,
    ).toHaveLength(2)
    // §7.2 L578 / §12.4 L1515：返回密钥材料之前要重判，所以重放也要重判。
    expect(
      getSpec?.deviceAddressed?.(getMeta(), { target_did: publisher.did, target_device_id: PUB_DEVICE }),
    ).toMatchObject({ recheckOnReplay: true })
    // `direct.send` 那一档不同：重放拿到的是历史结果，不重判。
    const direct = lookupMethod('direct.send')?.deviceAddressed?.(
      {
        ...getMeta(),
        recipient_device_id: PUB_DEVICE,
        target: { kind: 'agent', did: asker.did },
      },
      {},
    )
    expect(direct).toBeDefined()
    expect(direct?.recheckOnReplay).toBeUndefined()
  })

  it('has the device pair order the handlers read (caller first, target second)', () => {
    // `keys.ts` 的 `device(ctx, 0)` 是发布方、`device(ctx, 1)` 是目标设备，认的就是这个顺序。
    const pairs = lookupMethod(GET_PREKEY_BUNDLE)?.deviceAddressed?.(getMeta(), {
      target_did: publisher.did,
      target_device_id: PUB_DEVICE,
    })?.pairs
    expect(pairs).toEqual([
      { identity: asker.did, deviceId: ASK_DEVICE },
      { identity: publisher.did, deviceId: PUB_DEVICE },
    ])
  })

  it('throws rather than inventing a scope when the request is missing its target', () => {
    // 到不了（`checkMethod` 保证 `service-scoped` 必带 target），但兜一个空串会算出一个人
    // 也不会再命中的键——那是比当场炸掉更坏的静默。
    const { target: _dropped, ...withoutTarget } = publishMeta()
    void _dropped
    expect(() => lookupMethod(PUBLISH_PREKEY_BUNDLE)?.targetScope?.(withoutTarget, {})).toThrow(ConnectxError)
  })
})
