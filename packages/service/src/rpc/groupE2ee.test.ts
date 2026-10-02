// P6 §8 的两条 KeyPackage 方法（C13），走**整条**受理路径跑——方法表、资格门禁、分发、存储
// 都在这条路上，而这一块的正确性大半在"哪一步先判"上：一个对象"不是 KeyPackage"（5001）
// 与"它不是你的"（5002）分属两处，只测处理器会把顺序与分派一起测掉。
//
// `did_wba_binding` 的 proof 是**真的签**的（`signDidDocumentProofSync`，即附录 B 的产出侧），
// 因为 §6.4 L445–448 第 4–6 项要求的正是"这份证明算不算数、issuer 对不对、钥引对不对"，换成
// 一个假对象，被测的那一条就退化成"字段在不在"。签发身份与设备文档里那把签名钥同源——
// 这条链上每一段必须是同一颗钥，编一份假的会让验签这一步悄悄失效。

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
} from '@agentx/core'
import { signDidDocumentProofSync } from '@agentx/core/advanced'
import { loadConfig } from '../config'
import { serviceCapabilities } from '../capabilities'
import { createHttpNonceStore } from '../federation/nonces'
import { openObjectStore } from '../objects'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import { createDispatch } from './dispatch'
import type { RpcHandler, RpcRequest } from '../http/server'
import { GET_KEY_PACKAGE, PUBLISH_KEY_PACKAGE } from './groupE2ee'
import { lookupMethod } from './methods'

const config = loadConfig({})
const SERVICE_DID = config.serviceDid

/** 发布方与调用方是两个人，这样"KeyPackage 的 owner 与 meta.sender_did 不符"那条才有得测。 */
const publisher = createAnpIdentity('publisher.example')
const asker = createAnpIdentity('asker.example')

const PUB_DEVICE = 'dev-pub-7N3KQ2'
const ASK_DEVICE = 'dev-ask-4B8XT'

/** 一个时刻，让 `published_at` 与"过期"都是字面量。 */
const NOW = new Date('2026-10-01T12:00:00Z')

/** 设备在这份文档里的两个 keyid。e2ee 那个写成**相对形式**（`#…`），因为"同一颗钥的两种
 *  拼法"正是 `canonicalDidUrl` 存在的理由。 */
function keysOf(did: string, deviceId: string) {
  return { signing: `${did}#key-1`, e2eeFull: `${did}#${deviceId}-e2ee` }
}

/**
 * 一份够 §4.2 判定的设备文档：`assertionMethod` 上是身份自己的钥（`did_wba_binding` 的证明
 * 用它签，`GROUP_E2EE_DEVICE.signingRelationship` 就是 `assertionMethod`），`keyAgreement`
 * 上是这台设备的 X25519，清单把两者绑在 `device_id` 上。
 *
 * 与 `keys.test.ts` 那份的差别只有清单里宣告的 Profile：P6 要 §4.2 L253–262 那**四**项
 * （三项依赖加自身），少一项这条设备就不算数。
 *
 * 文档自己那份 `proof` 不重签：本服务读文档时不解那份证明（`DidDeviceResolver` 只读形状与
 * 关系），重签只会让这个夹具看起来像在证明什么。
 */
function deviceDocument(
  identity: AnpSigningIdentity,
  deviceId: string,
  patch: { e2eeKeyId?: string; signingKeyId?: string } = {},
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
          signing_key_id: patch.signingKeyId ?? identity.keyid,
          e2ee_key_id: e2eeKeyId,
          profiles: [
            'anp.core.binding.v1',
            'anp.identity.discovery.v1',
            'anp.group.base.v2',
            'anp.group.e2ee.v2',
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

function stripProof(document: Record<string, unknown>): Record<string, unknown> {
  const { proof: _proof, ...rest } = document
  void _proof
  return rest
}

/**
 * §6.3 那份 `did_wba_binding`。§6.4 L446 第 6 项点名的六个字段全在，`verification_method`
 * 取清单里那条 `signing_key_id`，`proof` 由**这台设备的那把钥**真签。
 */
function binding(
  overrides: Record<string, unknown> = {},
  signer: AnpSigningIdentity = publisher,
  deviceId: string = PUB_DEVICE,
): Record<string, unknown> {
  return stamp(
    {
      agent_did: signer.did,
      device_id: deviceId,
      verification_method: keysOf(signer.did, deviceId).signing,
      leaf_signature_key_b64u: 'AAAA',
      issued_at: '2026-09-30T00:00:00Z',
      expires_at: '2027-01-01T00:00:00Z',
      ...overrides,
    },
    keysOf(signer.did, deviceId).signing,
    signer.priv,
  )
}

/** §7.3 那份 `group_key_package`。顶层 `expires_at` 是 SHOULD，所以不在默认值里。 */
function keyPackage(
  overrides: Record<string, unknown> = {},
  bindingOverrides: Record<string, unknown> = {},
  signer: AnpSigningIdentity = publisher,
  deviceId: string = PUB_DEVICE,
): Record<string, unknown> {
  return {
    key_package_id: 'kp-1',
    owner_did: signer.did,
    owner_device_id: deviceId,
    suite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
    mls_key_package_b64u: 'AAAA',
    ...overrides,
    did_wba_binding: binding(bindingOverrides, signer, deviceId),
  }
}

function publishMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.group.e2ee.v2',
    security_profile: 'transport-protected',
    sender_did: publisher.did,
    sender_device_id: PUB_DEVICE,
    target: { kind: 'service', did: SERVICE_DID },
    operation_id: 'op-publish-1',
    ...overrides,
  }
}

function publishRequest(
  options: { meta?: AnpMeta; body?: Record<string, unknown>; id?: string } = {},
): AnpRequest {
  return buildMessageRequest({
    id: options.id ?? 'req-publish',
    method: PUBLISH_KEY_PACKAGE,
    meta: options.meta ?? publishMeta(),
    body: options.body ?? { group_key_package: keyPackage() },
  })
}

function getMeta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.group.e2ee.v2',
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
    method: GET_KEY_PACKAGE,
    meta: options.meta ?? getMeta(),
    body: options.body ?? { target_did: publisher.did, target_device_id: PUB_DEVICE },
  })
}

/** §10.2 L681–693：`anp_code` 与 `retryable` 在 `data` 上，Profile 自己的细节收在
 *  `data.details` 里（`toErrorObject`）。 */
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
    objects: openObjectStore({ directory: mkdtempSync(join(tmpdir(), 'agentx-keypkg-')), maxBytes: 1024 }),
    deviceResolver: deviceResolverFor(overrides.documents ?? defaultDocuments()),
    nonceStore: createHttpNonceStore(storage),
    log: () => undefined,
    now: () => NOW,
  })
  return {
    storage,
    async call(payload: unknown): Promise<Outcome> {
      // 不带 `method`：这一层走的是**同域明文**那条路，外层认证整段跳过。那正是这两条方法
      // 唯一能走的路——它们不要求业务层 `origin_proof`（§8.1.2 L706、§8.2.2 L740）。
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

describe(`${PUBLISH_KEY_PACKAGE} (§8.1)`, () => {
  it('accepts a KeyPackage bound to the publishing device, and files it as available', async () => {
    const h = harness()
    // One signed object, reused for the request and the assertion: the binding proof
    // carries a second-granularity `created`, so re-signing at assertion time makes
    // this flake when the second ticks over.
    const kp = keyPackage()
    const outcome = await h.call(publishRequest({ body: { group_key_package: kp } }))
    expect(outcome.json?.error).toBeUndefined()
    // §8.1.3 L718–722 的五个字段。
    expect(outcome.json?.result).toEqual({
      published: true,
      owner_did: publisher.did,
      owner_device_id: PUB_DEVICE,
      key_package_id: 'kp-1',
      published_at: NOW.toISOString(),
    })
    // 柜子里那一行是 `available`，且存的是**原样**那份对象（§8.2.3 要把同一份交给后面执行
    // `group.e2ee.add` 的那个 owner，见 `groupE2ee.ts` 的 `insertGroupKeyPackage` 调用点）。
    const row = h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')
    expect(row?.state).toBe('available')
    expect(JSON.parse(row?.packageJson ?? '{}')).toEqual(kp)
  })

  it('refuses an object that is not a KeyPackage, with 5001', async () => {
    // §7.3 L550–554 那五项里缺一项，它就不再是 §7.3 定义的那个对象了。这一条判的是对象
    // **自身**，所以是 5001（§17 L1920）而不是 5002。
    const h = harness()
    const { mls_key_package_b64u: _dropped, ...rest } = keyPackage()
    void _dropped
    const outcome = await h.call(publishRequest({ body: { group_key_package: rest } }))
    expect(outcome.json?.error?.code).toBe(5001)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.invalid_key_package')
    expect(outcome.json?.error?.message).toContain('mls_key_package_b64u')
  })

  it('refuses a KeyPackage whose own two statements disagree, with 5001', async () => {
    // §7.3 L557：`owner_did` MUST 等于 `did_wba_binding.agent_did`。两者不一致是这份材料
    // **自身**的矛盾，与本服务、与调用方都无关，所以也是 5001。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { group_key_package: keyPackage({ owner_did: asker.did }) },
    }))
    expect(outcome.json?.error?.code).toBe(5001)
    expect(outcome.json?.error?.message).toContain('owner_did')
  })

  it('refuses a KeyPackage whose owner is somebody else, with 5002', async () => {
    // §8.1.2 L699–700：§8.1.2 把 `owner_did` / `owner_device_id` 与 `meta.sender_did` /
    // `meta.sender_device_id` 逐字绑在一起。这份 KeyPackage 自身完全合规——错的是它不属于
    // 送它来的那台设备，所以是 5002（"与另一处的比对"），不是 5001。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: {
        group_key_package: keyPackage(
          { owner_did: asker.did, owner_device_id: ASK_DEVICE },
          { agent_did: asker.did, device_id: ASK_DEVICE },
        ),
      },
    }))
    expect(outcome.json?.error?.code).toBe(5002)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.did_binding_invalid')
    expect(h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')).toBeUndefined()
  })

  it('refuses a proof the publishing device did not make, with 5002', async () => {
    // §6.4 L445–448 第 4–5 项。这里把一份**有效**的证明搬到另一个被证明对象上，于是签名对
    // 不上——第三方能做的正是这个：他签不出那颗钥，只能改一改别人的东西。
    //
    // 这也是这条方法**唯一的认证**：§8.1.2 L706 说 v2 不要求额外的业务层 `origin_proof`，
    // 留下的就是这颗只有那台设备才有的签名钥（`groupE2ee.ts` 的文件头写了）。
    const h = harness()
    const tampered = { ...keyPackage(), did_wba_binding: { ...binding(), leaf_signature_key_b64u: 'ZZZZ' } }
    const outcome = await h.call(publishRequest({ body: { group_key_package: tampered } }))
    expect(outcome.json?.error?.code).toBe(5002)
    expect(h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')).toBeUndefined()
  })

  it("refuses a proof made with another of the DID's own keys, with 5002", async () => {
    // §6.4 L443 第 3 项要的是"清单里那条 `signing_key_id`，且被 `assertionMethod` 授权"。
    // 这份绑定的证明本身**完全合规**——由本 DID 文档里一颗被 `assertionMethod` 授权的钥签
    // 出、验得过。错的是它不是**这台设备**那颗钥，而这一点只有读过清单才知道。
    const second = createAnpIdentity('second-key.example')
    const secondKeyId = `${publisher.did}#key-2`
    const doc = deviceDocument(publisher, PUB_DEVICE, { signingKeyId: secondKeyId })
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

    const wrongKey = keyPackage({}, { verification_method: secondKeyId })
    const h = harness({
      documents: { [publisher.did]: doc, [asker.did]: deviceDocument(asker, ASK_DEVICE) },
    })
    const outcome = await h.call(publishRequest({ body: { group_key_package: wrongKey } }))
    expect(outcome.json?.error?.code).toBe(5002)
  })

  it('refuses a binding that names a key the manifest does not point at, with 5002', async () => {
    // §6.4 L443 第 3 项的**前半**：`verification_method` 等于该条目当前 `signing_key_id`。
    // proof 那一半由上一次调用按 `expectedVerificationMethod` 判掉了，这里判的是这份绑定
    // **声明**的那一半——两半都对上，这条绑定才指的是那把钥。
    const h = harness()
    const outcome = await h.call(publishRequest({
      body: { group_key_package: keyPackage({}, { verification_method: `${publisher.did}#key-9` }) },
    }))
    expect(outcome.json?.error?.code).toBe(5002)
    expect(outcome.json?.error?.message).toContain('verification_method')
  })

  it('ignores a re-publish of the same key_package_id, so a consumed one stays consumed', async () => {
    // §8.1.2 没有"`key_package_id` 不可重定义"这句（与 P5 §6.2.2 L371 不同），本服务对同名
    // 重发是**忽略**（先写者赢）。这条性质有两面，这里测的是后面那一面：§13.2 L1610 只允许
    // 被用过的 KeyPackage 在部署显式声明下重新流通，所以一枚变成 `consumed` 之后，重发不能
    // 把它复活。
    const h = harness()
    expect((await h.call(publishRequest({ id: 'req-1' }))).json?.error).toBeUndefined()
    expect(h.storage.markGroupKeyPackageConsumed(publisher.did, PUB_DEVICE, 'kp-1')).toBe('consumed')

    const again = await h.call(publishRequest({
      id: 'req-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
    }))
    expect(again.json?.error).toBeUndefined()
    expect(h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')?.state).toBe('consumed')
  })

  it('refuses a target that is not this service, with 1014', async () => {
    // §8.1.2 L696：`meta.target.did` MUST 等于发布方自己的 `serviceDid`。
    const h = harness()
    const outcome = await h.call(publishRequest({
      meta: publishMeta({ target: { kind: 'service', did: 'did:web:elsewhere.example' } }),
    }))
    expect(outcome.json?.error?.code).toBe(1014)
  })

  it('refuses a request without meta.sender_device_id, with 1003', async () => {
    // §4.3 L266：每个设备发起的 P6 请求 MUST 带它。方法表的 `requiredMeta` 就是这句话的
    // 落点——缺了它根本进不到处理器。
    const h = harness()
    const outcome = await h.call(publishRequest({ meta: publishMeta({ sender_device_id: undefined }) }))
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('sender_device_id')
  })

  it('refuses a body without group_key_package, with 1003', async () => {
    // §8.1.2 L697 的是**请求**的形状，与"它像不像一个 KeyPackage"（5001）是两件事。
    const h = harness()
    const outcome = await h.call(publishRequest({ body: {} }))
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('group_key_package')
  })

  it('refuses an ineligible publishing device, with 1017 (§4.2)', async () => {
    // §4.2 那四项少一项，发布方自己就不算数——一台没宣告 P6 的设备在这条链上没有意义。
    const doc = deviceDocument(publisher, PUB_DEVICE)
    const manifest = doc.deviceManifest as { devices: { profiles: string[] }[] }
    manifest.devices[0].profiles = ['anp.core.binding.v1', 'anp.identity.discovery.v1']
    const h = harness({ documents: { [publisher.did]: doc, [asker.did]: deviceDocument(asker, ASK_DEVICE) } })
    const outcome = await h.call(publishRequest())
    expect(outcome.json?.error?.code).toBe(1017)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.device_not_eligible')
  })
})

describe(`${GET_KEY_PACKAGE} (§8.2)`, () => {
  /** 发布一枚 KeyPackage，返回接下来可以直接问的那套东西。 */
  async function published(overrides: Record<string, unknown> = {}): Promise<Harness> {
    const h = harness()
    const outcome = await h.call(publishRequest({ body: { group_key_package: keyPackage(overrides) } }))
    expect(outcome.json?.error).toBeUndefined()
    return h
  }

  it('hands back the KeyPackage and reserves it (§8.2.4 L767)', async () => {
    const h = await published()
    const outcome = await h.call(getRequest())
    expect(outcome.json?.error).toBeUndefined()
    // §8.2.3 L751–755 的三个字段。
    expect(outcome.json?.result).toEqual({
      target_did: publisher.did,
      target_device_id: PUB_DEVICE,
      group_key_package: keyPackage(),
    })
    // 取用即占住：§8.2.4 L769 要求两次 `add` 不该复用同一枚，而认领是原子的条件 UPDATE，
    // 只有这样"两个人同时问"才不会各拿到一份。
    const row = h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')
    expect(row?.state).toBe('reserved')
    expect(row?.reservedTo).toBe(asker.did)
    expect(h.storage.availableGroupKeyPackages(publisher.did, PUB_DEVICE)).toHaveLength(0)
  })

  it('returns the same KeyPackage to a retry, and does not claim a second one', async () => {
    // §9.1 L630：同一条幂等键重试必须拿到同一个结果。实现上这不是"把分配键存下来"，而是
    // 命中同键时 `acceptOperation` 根本不调 `perform`（`accept.ts`），回放上次那份响应。
    const h = await published()
    // 第二枚用来观察"重试没有顺手动它"。
    await h.call(publishRequest({
      id: 'req-publish-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
      body: { group_key_package: keyPackage({ key_package_id: 'kp-2' }) },
    }))

    const first = await h.call(getRequest())
    const retry = await h.call(getRequest({ id: 'req-get-2' }))
    expect(retry.json?.result?.group_key_package).toEqual(first.json?.result?.group_key_package)
    expect(h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-2')?.state).toBe('available')
  })

  it('answers 5000 for a device that never published', async () => {
    const h = harness()
    const outcome = await h.call(getRequest())
    expect(outcome.json?.error?.code).toBe(5000)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.key_package_not_found')
  })

  it('answers 5000 once the only package has been reserved', async () => {
    // §8.2.4 L763 的 SHOULD 是"返回未**过期**未撤销未**消费**的"，而柜子里那些已经被别人
    // 认领走的不再是候选。这与 P5 的 OPK 池同构：`reserved` 是终态。
    const h = await published()
    expect((await h.call(getRequest({ meta: getMeta({ operation_id: 'op-get-1' }) }))).json?.error).toBeUndefined()
    const second = await h.call(getRequest({ meta: getMeta({ operation_id: 'op-get-2' }) }))
    expect(second.json?.error?.code).toBe(5000)
  })

  it('prefers an unexpired package, and falls back to an expired one only when asked loosely', async () => {
    // §8.2.4 L763 对"未过期的"只说 SHOULD，所以规范没有定义 `require_fresh`（§8.2.2 L743 是
    // 全篇唯一提到它的地方）。本实现只让它**收紧**那条 SHOULD：默认把过期的排在后面、全是
    // 过期时才回落；调用方要求了新鲜的就不回落。
    const h = await published({ key_package_id: 'kp-old', expires_at: '2026-09-01T00:00:00Z' })
    await h.call(publishRequest({
      id: 'req-publish-2',
      meta: publishMeta({ operation_id: 'op-publish-2' }),
      body: { group_key_package: keyPackage({ key_package_id: 'kp-new' }) },
    }))
    const loose = await h.call(getRequest({ meta: getMeta({ operation_id: 'op-get-1' }) }))
    expect(loose.json?.result?.group_key_package).toMatchObject({ key_package_id: 'kp-new' })

    // 只剩过期那一枚：不要求新鲜时照发（那条 SHOULD 允许），要求了就 5000。
    const expiredOnly = await published({ key_package_id: 'kp-old', expires_at: '2026-09-01T00:00:00Z' })
    const looseAgain = await h.call(getRequest({ meta: getMeta({ operation_id: 'op-get-2' }) }))
    expect(looseAgain.json?.error).toBeUndefined()
    expect(looseAgain.json?.result?.group_key_package).toMatchObject({ key_package_id: 'kp-old' })

    const strict = await expiredOnly.call(getRequest({
      meta: getMeta({ operation_id: 'op-get-3' }),
      body: { target_did: publisher.did, target_device_id: PUB_DEVICE, require_fresh: true },
    }))
    expect(strict.json?.error?.code).toBe(5000)
  })

  it('re-verifies the target against the current manifest, with 5002 (§8.2.4 L767)', async () => {
    // §8.2.4 L767 那条 MUST 说的是"**返回前**"按当前 P2 Manifest 重验目标设备。设备还在、
    // 但它换掉 `signing_key_id` 之后，柜子里存的那份已经没有任何合规接收方会用它入群
    // （§13.2 的重定义检查会拒掉），而我们还在照发。这个窗口正是发布新 KeyPackage 之前的那
    // 一小段，所以存下来的那份要再判一次。
    const h = await published()

    const second = createAnpIdentity('rotated.example')
    const secondKeyId = `${publisher.did}#key-2`
    const rotated = deviceDocument(publisher, PUB_DEVICE, { signingKeyId: secondKeyId })
    const secondKey = 'publicKeyMultibase' in second.publicKey ? second.publicKey.publicKeyMultibase : ''
    ;(rotated.verificationMethod as unknown[]).push({
      id: secondKeyId,
      type: 'Multikey',
      controller: publisher.did,
      publicKeyMultibase: secondKey,
    })
    ;(rotated.assertionMethod as unknown[]).push(secondKeyId)

    const moved = harness({
      storage: h.storage,
      documents: { [publisher.did]: rotated, [asker.did]: deviceDocument(asker, ASK_DEVICE) },
    })
    const outcome = await moved.call(getRequest())
    expect(outcome.json?.error?.code).toBe(5002)
    expect(outcome.json?.error?.data?.anp_code).toBe('anp.group.e2ee.did_binding_invalid')
  })

  it('re-checks eligibility on a replay too, with 1017', async () => {
    // `recheckOnReplay: true` 那一档：§8.2.4 L767 说的是"返回前"，所以**重放**也算一次返回
    // ——与 `get_prekey_bundle` 同一档（§7.2 L578）。一台设备失去资格之后，拿同一个
    // `operation_id` 重试不该还能把材料取走。
    const h = await published()
    const first = await h.call(getRequest())
    expect(first.json?.error).toBeUndefined()

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
    const replay = await stripped.call(getRequest({ id: 'req-get-2' }))
    expect(replay.json?.error?.code).toBe(1017)
  })

  it('refuses a target device that is not eligible before handing out material, with 1017', async () => {
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
    const outcome = await stripped.call(getRequest())
    expect(outcome.json?.error?.code).toBe(1017)
    // 一枚字节都没出去，所以那一枚也还是 `available`。
    expect(h.storage.groupKeyPackage(publisher.did, PUB_DEVICE, 'kp-1')?.state).toBe('available')
  })

  it('refuses a body without the target pair, with 1003', async () => {
    const h = await published()
    const outcome = await h.call(getRequest({ body: { target_did: publisher.did } }))
    expect(outcome.json?.error?.code).toBe(1003)
    expect(outcome.json?.error?.message).toContain('target_device_id')
  })

  it('refuses a non-boolean require_fresh, with 1003', async () => {
    // 收一个 `"true"` 再按真值判，会让调用方以为它在要求"只要新鲜的"，而服务端以为它没要求
    // （与 P5 的 `require_opk` 同一个坑）。
    const h = await published()
    const outcome = await h.call(getRequest({
      body: { target_did: publisher.did, target_device_id: PUB_DEVICE, require_fresh: 'true' },
    }))
    expect(outcome.json?.error?.code).toBe(1003)
  })
})

describe('the method table entries (§8.1 / §8.2)', () => {
  it('keeps the two KeyPackage methods service-scoped, in the P6 profile and key security mode', () => {
    const publishSpec = lookupMethod(PUBLISH_KEY_PACKAGE)
    const getSpec = lookupMethod(GET_KEY_PACKAGE)
    expect(publishSpec?.targetMode).toBe('service-scoped')
    expect(getSpec?.targetMode).toBe('service-scoped')
    // §4.1 L251 / §4.3 L264 与 L272：这两条在 P6 自己的 Profile 上，安全模式是
    // `transport-protected`（`group-e2ee` 留给四条控制方法）。
    expect(publishSpec?.profiles).toEqual(['anp.group.e2ee.v2'])
    expect(publishSpec?.securityProfiles).toEqual(['transport-protected'])
    // §4.3 L266：每个设备发起的 P6 请求 MUST 带 `sender_device_id`。
    expect(publishSpec?.requiredMeta).toEqual(['sender_did', 'sender_device_id', 'operation_id'])
  })

  it('has two different target scopes, with the getter keyed by target_did (§8.2)', () => {
    // §8.2 的幂等键元组比 §8.1 多一个 `target_did`——"问谁要"是这一次操作的一部分，而两条
    // 方法各自取自己规范里逐字给出的那一段，不复用看起来差不多的那一份。
    const publishSpec = lookupMethod(PUBLISH_KEY_PACKAGE)
    const getSpec = lookupMethod(GET_KEY_PACKAGE)
    expect(publishSpec?.targetScope?.(publishMeta(), {})).toBe(SERVICE_DID)
    expect(
      getSpec?.targetScope?.(getMeta(), { target_did: publisher.did, target_device_id: PUB_DEVICE }),
    ).toBe(`${SERVICE_DID}/${publisher.did}`)
  })

  it('has the device pair order the handlers read (caller first, target second)', () => {
    // `groupE2ee.ts` 的 `device(ctx, 0)` 是发布方，`device(ctx, 1)` 是目标设备，认的就是这
    // 个顺序——发布只点自己一台（§8.1.2 L697 那条路上没有收件人），领取点两台。
    const publishPairs = lookupMethod(PUBLISH_KEY_PACKAGE)?.deviceAddressed?.(publishMeta(), {})?.pairs
    expect(publishPairs).toEqual([{ identity: publisher.did, deviceId: PUB_DEVICE }])

    const getPairs = lookupMethod(GET_KEY_PACKAGE)?.deviceAddressed?.(getMeta(), {
      target_did: publisher.did,
      target_device_id: PUB_DEVICE,
    })?.pairs
    expect(getPairs).toEqual([
      { identity: asker.did, deviceId: ASK_DEVICE },
      { identity: publisher.did, deviceId: PUB_DEVICE },
    ])
  })

  it('re-checks eligibility on replay only for the getter (§8.2.4 L767)', () => {
    const publishAddressed = lookupMethod(PUBLISH_KEY_PACKAGE)?.deviceAddressed?.(publishMeta(), {})
    expect(publishAddressed?.recheckOnReplay).toBeUndefined()
    const getAddressed = lookupMethod(GET_KEY_PACKAGE)?.deviceAddressed?.(getMeta(), {
      target_did: publisher.did,
      target_device_id: PUB_DEVICE,
    })
    expect(getAddressed?.recheckOnReplay).toBe(true)
  })

  it('throws rather than inventing a scope when the request is missing its target', () => {
    // 到不了（`checkMethod` 保证 `service-scoped` 必带 target），但兜一个空串会算出一个人
    // 也不会再命中的键——那是比当场炸掉更坏的静默。
    const { target: _dropped, ...withoutTarget } = publishMeta()
    void _dropped
    expect(() => lookupMethod(PUBLISH_KEY_PACKAGE)?.targetScope?.(withoutTarget, {})).toThrow(ConnectxError)
  })
})

describe('the capability list (D2)', () => {
  it('does not advertise P6 as a stable profile, but still answers the methods', () => {
    // §6.3.1 L430：`anp_did_wba_device_binding` 那个 MLS `ExtensionType` 0xF0A1 **不是**
    // IANA 分配，且"ANP 在发布 v2 前 MUST 公布稳定的注册 code point"；§20 L2457 把那条注册
    // 列为后续版本 SHOULD 建立的注册表。于是实现照做、声明留白（`capabilities.ts` 的
    // `WITHHELD_PROFILES`，与官方 Rust crate 的 `ErrP6V2PublicReleaseBlocked` 同一个位置）。
    const caps = serviceCapabilities()
    expect(caps.profiles).not.toContain('anp.group.e2ee.v2')
    expect(caps.extensionProfiles).not.toContain('anp.group.e2ee.v2')
    // 也不许从 `x_` 那一侧绕进去：那条 Profile 不是本服务的扩展，它是**草案中的规范**。
    expect([...caps.profiles, ...caps.extensionProfiles]).not.toContain('anp.group.e2ee.v2')

    // 扣留的是 Profile，不是方法表——`lookupMethod` 仍然认这两条，直接发过来是能受理的
    // （§6.3.1 L431：该值"仅在显式协商 `anp.group.e2ee.v2` 后使用"，而显式协商就是调用方
    // 自己写明 `meta.profile`，不是靠这份清单）。
    expect(lookupMethod(PUBLISH_KEY_PACKAGE)).toBeDefined()
    expect(lookupMethod(GET_KEY_PACKAGE)).toBeDefined()
  })

  it('keeps transport-protected, and now claims group-e2ee with the four control methods', () => {
    // 安全模式**不**跟着 Profile 一起扣留：`transport-protected` 是 P1 的公共值，少列一个只是
    // 少说一句真话。`group-e2ee`（§4.3 L273）由 §9 那四条控制方法使用，而它们从 C13 起在方法
    // 表里——所以它**应该**出现。上一条测的是 Profile 名被扣留，这一条测的是安全模式名不受
    // 那条扣留的牵连；两者一起才说明 `WITHHELD_PROFILES` 只过滤 `profiles`。
    const caps = serviceCapabilities()
    expect(caps.securityProfiles).toContain('transport-protected')
    expect(caps.securityProfiles).toContain('group-e2ee')
  })
})
