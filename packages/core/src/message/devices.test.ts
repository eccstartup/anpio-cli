// P2 §5.5 的 `deviceManifest` 读取。用内联文档跑：`DeviceResolver` 的缝就是
// `LocateOptions.didDocument`，所以这里不需要网络，而"选哪一条"这个判定本身也就成了
// 可以直接观察的东西。

import { describe, expect, it } from 'vitest'
import { DidDeviceResolver } from './devices'

const ALICE = 'did:web:example.com:alice'

/** 一个 P2 §5.5 L236–256 那个例子形状的文档。两个 keyid 分别落在文档声明的关系里。 */
function document(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: ALICE,
    verificationMethod: [
      { id: `${ALICE}#dev-a-sign`, type: 'Multikey', controller: ALICE, publicKeyMultibase: 'z6Mk' },
      { id: `${ALICE}#dev-a-e2ee`, type: 'Multikey', controller: ALICE, publicKeyMultibase: 'z6LS' },
      { id: `${ALICE}#loose`, type: 'Multikey', controller: ALICE, publicKeyMultibase: 'z6Mk' },
    ],
    authentication: [`${ALICE}#dev-a-sign`],
    assertionMethod: [`${ALICE}#dev-a-sign`],
    keyAgreement: [`${ALICE}#dev-a-e2ee`],
    deviceManifest: {
      type: 'ANPDeviceManifest',
      devices: [
        {
          device_id: 'dev-a-7N3KQ2',
          signing_key_id: `${ALICE}#dev-a-sign`,
          e2ee_key_id: `${ALICE}#dev-a-e2ee`,
          profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1', 'anp.direct.e2ee.v2'],
        },
      ],
    },
    ...overrides,
  }
}

async function resolve(doc: unknown, deviceId: string, identity = ALICE) {
  return (await new DidDeviceResolver().resolveDevice(identity, deviceId, { didDocument: doc })).entries
}

describe('reading a deviceManifest', () => {
  it('hands back the document the entries came from', async () => {
    // Bundle 的 Object Proof 要从 **issuer 的文档**里取公钥（P5 §6.2.3 L395），而这次
    // 解析本来就已经把文档拿在手里了。只交条目会让同一次发布把它解析两遍——在验证路径上
    // 那是把"信任根是谁"确定两次，两次之间隔着一次网络往返。
    const doc = document()
    const resolved = await new DidDeviceResolver().resolveDevice(ALICE, 'dev-a-7N3KQ2', { didDocument: doc })
    expect(resolved.document).toBe(doc)
    expect(resolved.entries).toHaveLength(1)
  })

  it('hands back the four declared fields for the selected device', async () => {
    const [entry] = await resolve(document(), 'dev-a-7N3KQ2')
    expect(entry).toEqual({
      deviceId: 'dev-a-7N3KQ2',
      signingKeyId: `${ALICE}#dev-a-sign`,
      e2eeKeyId: `${ALICE}#dev-a-e2ee`,
      profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1', 'anp.direct.e2ee.v2'],
      // P2 §10.2.1：同一个 signing_key_id 在两处要落在不同的关系里，所以这里报**事实**，
      // 由 P5 按场合判。这个 keyid 两处都在，报两个。
      signingAuthorizedBy: ['authentication', 'assertionMethod'],
      e2eeAuthorizedBy: ['keyAgreement'],
    })
  })

  it('reports only the relationships the document actually lists', async () => {
    // `#loose` 是文档里存在、但没有任何关系引用它的验证方法。列在 `verificationMethod`
    // 里**不等于**可用（P2 §10.2.1 要的是关系）。
    const doc = document({ assertionMethod: [] })
    const [entry] = await resolve(doc, 'dev-a-7N3KQ2')
    expect(entry?.signingAuthorizedBy).toEqual(['authentication'])
  })

  it('selects nothing when the DID publishes no manifest at all', async () => {
    // P2 §5.5 规则 1：只支持 Base 的 DID **MAY** 省略它。省略不是"文档坏了"，
    // 是"这个 DID 不宣告设备定址"，两者都表现为"没有这台设备"。
    expect(await resolve(document({ deviceManifest: undefined }), 'dev-a-7N3KQ2')).toEqual([])
  })

  it('ignores a manifest whose type is not ANPDeviceManifest', async () => {
    // 规则 2 是 MUST。一个 `type` 是别的值的 `deviceManifest` 不是本规范的那个对象，
    // 按它选设备等于拿一个没人承诺过形状的东西当地址簿。
    const doc = document({ deviceManifest: { type: 'SomethingElse', devices: [{ device_id: 'x' }] } })
    expect(await resolve(doc, 'x')).toEqual([])
  })

  it('drops an entry that is missing one of the four required members', async () => {
    const doc = document({
      deviceManifest: {
        type: 'ANPDeviceManifest',
        devices: [
          { device_id: 'dev-a-7N3KQ2', signing_key_id: `${ALICE}#dev-a-sign`, e2ee_key_id: `${ALICE}#dev-a-e2ee` },
          { device_id: 'dev-b', signing_key_id: `${ALICE}#dev-a-sign`, e2ee_key_id: `${ALICE}#dev-a-e2ee`, profiles: 7 },
        ],
      },
    })
    // 缺 `profiles` 与 `profiles` 不是字符串数组，都整条丢掉：一个读不出依赖集的条目
    // 判不了资格，而"判不了"必须表现得像"没有这台设备"，不能表现得像"它合格"。
    expect(await resolve(doc, 'dev-a-7N3KQ2')).toEqual([])
    expect(await resolve(doc, 'dev-b')).toEqual([])
  })

  it('hands back every entry when a malformed document repeats a device_id', async () => {
    // 规则 3 要求 `device_id` 在清单内唯一。真出现两条时**不取第一条**：让调用方看见
    // 这份文档违规并按自己 Profile 的意思拒掉，而不是替它静默选一个。
    const entry = (sign: string) => ({
      device_id: 'dup',
      signing_key_id: `${ALICE}#${sign}`,
      e2ee_key_id: `${ALICE}#dev-a-e2ee`,
      profiles: ['anp.direct.e2ee.v2'],
    })
    const doc = document({
      deviceManifest: { type: 'ANPDeviceManifest', devices: [entry('dev-a-sign'), entry('loose')] },
    })
    const found = await resolve(doc, 'dup')
    expect(found).toHaveLength(2)
    expect(found.map((e) => e.signingAuthorizedBy)).toEqual([['authentication', 'assertionMethod'], []])
  })

  it('refuses an account id instead of reporting that it has no devices', async () => {
    // 账户 id（CAIP-10）上没有 `deviceManifest` 可读，也不该有——这与"这个 DID 没宣告
    // 任何设备"是两件事，回一个空数组会把前者说成后者。
    await expect(resolve(document(), 'dev-a-7N3KQ2', 'eip155:1:0xabc')).rejects.toThrow(/deviceManifest/)
  })
})
