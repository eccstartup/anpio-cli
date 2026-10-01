// P5 §4.1.1 的四项判定。用假的 `DeviceResolver` 跑：这一层要判的是"清单交回什么时算数"，
// 而"清单怎么读"是 core 的 `devices.test.ts` 在管。两个文件各测一半，中间那条缝就是
// `DeviceResolver` 这个接口。
//
// 错误码是这一层的产出，所以每个用例都盯着 `anpCode` 而不只是"拒了"——§4.1.1 的四项对应
// 三个码（1016 / 1017），配错的表现是调用方按诊断改错了地方。

import { describe, expect, it } from 'vitest'
import type { DeviceEntry, DeviceResolver } from '@agentx/core'
import { DIRECT_E2EE_DEVICE } from './e2ee'
import { checkDevice, deviceSelector, isRejection, type EligibleDevice } from './eligibility'

const ALICE = 'did:web:example.com:alice'
const DEV = 'dev-a-7N3KQ2'

/** 一个只答一次问的解析器。`resolveDevice` 是唯一的缝，所以不必模拟 DID 文档。
 *
 *  §4.1.1 L178 第 4 项要的是"这份 Bundle 与**交出它的**那份文档"，所以解析器交回形状里
 *  文档与条目是一起走的——只回答条目会让 Bundle 的 proof 无从验起（`EligibleDevice`）。 */
function resolverAnswering(entries: DeviceEntry[], document: Record<string, unknown> = { id: ALICE }): DeviceResolver {
  return {
    resolveDevice: () => Promise.resolve({ entries, document }),
  }
}

function entry(overrides: Partial<DeviceEntry> = {}): DeviceEntry {
  return {
    deviceId: DEV,
    signingKeyId: `${ALICE}#dev-a-sign`,
    e2eeKeyId: `${ALICE}#dev-a-e2ee`,
    // P2 §5.5 L267 规则 5：`profiles` 是**完整**依赖集，所以合格的那一份要把四项都写上。
    profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1', 'anp.direct.e2ee.v2'],
    signingAuthorizedBy: ['assertionMethod'],
    e2eeAuthorizedBy: ['keyAgreement'],
    ...overrides,
  }
}

function check(entries: DeviceEntry[], requirement = DIRECT_E2EE_DEVICE) {
  return checkDevice({ resolver: resolverAnswering(entries), requirement, identity: ALICE, deviceId: DEV })
}

describe('checkDevice', () => {
  it('hands the entry back when all four conditions hold', async () => {
    const outcome = await check([entry()])
    expect(isRejection(outcome)).toBe(false)
    if (isRejection(outcome)) throw new Error('unreachable')
    expect(outcome.entry.deviceId).toBe(DEV)
    // 交回的文档与条目是同一次解析的产物——Bundle 的 proof 只有对着**这一份**才说明得了
    // 事情（`EligibleDevice` 上写了理由）。
    expect(outcome.document.id).toBe(ALICE)
  })

  it('refuses a device the manifest does not list, with 1017', async () => {
    // §4.1.1 第 1 项。零条是"这台设备不在当前清单里"，调用方能做的是换一台再试——它
    // 改不了自己的清单，所以码要说的是"这台不算数"，而不是"你的文档坏了"。
    const outcome = await check([])
    expect(outcome).toMatchObject({ anpCode: 'anp.device_not_eligible' })
  })

  it('refuses a manifest that lists the device twice, with 1016 and not 1017', async () => {
    // P2 §5.5 规则 3 要求 `device_id` 唯一。两条是**文档违规**，不是"这台设备晚了"——
    // 两者的处置完全不同（一个是换设备，一个是修文档），共用一个码会把后者说成前者。
    const outcome = await check([entry(), entry({ signingKeyId: `${ALICE}#other` })])
    expect(outcome).toMatchObject({ anpCode: 'anp.device_binding_invalid' })
  })

  it('refuses an entry that does not declare the whole dependency set, with 1017', async () => {
    // §4.1.1 第 2 项。少一项就整条不算数：依赖集不完整意味着这台设备没有承诺它会处理
    // 哪一族，而"没承诺"不能读成"承诺了"。
    const outcome = await check([entry({ profiles: ['anp.direct.e2ee.v2'] })])
    expect(outcome).toMatchObject({ anpCode: 'anp.device_not_eligible' })
    if (!isRejection(outcome)) throw new Error('unreachable')
    expect(outcome.details).toMatchObject({
      missing_profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1'],
    })
  })

  it('refuses a signing key that is not in assertionMethod, with 1016', async () => {
    // §4.1.1 第 3 项。P2 §10.2.1 L629–631 说同一个 keyid 在不同场合要落在不同关系里，
    // 而 Bundle 用的是 Object Proof —— 落 `authentication` 不算数，哪怕它确实被授权了。
    const outcome = await check([entry({ signingAuthorizedBy: ['authentication'] })])
    expect(outcome).toMatchObject({ anpCode: 'anp.device_binding_invalid' })
  })

  it('refuses an e2ee key that is not in keyAgreement, with 1016', async () => {
    // P2 §5.5 规则 4：`e2ee_key_id` **MUST** 被 `keyAgreement` 授权。
    const outcome = await check([entry({ e2eeAuthorizedBy: ['authentication', 'assertionMethod'] })])
    expect(outcome).toMatchObject({ anpCode: 'anp.device_binding_invalid' })
  })

  it('reports the signing-key failure before the e2ee one', async () => {
    // 两条都错时报前一条。顺序不是任意的：诊断要指出**先**该改的那一处，否则调用方会
    // 改完第二条再来一次，而第一次的答复一直是没用的。
    const outcome = await check([
      entry({ signingAuthorizedBy: [], e2eeAuthorizedBy: [] }),
    ])
    if (!isRejection(outcome)) throw new Error('unreachable')
    expect(outcome.message).toContain('signing_key_id')
  })

  it('takes its requirement from the caller, not from P5', async () => {
    // 这一层不替任何 Profile 做主：同一个条目在 P5 的要求下合格，在另一套关系下不合格。
    const outcome = await check([entry({ signingAuthorizedBy: ['authentication'] })], {
      profiles: ['anp.core.binding.v1'],
      signingRelationship: 'authentication',
      e2eeRelationship: 'keyAgreement',
    })
    expect(isRejection(outcome)).toBe(false)
  })
})

describe('isRejection', () => {
  it('separates the two outcomes on a field only a refusal has', () => {
    // 判别式取 `code`：将来给 `DeviceEntry` 加一个字段不会让它失效，而按"有没有哪个
    // 业务字段"去判会。
    const eligible: EligibleDevice = { entry: entry(), document: { id: ALICE } }
    expect(isRejection({ code: 1017, anpCode: 'anp.device_not_eligible', message: 'x' } as never)).toBe(true)
    expect(isRejection(eligible)).toBe(false)
  })
})

describe('deviceSelector', () => {
  it('carries the owner, because a device_id is an opaque string (P2 §5.5 L263)', () => {
    expect(deviceSelector({ identity: ALICE, deviceId: DEV })).toBe(`${ALICE}#${DEV}`)
    // 同一个 `device_id` 挂在两个 DID 下必须是两段不同的 selector——这正是"只写设备 id"
    // 丢掉的那一半。两侧各自取名，撞上同一个 `dev-a` 完全可能，那时
    // "S 的 a → R 的 b" 与 "S 的 b → R 的 a" 会算出同一个幂等键（1008）。
    expect(deviceSelector({ identity: ALICE, deviceId: DEV })).not.toBe(
      deviceSelector({ identity: 'did:web:example.com:bob', deviceId: DEV }),
    )
  })
})
