// P2 §5.5 / §10.2.1 —— 设备清单（`deviceManifest`）的读取。
//
// 清单住在 **Agent DID 文档的顶层**（P2 §5.5 L227），只有宣告了设备定址 E2EE Profile 的
// DID 才必须有它（P2 §5.5 L263 规则 1）——Base 消息不查它，也不该查。它是"这台设备此刻算
// 不算数"的**唯一**来源：P2 §12 L947 明说资格判定只能看当前清单、它引用的钥、宣告的能力
// 与该 Profile 自己的规则，**不得**依赖任何未声明的注册表版本或检查点。所以这里没有缓存、
// 没有版本号，每次问都是当下这一份。
//
// 本模块只做**读取与形状**：把 `device_id` 选中的条目按 P2 §5.5 L264 的四项交出去。三件
// 事刻意留在外面，因为它们都是 Profile 的判定，不是清单的形状：
//
//   - **"恰好一条才算选中"**——P5 §4.1.1 第 1 项。与 `DidServiceLocator` 交出全部服务条目
//     是同一个分工：这一层回答"文档里有什么"，选哪一条是上层的事。
//   - **"这条要宣告哪个 Profile"**——P5 要 `anp.direct.e2ee.v2`，P6 要另外的集合。
//   - **"钥引用要落在哪个验证关系里"**——P5 §4.1.1 第 3 项要 `assertionMethod` 与
//     `keyAgreement`。这里只把**事实**（这个 keyid 被哪些关系授权）报出去，判定归调用方。
//
// 把这三件收进来，就等于替所有 Profile 决定了它们该怎么判——而它们要判的并不一样。

import { isMethodAuthorized, resolveDidDocument } from '../crypto/resolveDid'
import type { ResolveDidOptions } from '../crypto/resolveDid'
import { ConnectxError } from '../errors'
import { isDidIdentity, type LocateOptions } from './locator'

/** P2 §5.5 L237 规则 2：`deviceManifest.type` **MUST** 等于这个值。 */
export const DEVICE_MANIFEST_TYPE = 'ANPDeviceManifest'

/**
 * P2 §10.2.1 L629–L631 点名的三个验证关系，外加 `capabilityInvocation`——本模块只做
 * **事实报告**，所以它按文档里实际出现的关系名收，而不是按 P5 用得到的那几个收。
 */
export type DeviceRelationship = 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation'

const RELATIONSHIPS: readonly DeviceRelationship[] = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityInvocation',
]

/**
 * P2 §5.5 L264 规则 2 的**恰好四项**：`device_id`、`signing_key_id`、`e2ee_key_id`、
 * `profiles`。多出来的字段不拒也不留——规范说的是"**MUST** contain exactly"，而多一个
 * 未知字段是文档作者的自由，把它变成拒绝理由会让本实现比规范更严。
 */
export interface DeviceEntry {
  /** P2 §5.5 L265 规则 3：不透明字符串，在当前 Agent DID 清单内唯一，移除后不得复用。 */
  deviceId: string
  /** 同规则 4：DID URL，指向同一 Agent DID 文档里的验证方法。 */
  signingKeyId: string
  /** 同规则 4：DID URL，**MUST** 被 `keyAgreement` 授权。 */
  e2eeKeyId: string
  /** 同规则 5：**完整**依赖集。P5 条目因此含 P1 / P2 / P3 三族。 */
  profiles: readonly string[]
  /**
   * `signing_key_id` 在文档里被哪些关系授权。
   *
   * 之所以把事实报出来而不是替调用方判：P2 §10.2.1 L630 说同**一个** `signing_key_id`，
   * 在 `origin_proof` 场合要落 `authentication`（那是登录钥），在 Bundle 证明场合要落
   * `assertionMethod`（那是声明钥）；两个场所的要求不同，而"这条设备现在算不算数"的答案
   * 也随之不同。本模块没有立场替它们选一个。
   */
  signingAuthorizedBy: readonly DeviceRelationship[]
  /** `e2ee_key_id` 被哪些关系授权。P2 §5.5 规则 4 只要求 `keyAgreement`。 */
  e2eeAuthorizedBy: readonly DeviceRelationship[]
}

/**
 * 身份 + 设备 selector → 清单里 `device_id` 等于它的**那些**条目。
 *
 * 复数不是笔误：P2 §5.5 规则 3 要求 `device_id` 在清单内唯一，所以正常情况下至多一条；
 * 返回数组是让"文档违规（有两条）"这件事能被调用方看见并按 Profile 的意思拒掉，而不是
 * 在这里悄悄取第一条——取第一条会把一次文档错误变成一次静默的选错设备。
 */
export interface DeviceResolver {
  resolveDevice(identity: string, deviceId: string, opts?: LocateOptions): Promise<DeviceEntry[]>
}

/** 文档里的 `deviceManifest` 是否是 P2 §5.5 规定的形状；是就交出它那个 `devices` 数组。
 *
 *  返回类型写 `unknown[] | undefined` 而不是 `unknown`：调用方紧接着要 `filter`，而
 *  `unknown` 在排掉 `undefined` 之后收窄成 `{}`——一个没有 `filter` 的类型，且仍然带着
 *  `null`。把形状判到这一层，调用点就不必再判一次。 */
function manifestDevices(document: Record<string, unknown>): unknown[] | undefined {
  const manifest = document.deviceManifest
  if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) return undefined
  if ((manifest as Record<string, unknown>).type !== DEVICE_MANIFEST_TYPE) return undefined
  const devices = (manifest as Record<string, unknown>).devices
  return Array.isArray(devices) ? devices : undefined
}

/** 一个条目是否四项齐全。缺一项就整条丢掉：一个只有 `device_id` 的条目**不是**设备。 */
function isDeviceEntry(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const v = value as Record<string, unknown>
  return (
    typeof v.device_id === 'string' &&
    typeof v.signing_key_id === 'string' &&
    typeof v.e2ee_key_id === 'string' &&
    Array.isArray(v.profiles) &&
    v.profiles.every((p) => typeof p === 'string')
  )
}

function relationshipsOf(document: Record<string, unknown>, keyid: string): DeviceRelationship[] {
  return RELATIONSHIPS.filter((relationship) => isMethodAuthorized(document, relationship, keyid))
}

function toDeviceEntry(document: Record<string, unknown>, value: Record<string, unknown>): DeviceEntry {
  const signingKeyId = value.signing_key_id as string
  const e2eeKeyId = value.e2ee_key_id as string
  return {
    deviceId: value.device_id as string,
    signingKeyId,
    e2eeKeyId,
    profiles: [...(value.profiles as string[])],
    signingAuthorizedBy: relationshipsOf(document, signingKeyId),
    e2eeAuthorizedBy: relationshipsOf(document, e2eeKeyId),
  }
}

/**
 * v1 的 DID 实现：读 DID 文档顶层的 `deviceManifest`。
 *
 * 文档里**没有** `deviceManifest` 与"清单里没有这台设备"是**两件不同的事实**，这里都
 * 交回一个空数组——与 `DidServiceLocator` 同样的取舍：把"文档没宣告设备定址"与"你选的
 * 那台不在"分成两个码，是上层看得到文档时才能做的判断，而把文档形状的判断提前塞进这一层，
 * 会让它对"内联文档"与"取来的文档"两种来源都多知道一件事。
 */
export class DidDeviceResolver implements DeviceResolver {
  async resolveDevice(identity: string, deviceId: string, opts: LocateOptions = {}): Promise<DeviceEntry[]> {
    if (!isDidIdentity(identity)) {
      // 账户 id（CAIP-10）上没有 `deviceManifest` 可读，也不该有：清单挂在 DID 文档上。
      throw new ConnectxError(
        'caip10_has_no_ingress',
        `"${identity}" is not a DID, so it publishes no deviceManifest`,
      )
    }
    const document =
      opts.didDocument !== undefined
        ? (opts.didDocument as Record<string, unknown>)
        : (await resolveDidDocument(identity, opts as ResolveDidOptions)).document
    const devices = manifestDevices(document)
    if (devices === undefined) return []
    return devices
      .filter(isDeviceEntry)
      .filter((entry) => entry.device_id === deviceId)
      .map((entry) => toDeviceEntry(document, entry))
  }
}
