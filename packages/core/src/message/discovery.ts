// ANP-09 P2 —— 发现：从目标 DID 走到**它那一个** ANPMessageService。
//
// 走的是 P2 §9.1 L549–560 那五步（Agent 与 Group 收敛到同一条）：解析文档 → 读
// `service` 列表 → 选出唯一的可跨域 `ANPMessageService` → 读 `serviceDid` →
// 结合静态 hint 与运行时能力。
//
// 定位（"文档里有什么服务"）在 `locator.ts`；这里只负责 P2 那条业务规则：
// **一份 DID 文档只许有一个对外公开的 ANPMessageService**（§7.1 L352–353）。

import { ConnectxError } from '../errors'
import { DidServiceLocator } from './locator'
import type { LocateOptions, ServiceLocator, ServiceEntry } from './locator'

/** P2 §7.2：DID 文档里那个对外公开的统一消息入口。 */
export const ANP_MESSAGE_SERVICE_TYPE = 'ANPMessageService'

/**
 * 一次发现的结果。静态 hint 与运行时能力**分开持有**，因为 §8.3 L586–590 规定
 * 两者冲突时以运行时为准——把它们合并成一个字段，就等于把这个 MUST 交给每个
 * 调用点各自记得。
 */
export interface AnpMessageServiceTarget {
  /** 文档是谁的——也就是 `meta.target.did` 该填的值。 */
  identity: string
  /** 服务条目的 `id`（P2 §8.1 L337 的三个必填成员之一）。 */
  serviceId: string
  /** `serviceEndpoint`。**不是** DID，是一个 HTTP(S) 传输地址。 */
  endpoint: string
  /** P2 §8.7 L504：跨域服务身份，**裸域名 DID**，不是 DID URL。
   *  只参与跨域调用时才 MUST 存在——同域调用可以没有它。 */
  serviceDid?: string
  /** 静态 hint（缓存用）。可能与运行时能力不同，见 {@link negotiateProfiles}。 */
  hintedProfiles: string[]
  hintedSecurityProfiles: string[]
}

export interface DiscoverMessageServiceOptions extends LocateOptions {
  /** 默认 `new DidServiceLocator()`，由 `locator.ts` 提供。传进来是为了让 CLI 的
   *  `--did-document` 这类内联文档路径（以及测试）不必绕开这一层。 */
  locator?: ServiceLocator
}

/**
 * 解析 `identity` 的 DID 文档，取它**唯一**的 ANPMessageService。
 *
 * 0 个或 2 个以上都拒。§7.1 L352 是 MUST：一份文档暴露两个可跨域入口时，跨域调用
 * 方无从选择，而且选错的那个也可能"看起来能用"——所以这不是"取第一个"能糊过去的
 * 情形。返回 `message_service_not_found` 并带上实际条数，让诊断不需要再查一遍文档。
 */
export async function discoverMessageService(
  identity: string,
  options: DiscoverMessageServiceOptions = {},
): Promise<AnpMessageServiceTarget> {
  const { locator = new DidServiceLocator(), ...locateOptions } = options
  const services = await locator.locate(identity, locateOptions)
  const matches = services.filter((s) => s.type === ANP_MESSAGE_SERVICE_TYPE)

  if (matches.length !== 1) {
    throw new ConnectxError(
      'message_service_not_found',
      `"${identity}" exposes ${matches.length} ANPMessageService entries; exactly one is required`,
      { cause: { count: matches.length } },
    )
  }

  const entry = matches[0] as ServiceEntry
  const target: AnpMessageServiceTarget = {
    identity,
    serviceId: entry.id,
    endpoint: entry.serviceEndpoint,
    hintedProfiles: entry.profiles ?? [],
    hintedSecurityProfiles: entry.securityProfiles ?? [],
  }
  if (entry.serviceDid !== undefined) target.serviceDid = entry.serviceDid
  return target
}

/**
 * P1 §8.2.2 L553–578 的 `anp.get_capabilities` 结果——**运行时权威**。
 *
 * 字段名是下划线式（`supported_profiles` / `service_did`），与 DID 文档里的
 * `profiles` / `serviceDid` 不同拼法。这不是笔误，两边都照抄。
 */
export interface AnpCapabilities {
  serviceDid?: string
  supportedProfiles: string[]
  supportedSecurityProfiles: string[]
  /** §8.2.2 L567：值也是**十进制字符串**（§7.3 L491）——别 `Number()` 掉。 */
  limits: Record<string, string>
  supportedContentTypes: string[]
}

/**
 * 解析 `anp.get_capabilities` 的 `result`。
 *
 * 缺 `supported_profiles` 或 `supported_security_profiles` 就拒：其余三项都是
 * 推荐 / 可选（§8.2.2 L578 只说 `supported_content_types` 是 SHOULD），但这两项
 * 缺失意味着这个服务没法被协商，静默补空数组会让调用方以为"对方什么都不会"。
 */
export function parseCapabilities(result: Record<string, unknown>): AnpCapabilities {
  const profiles = stringArray(result.supported_profiles)
  const securityProfiles = stringArray(result.supported_security_profiles)
  if (profiles === undefined || securityProfiles === undefined) {
    throw new ConnectxError(
      'message_invalid',
      'anp.get_capabilities result MUST carry supported_profiles and supported_security_profiles',
    )
  }
  const capabilities: AnpCapabilities = {
    supportedProfiles: profiles,
    supportedSecurityProfiles: securityProfiles,
    limits: stringRecord(result.limits),
    supportedContentTypes: stringArray(result.supported_content_types) ?? [],
  }
  if (typeof result.service_did === 'string') capabilities.serviceDid = result.service_did
  return capabilities
}

/**
 * §8.3 L588–589：静态 hint 与运行时能力冲突时，**以运行时为准**。
 *
 * 单独一个函数，是因为"哪个赢"如果散在各调用点，就总有一处会读错顺序——而错的那处
 * 不会报错，只会安静地用一个过期的 hint 去发消息。拿不到运行时结果（还没协商过、
 * 或协商失败）才回落到 hint。
 *
 * 回落是**整组**回落，不逐项回落到 hint：一半运行时、一半 hint 的组合谁也没定义过，
 * 而它看起来又是合法的。`source` 因此报的是这次到底用了哪一份。
 */
export function negotiateProfiles(input: {
  hinted: Pick<AnpMessageServiceTarget, 'hintedProfiles' | 'hintedSecurityProfiles'>
  runtime?: AnpCapabilities
}): { profiles: string[]; securityProfiles: string[]; source: 'runtime' | 'hint' } {
  if (input.runtime) {
    return {
      profiles: input.runtime.supportedProfiles,
      securityProfiles: input.runtime.supportedSecurityProfiles,
      source: 'runtime',
    }
  }
  return {
    profiles: input.hinted.hintedProfiles,
    securityProfiles: input.hinted.hintedSecurityProfiles,
    source: 'hint',
  }
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  return value.filter((v): v is string => typeof v === 'string')
}

function stringRecord(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {}
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v
  }
  return out
}
