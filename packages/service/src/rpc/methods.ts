// 方法表 —— 每个方法自己声明的东西。
//
// 信封层面能查的（jsonrpc / id / method / params 形状）在 core 的 `parseEnvelope` 里，
// §3 那张表里剩下的两行要的正是这个文件：目标建模模式（P1 §6.2.5.1 L361–378）与
// "还有哪些 `meta` 字段是这个方法必须带的"。
//
// 表放在一起而不是散在 handler 里，是因为这几件事**必须一起看**才对得上：目标模式错了
// 回哪个码、这个方法的 proof 缺失算 1005 还是 2005、幂等键的 `target_scope` 取哪个字段。
// 分开写就会有一处不一致，而那种不一致运行起来只表现为"某个码回得不对"，很难察觉。

import {
  anpRejection,
  ConnectxError,
  type AnpMeta,
  type AnpRejection,
  type AnpTarget,
  type AnpTargetKind,
} from '@agentx/core'
import { DIRECT_AUTH_CODES, type AuthErrorCodes } from './auth'

/**
 * P1 §6.2.5.1 L361–378 的四种模式。
 *
 * `endpoint-local` 是"允许省略 target"，不是"target 随便写"——它同样没有一个 `kind`
 * 要对上，所以下面那张表里它是 `undefined`。
 */
export type TargetMode = 'agent-addressed' | 'group-addressed' | 'service-scoped' | 'endpoint-local'

const TARGET_KIND: Record<TargetMode, AnpTargetKind | undefined> = {
  'agent-addressed': 'agent',
  'group-addressed': 'group',
  'service-scoped': 'service',
  'endpoint-local': undefined,
}

/** `meta` 里可以被方法声明点名的那几个字段。
 *
 *  用 `keyof AnpMeta` 而不是 `string` 是有意的：这个类型让表里写错字段名成为**编译错误**。
 *  写成 `string` 的话 `requiredMeta: ['messageId']` 编译得过，运行时又永远查不出缺失
 *  ——一条静默失效的 MUST。 */
export type MetaField = keyof AnpMeta

export interface MethodSpec {
  name: string
  /** P1 §6.2.5.1 L361–378：`meta.target.kind` 必须对上这个模式，否则 1014（L382）。 */
  targetMode: TargetMode
  /** 本服务为这个方法实现了哪些 `meta.profile`（P1 §6.2.2 L277）。不在表里 → 1001。 */
  profiles: readonly string[]
  /** 同上，`meta.security_profile`（P1 §6.2.3）→ 1002。 */
  securityProfiles: readonly string[]
  /** 这个方法**必须**带的 `meta` 字段，缺一个 → 1003。
   *  `target` 不在这里：它由 `targetMode` 管，报的码不同（1014 而不是 1003）。 */
  requiredMeta: readonly MetaField[]
  /** **不得**出现的 `meta` 字段，出现即 1003。 */
  forbiddenMeta: readonly MetaField[]
  /** 这次调用是否必须带 `auth.origin_proof`。 */
  requiresOriginProof(meta: AnpMeta): boolean
  /** 证明不通过时用哪一对码（P1 §10.3 L706 vs P3 §11 L599–600）。 */
  authCodes: AuthErrorCodes
  /** Profile 定义的幂等 `target_scope`（P1 §9.1 L635 + P3 §8.2 L437–442）。
   *  `undefined` 表示这个方法不改状态，也就不进幂等台账。 */
  targetScope?: (meta: AnpMeta, body: Record<string, unknown>) => string
}

export const DIRECT_SEND = 'direct.send'

/** 直连私聊。`meta.target.kind` 必须是 `agent`（P3 §5.1 L172）。 */
const DIRECT_SEND_SPEC: MethodSpec = {
  name: DIRECT_SEND,
  targetMode: 'agent-addressed',
  profiles: ['anp.direct.base.v1'],
  securityProfiles: ['transport-protected'],
  requiredMeta: ['sender_did', 'operation_id', 'message_id', 'content_type'],
  // P3 §7.1.2 L362：设备 selector 只属于 P5 v2。P1 §10.3 L724 说 Base 操作收到 selector
  // 就按"非法参数"处理——1015–1018 那四个码专给设备定址 Overlay，这里不许用。
  forbiddenMeta: ['sender_device_id', 'recipient_device_id'],
  // P3 §6.4 L290 要求 base + transport-protected 必须带 `auth`。P3 §4.3 L161 让
  // `anp.direct.e2ee.v2` 整个覆盖掉这条强制要求（该 Overlay 用建链材料与 AAD 认证发送方，
  // 为的是保住更强的可否认性）。那个 profile 是 C12 的，届时加进上面的 `profiles` 即可，
  // 判断保持写在这一处。
  requiresOriginProof: (meta) => meta.profile !== 'anp.direct.e2ee.v2',
  authCodes: DIRECT_AUTH_CODES,
  // P3 §8.2 L437–442：`(sender_did, target.did, method, operation_id)`。
  targetScope: (meta) => {
    const target = meta.target
    // dispatch 已经查过目标绑定（1014），所以这里必定存在。抛而不是兜一个空串：
    // 空串会算出一个谁也不会再命中的键，那比当场炸掉更坏。
    if (target === undefined) throw new ConnectxError('message_invalid', 'direct.send requires meta.target')
    return target.did
  },
}

const METHODS: readonly MethodSpec[] = [DIRECT_SEND_SPEC]

export function lookupMethod(name: string): MethodSpec | undefined {
  return METHODS.find((spec) => spec.name === name)
}

/** `meta.target` 是否满足这个方法声明的建模模式（P1 §6.2.5.1 L363–378）。
 *  `target` 缺失由调用方先判（那是 1003），到这里只判 `kind` 对不对。 */
export function targetBindingHolds(spec: MethodSpec, target: AnpTarget | undefined): boolean {
  const kind = TARGET_KIND[spec.targetMode]
  // endpoint-local：允许省略，也就没有 kind 可以对错。
  if (kind === undefined) return true
  return target?.kind === kind
}

/**
 * 方法自己声明的那些 MUST，按 §3 那张表的顺序查一遍。
 *
 * 信封层面查不到的都在这里：Profile（§6.2.2 L277）、安全模式（§6.2.3）、这个方法还要求
 * 哪些 `meta` 字段、以及目标建模模式（§6.2.5.1 L382）。`parseEnvelope` 已经保证 `meta`
 * 是个对象、`target` 的形状合法、`kind` 是三个词之一，所以这里只判"这个方法要不要求"。
 *
 * **缺失 `target` 报 1003，不是 1014**：L382 那条 MUST 说的是"`kind` 与声明的模式不一致"，
 * 前提是 `target` 在；一个连 `target` 都没有的请求，错的是 `params` 的形状（§10.3 L704）。
 * 这是本实现的读法，规范没有为"该有却没有"单独配码。
 */
export function checkMethod(spec: MethodSpec, meta: AnpMeta): AnpRejection | undefined {
  if (!spec.profiles.includes(meta.profile)) {
    return anpRejection('anp.unsupported_profile', `${spec.name} does not implement profile ${meta.profile}`)
  }
  if (!spec.securityProfiles.includes(meta.security_profile)) {
    return anpRejection(
      'anp.unsupported_security_profile',
      `${spec.name} does not implement security profile ${meta.security_profile}`,
    )
  }
  for (const field of spec.requiredMeta) {
    if (meta[field] === undefined) {
      return anpRejection('anp.invalid_params_shape', `${spec.name} requires meta.${field}`)
    }
  }
  for (const field of spec.forbiddenMeta) {
    if (meta[field] !== undefined) {
      return anpRejection('anp.invalid_params_shape', `${spec.name} forbids meta.${field}`)
    }
  }

  // §6.2.5 L341 与 §6.2.5.1 L377–380：target 必不必填，由建模模式决定。L1068 再补一条
  // ——只要这个方法要 `origin_proof`，`meta.target` 就 MUST 存在，因为 `@target-uri` 要用
  // 它的 kind 与 did（L1062）。两条取并：一个 endpoint-local 方法将来若要 proof，仍然
  // 必须带 target，而那正是 L1070 要求它的 Profile 显式定义的东西。
  const needsTarget = spec.targetMode !== 'endpoint-local' || spec.requiresOriginProof(meta)
  if (meta.target === undefined) {
    if (!needsTarget) return undefined
    return anpRejection(
      'anp.invalid_params_shape',
      `${spec.name} is ${spec.targetMode} and requires meta.target`,
    )
  }
  if (!targetBindingHolds(spec, meta.target)) {
    return anpRejection(
      'anp.invalid_target_binding',
      `${spec.name} is ${spec.targetMode}; meta.target.kind MUST be ${String(TARGET_KIND[spec.targetMode])}`,
      { details: { received: meta.target.kind } },
    )
  }
  return undefined
}
