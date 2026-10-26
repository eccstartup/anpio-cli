// C12 —— P5 §7 的两条密钥控制面方法：发布与领取 PreKey 材料。
//
// 它们与 `direct.send`（`e2ee.ts`）是**同一份规范的两半**：那一条搬密文，这两条搬建链材料。
// 共同的部分已经在那里了——Profile 名、安全模式、设备资格的四项依赖集、`auth` 必须缺省——
// 所以这里只写这两条各自的那部分。
//
// ## 服务端到底验什么
//
// §6.5 把 Bundle 的八项验证写成**发送方**的 MUST，§7 又要求服务端在**收下**和**交出**材料
// 之前各自判一遍。两处不是重复：发送方验的是"我拿到的这份材料能不能用"，服务端验的是
// "这份材料是不是这个设备的、此刻还算不算数"。判据不同、时机不同，结论也因此可以不同。
//
// 服务端这一侧的依据是 §4.1.1 L178 第 4 项——**"Before publishing, returning, or using P5
// material for (D, d)"**，实现 MUST 按当前 DID 文档确认"Bundle / Session / AAD / 重放状态 /
// 信箱操作用的是同一个 DID、设备与密钥引用"。逐字点到了 Bundle 与 returning，所以下面
// `bundleBindingProblem` 在**发布与领取两侧都要跑**，不是只跑发布。
//
// ## 码的分派
//
// §13 L1531–1545 那一段是 4000–4012，另有一句把两类情形分出去（L1547）：
//
//   - **不合附录 B 的 proof**、`proof` 的 issuer 与 `owner_did` 不一致 → **4001**
//     `bundle_invalid`（§6.2.3 L379 逐字指定）。
//   - Core 的**设备**判定失败 → 1015–1018（由 `eligibility.ts` 报，不在本模块）。
//   - Core 资格**通过之后**，"Bundle owner、密钥引用、Session 对、AAD、信箱"里的不一致
//     → **4012** `invalid_security_binding`（L1547 逐字列出这几类）。
//
// 所以下面 `Bundle owner 与 meta.sender_* 不符`、`static_key_agreement_id` 与清单的
// `e2ee_key_id` 不符、`proof` 用的不是清单那条 `signing_key_id` 三处都回 4012；而
// "这个对象根本不像一个 Bundle"（§6.3 L383–397 那两份清单）回 4001——它是**对象的定义**，
// 不是某个字段与另一处的比对。
//
// ## 两个码在本服务里没有产生路径
//
//   - **4002 `bundle_expired`**：§6.5 第 6 项把"`signed_prekey.expires_at` 未过期"写成
//     **发送方**的 MUST，而 §6.3 L383–391 那份 `MUST contain` 清单里**没有** `expires_at`
//     ——本服务因此既不要求它、也不判它。每设备只留一行"最新"的 Bundle（§7.3 L592），所以
//     "过期了但池子里还有旧的"这种情形在本服务里构造不出来。
//   - **4004 `missing_key_agreement`**：本服务不解析 Bundle 里的钥，`keyAgreement` 有没有
//     对应的条目由 §4.1.1 第 3 项那次资格判定回答（`eligibility.ts`）。

import {
  anpRejection,
  canonicalDidUrl,
  profileRejection,
  verifyObjectProofDetailed,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
} from '@anpio-cli/core'
import type { Storage } from '../storage/types'
import type { EligibleDevice } from './eligibility'
import { refusal } from './refusal'

export const PUBLISH_PREKEY_BUNDLE = 'direct.e2ee.publish_prekey_bundle'
export const GET_PREKEY_BUNDLE = 'direct.e2ee.get_prekey_bundle'

// ---- 错误码 ------------------------------------------------------------------

function pair(code: number, anpCode: string): { code: number; anpCode: string } {
  return { code, anpCode }
}

/**
 * §13 L1533–1545 里**本服务会发**的那两个。走 `profileRejection` 而不是 `anpRejection`：
 * 这一段不在 P1 的公共表里，码值也不在 1000–1021 之间。
 */
const KEY_ERRORS = {
  bundleInvalid: pair(4001, 'anp.direct.e2ee.bundle_invalid'),
  bundleNotFound: pair(4000, 'anp.direct.e2ee.bundle_not_found'),
  opkUnavailable: pair(4003, 'anp.direct.e2ee.opk_unavailable'),
  binding: pair(4012, 'anp.direct.e2ee.invalid_security_binding'),
} as const

type KeyErrorName = keyof typeof KEY_ERRORS

function keyError(name: KeyErrorName, message: string, details?: Record<string, unknown>): AnpRejection {
  const codes = KEY_ERRORS[name]
  return profileRejection(codes.code, codes.anpCode, message, details !== undefined ? { details } : {})
}

/** 形状问题一律 §10.3 L704 的 1003：错的是请求本身，不是 Bundle，也不是权限。 */
function shapeProblem(message: string): AnpRejection {
  return anpRejection('anp.invalid_params_shape', message)
}

/** P1 §10.3 L716 的 1018。见下面 `bundleBindingProblem` 里那条"清单已变"的判据。 */
function stateChanged(message: string): AnpRejection {
  return anpRejection('anp.device_state_changed', message)
}

// ---- 小工具 ------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** 规范在这两处要的都是"非空字符串"而不是"字段在场"（§7.1 L472–476）：空串能通过
 *  `!== undefined`，但一个空的 `bundle_id` 说明不了任何事。 */
function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== ''
}

/**
 * §7.1 / §7.2 都写着 `params.auth` **MUST** 缺省（未协商扩展时），与 §3.8 L140 对 v2 的
 * `direct.send` 是同一条要求、同一个理由：这两条路上发送方由建链材料与 AAD 认证，
 * 不要再叠一层业务证明。码同 v2——"这个字段不该在这儿"是 1003（§10.3 L724）。
 */
export function keyMethodParams(params: AnpParams): AnpRejection | undefined {
  if (params.auth !== undefined) {
    return shapeProblem('params.auth MUST be absent unless the Direct Init Accountability Extension is negotiated')
  }
  return undefined
}

// ---- §6.3 的 Bundle 定义 -------------------------------------------------------

/** §6.3 L383–391：`prekey_bundle` **MUST** contain 这六项。 */
const BUNDLE_FIELDS = ['bundle_id', 'owner_did', 'owner_device_id', 'suite', 'static_key_agreement_id'] as const

/**
 * "这个对象**是**一个 Bundle 吗"（§6.3 L383–397）。不是就是 4001。
 *
 * 不在这里判的：`proof` 算不算数（要 issuer 文档，见 `proofProblem`），以及 `owner_*` 与
 * 调用方对不对得上（那是"与另一处的比对"，4012）。`signed_prekey.expires_at` 也不在这里
 * ——§6.5 第 6 项把它写成发送方的 MUST，而本服务没有 4002 的产生路径（文件头写了理由）。
 */
function bundleShapeProblem(bundle: Record<string, unknown>): AnpRejection | undefined {
  for (const field of BUNDLE_FIELDS) {
    if (!nonEmptyString(bundle[field])) {
      return keyError('bundleInvalid', `prekey_bundle.${field} MUST be a non-empty string`)
    }
  }
  const spk = bundle.signed_prekey
  if (!isPlainObject(spk)) {
    return keyError('bundleInvalid', 'prekey_bundle.signed_prekey MUST be an object')
  }
  // 这两项是 §6.5 第 1、2 项与 §8 的 DH 各自要用的，缺一项这份 Bundle 就没有接收方能用它
  // 建链——`signed_prekey` 里没有钥的 "signed_prekey" 不是 signed_prekey。
  if (!nonEmptyString(spk.key_id)) {
    return keyError('bundleInvalid', 'prekey_bundle.signed_prekey.key_id MUST be a non-empty string')
  }
  if (!nonEmptyString(spk.public_key_b64u)) {
    return keyError('bundleInvalid', 'prekey_bundle.signed_prekey.public_key_b64u MUST be a non-empty string')
  }
  // §6.3 L393–395 逐字：`prekey_bundle` **MUST NOT** directly contain `one_time_prekey`。
  // 理由在 §6.2 L300：OPK 是**按次发放**的，塞进静态对象就等于让它落在静态 proof 之外
  // 却随静态对象一起被缓存——发送方仍然得找服务端要一枚可用的。
  if (bundle.one_time_prekey !== undefined) {
    return keyError('bundleInvalid', 'prekey_bundle MUST NOT embed one_time_prekey')
  }
  return undefined
}

/**
 * §6.2.2 L371：接受窗口内同一个 `bundle_id` **MUST** 唯一映射到这六项的组合。
 *
 * 同一行还给了另一半——"MAY accept multiple different `bundle_id` values concurrently"
 * ——所以**换了 `bundle_id` 就是另一份 Bundle**，允许覆盖；只有"同一个 `bundle_id` 指向了
 * 不同的组合"才是 MUST NOT。本服务每设备只留最新一行，那个 MAY 因此在存储上表现为覆盖，
 * 判定不受影响。
 *
 * `JSON.stringify` 一个字符串数组当键：六项都是字符串，数组形式没有任何拼接歧义（与
 * core 的 `idempotencyKey()` 用长度前缀是同一个理由，只是这里没有分隔符可撞）。
 */
function bundleIdentity(bundle: Record<string, unknown>): string {
  const spk = bundle.signed_prekey as Record<string, unknown>
  return JSON.stringify([
    bundle.owner_did,
    bundle.owner_device_id,
    bundle.suite,
    bundle.static_key_agreement_id,
    spk.key_id,
    spk.public_key_b64u,
  ])
}

/**
 * §4.1.1 L178 第 4 项：Bundle 与**当前**清单条目必须用同一套 DID / 设备 / 密钥引用。
 *
 * 这一条是**领取侧**要跑的那半。发布侧的同一件事在 `publishPrekeyBundle` 里按 §7.1 的
 * 字段要求逐项写了（那里知道更多：调用方是谁、`meta.sender_*` 是什么）；这里只知道"这份
 * 存下来的材料"与"这个设备此刻的条目"。
 *
 * 它要防的是一个很短但真实的窗口：设备换掉 `signing_key_id` / `e2ee_key_id` 之后、重新
 * 发布 Bundle 之前，存着的那份已经**没有任何合规发送方会用**（§6.5 第 2、4 项会各自拒掉
 * 它），而我们还在照发——§4.1.1 L180 对这种情形的要求是"new material MUST be rejected"。
 *
 * 码取 **1018 `anp.device_state_changed`**，不是 4012：§13 L1547 把这类情形的归属写得很
 * 清楚——"Missing or invalid selectors and **current Manifest changes** use the shared Core
 * errors **`anp.device_state_changed`**"。4012 留给"调用方送来的东西绑错了"，而这里错的是
 * **目标设备**的清单变了，调用方什么都没做错。
 */
function bundleBindingProblem(
  bundle: Record<string, unknown>,
  ownerDid: string,
  device: EligibleDevice,
): AnpRejection | undefined {
  const docId = device.document.id
  const proof = verifyObjectProofDetailed({
    document: bundle,
    issuerDid: ownerDid,
    issuerDocument: device.document,
    expectedVerificationMethod: device.entry.signingKeyId,
  })
  if (!proof.ok) {
    return stateChanged(
      `the stored prekey_bundle for ${ownerDid} does not verify against the device's current signing_key_id ${device.entry.signingKeyId} (${proof.reason})`,
    )
  }
  const ka = bundle.static_key_agreement_id
  const bundleKa = nonEmptyString(ka) ? canonicalDidUrl(docId, ka) : undefined
  const entryKa = canonicalDidUrl(docId, device.entry.e2eeKeyId)
  if (bundleKa === undefined || entryKa === undefined || bundleKa !== entryKa) {
    return stateChanged(
      `the stored prekey_bundle's static_key_agreement_id does not match the device's current e2ee_key_id ${device.entry.e2eeKeyId}`,
    )
  }
  return undefined
}

// ---- 请求正文校验（1003） ------------------------------------------------------

/** §7.1 L470–476 的正文要求。`prekey_bundle` 的存在与"是个对象"是**请求**的形状；
 *  它内部像不像一个 Bundle 由 `bundleShapeProblem` 判，回的是 4001。 */
export function validatePublishBody(body: Record<string, unknown>): AnpRejection | undefined {
  if (!isPlainObject(body.prekey_bundle)) {
    return shapeProblem(`${PUBLISH_PREKEY_BUNDLE} requires an object body.prekey_bundle`)
  }
  const list = body.one_time_prekeys
  if (list === undefined) return undefined
  // §7.1 L472：存在时 **MUST** 是非空数组，每个元素 **MUST** 至少含 `key_id` 与
  // `public_key_b64u`。"空数组"不是"这次没带 OPK"的写法——那是不带这个字段。
  if (!Array.isArray(list) || list.length === 0) {
    return shapeProblem('body.one_time_prekeys MUST be a non-empty array when present')
  }
  for (const [index, raw] of list.entries()) {
    if (!isPlainObject(raw)) {
      return shapeProblem(`body.one_time_prekeys[${index}] MUST be an object`)
    }
    if (!nonEmptyString(raw.key_id)) {
      return shapeProblem(`body.one_time_prekeys[${index}].key_id MUST be a non-empty string`)
    }
    if (!nonEmptyString(raw.public_key_b64u)) {
      return shapeProblem(`body.one_time_prekeys[${index}].public_key_b64u MUST be a non-empty string`)
    }
  }
  return undefined
}

/**
 * §7.2 L546–554 的正文要求。
 *
 * `preferred_suite` 只做**形状**校验，不参与任何判断：§7.2 L560 说它的用途是"服务端同时维护
 * 多份材料时，调用方想先拿哪一份"，而本服务每设备只留最新一份（§7.3 L592 "the latest"），
 * 没有候选可比。把它当成筛选条件会让"服务端只有一份"这个事实变成一个 4000。
 */
export function validateGetBundleBody(body: Record<string, unknown>): AnpRejection | undefined {
  if (!nonEmptyString(body.target_did)) {
    return shapeProblem(`${GET_PREKEY_BUNDLE} requires body.target_did`)
  }
  if (!nonEmptyString(body.target_device_id)) {
    return shapeProblem(`${GET_PREKEY_BUNDLE} requires body.target_device_id`)
  }
  if (body.preferred_suite !== undefined && !nonEmptyString(body.preferred_suite)) {
    return shapeProblem(`body.preferred_suite MUST be a non-empty string when present`)
  }
  // §7.2 L562：`require_opk` 的语义是"不许在没有 OPK 的情况下降级建链"，所以它只有真假两种
  // 取值。收一个 `"true"` 再按真值判，会让调用方以为它在要求 OPK，而服务端以为它没要求。
  if (body.require_opk !== undefined && typeof body.require_opk !== 'boolean') {
    return shapeProblem('body.require_opk MUST be a boolean when present')
  }
  return undefined
}

// ---- 处理器 ------------------------------------------------------------------

export interface KeyContext {
  storage: Storage
  /** 本服务的 `serviceDid`：两条方法的 `meta.target.did` 都必须等于它（§7.1 L466、
   *  §7.2 L543——调用方寻址的正是**目标 Agent 暴露的那个**服务）。 */
  serviceDid: string
  meta: AnpMeta
  body: Record<string, unknown>
  /** RFC 3339，一次请求一个时刻。 */
  acceptedAt: string
  /**
   * 这次调用点名的设备，**顺序同 `DeviceAddressed.pairs`**，且都已判过 §4.1.1 资格。
   *
   * 发布：[0] 是发布方自己。领取：[0] 是调用方，[1] 是 `body` 里的目标设备——后者是
   * §7.2 L572 点名的那个 MUST。文档与条目一起交过来，这样 Bundle 的 proof 不必再解析
   * 一遍（同一次请求里解析两次会得到两份可能不同的文档）。
   */
  devices: readonly EligibleDevice[]
}

/** §7.1 L466 / §7.2 L543：`meta.target.did` **MUST** 等于本服务的 `serviceDid`。
 *  `targetBindingHolds` 只判 `kind`（`methods.ts`），所以这一条由处理器自己判，与
 *  `attachments.ts` 的 `requireServiceTarget` 同一处理。 */
function requireServiceTarget(ctx: KeyContext): void {
  if (ctx.meta.target?.did !== ctx.serviceDid) {
    throw refusal(
      anpRejection('anp.invalid_target_binding', `key methods MUST target ${ctx.serviceDid}`),
    )
  }
}

/** `sender_did` / `sender_device_id` 由方法表的 `requiredMeta` 保证，缺一个都进不来。
 *  抛而不是兜空串：空串会算出一个谁也不会再命中的身份（与 `targetScope` 抛空串同理）。 */
function device(
  ctx: KeyContext,
  index: number,
  what: string,
): EligibleDevice {
  const found = ctx.devices[index]
  if (found === undefined) {
    throw new Error(`${String(ctx.meta.profile)}: ${what} device was not resolved before the transaction`)
  }
  return found
}

function senderOf(meta: AnpMeta): string {
  const did = meta.sender_did
  if (!nonEmptyString(did)) {
    throw new Error('key methods require meta.sender_did')
  }
  return did
}

/**
 * `direct.e2ee.publish_prekey_bundle`（§7.1）。
 *
 * 顺序是 §7.1 那几段的顺序：目标是不是本服务 → Bundle 是不是 Bundle → 它的 owner 是不是
 * 调用方 → proof 算不算数 → 绑定对不对 → `bundle_id` 有没有被重定义 → 落库。
 *
 * **认证这件事在 v1 由 proof 承担。** §7.1 L492 明写这条方法"does not require an additional
 * business-layer `origin_proof`"，而 L472 又要求 `params.auth` MUST 缺省——所以调用方是谁，
 * 无法从信封上读出来。能读出来的是：这份 Bundle 的 proof 必须由**该设备清单里那条
 * `signing_key_id`** 签出（§6.5 第 2 项），而那颗私钥只有那台设备有。于是"冒名发布"要拿到
 * 别人的设备钥才行——第三个人能做的只是把一份**自己签不出**的东西送过来。同域没有外层
 * 签名时，这就是这条方法全部的认证（`docs/design/e2ee-direct.md` §9 记了这条缺口）。
 */
export function publishPrekeyBundle(ctx: KeyContext): Record<string, unknown> {
  requireServiceTarget(ctx)

  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = ctx.meta.sender_device_id
  if (!nonEmptyString(senderDeviceId)) {
    throw new Error(`${PUBLISH_PREKEY_BUNDLE} requires meta.sender_device_id`)
  }

  const bundle = ctx.body.prekey_bundle
  // `validatePublishBody` 已经保证它是对象。
  if (!isPlainObject(bundle)) {
    throw refusal(shapeProblem(`${PUBLISH_PREKEY_BUNDLE} requires an object body.prekey_bundle`))
  }

  const shape = bundleShapeProblem(bundle)
  if (shape !== undefined) throw refusal(shape)

  // §7.1 L470–471：owner 与**这次调用的发送方**必须一致。这是 §13 L1547 的 "P5 Bundle
  // owner" 那一项，所以是 4012 而不是 4001——Bundle 自身可以是完全合规的一份，错的是它
  // 不属于送它来的那个人。
  if (bundle.owner_did !== senderDid) {
    throw refusal(
      keyError('binding', `prekey_bundle.owner_did MUST equal meta.sender_did (${senderDid})`, {
        bundle_id: bundle.bundle_id,
      }),
    )
  }
  if (bundle.owner_device_id !== senderDeviceId) {
    throw refusal(
      keyError('binding', `prekey_bundle.owner_device_id MUST equal meta.sender_device_id (${senderDeviceId})`, {
        bundle_id: bundle.bundle_id,
      }),
    )
  }

  const publisher = device(ctx, 0, 'publisher')

  // 两次验签，顺序**不能**反过来。第一次只问附录 B：**任何**不合规都是 4001（§6.2.3 L379
  // 逐字）。第二次问"用的**是不是清单里那条** `signing_key_id`"，它只可能以
  // `unexpected_verification_method` 失败，那是 4012 的密钥引用不一致。
  //
  // 合成一次调用会让错误分派变得含混：`objectProof.ts` 的期望值判定排在验签**之前**，
  // 于是一份签名完全对不上、`verificationMethod` 又恰好不是这一条的 Bundle，会被报成
  // 4012 而不是 4001——而 §13 给"proof verification failed"的码是 4001。
  const appendixB = verifyObjectProofDetailed({
    document: bundle,
    issuerDid: senderDid,
    issuerDocument: publisher.document,
  })
  if (!appendixB.ok) {
    throw refusal(
      keyError('bundleInvalid', `prekey_bundle.proof does not meet the Object Proof Profile (${appendixB.reason})`, {
        bundle_id: bundle.bundle_id,
      }),
    )
  }
  const expected = verifyObjectProofDetailed({
    document: bundle,
    issuerDid: senderDid,
    issuerDocument: publisher.document,
    expectedVerificationMethod: publisher.entry.signingKeyId,
  })
  if (!expected.ok) {
    throw refusal(
      keyError('binding', `prekey_bundle.proof.verificationMethod MUST be the device's signing_key_id ${publisher.entry.signingKeyId}`, {
        bundle_id: bundle.bundle_id,
      }),
    )
  }

  // §4.1.1 L178 第 4 项（"the Bundle … use the same … key references"）。proof 指向的钥
  // 已经对上了，这里判的是**DH 那把**：`static_key_agreement_id` 必须是这条清单的
  // `e2ee_key_id`。两边都可能写成相对形式（`#ka-1`），所以比的是规范化之后的值。
  const docId = publisher.document.id
  const bundleKa = nonEmptyString(bundle.static_key_agreement_id)
    ? canonicalDidUrl(docId, bundle.static_key_agreement_id)
    : undefined
  const entryKa = canonicalDidUrl(docId, publisher.entry.e2eeKeyId)
  if (bundleKa === undefined || entryKa === undefined || bundleKa !== entryKa) {
    throw refusal(
      keyError('binding', `prekey_bundle.static_key_agreement_id MUST be the device's e2ee_key_id ${publisher.entry.e2eeKeyId}`, {
        bundle_id: bundle.bundle_id,
      }),
    )
  }

  // §6.2.2 L371。
  const stored = ctx.storage.prekeyBundle(senderDid, senderDeviceId)
  if (stored !== undefined && stored.bundleId === bundle.bundle_id) {
    const before: unknown = JSON.parse(stored.bundleJson)
    if (isPlainObject(before) && bundleIdentity(before) !== bundleIdentity(bundle)) {
      throw refusal(
        keyError('bundleInvalid', `bundle_id ${stored.bundleId} is already bound to a different Bundle`, {
          bundle_id: stored.bundleId,
        }),
      )
    }
  }

  const bundleId = bundle.bundle_id as string
  ctx.storage.upsertPrekeyBundle({
    ownerDid: senderDid,
    ownerDeviceId: senderDeviceId,
    bundleId,
    // 原样存下整个对象（`proof` 也在内）：§7.2 要把**同一份**对象交回给发送方，发送方
    // 按 §6.5 重验的就是它。本服务不解析里面的任何一处。
    bundleJson: JSON.stringify(bundle),
    publishedAt: ctx.acceptedAt,
  })

  // §7.1 L472：OPK 是**可选的一批**，一次补进池子。计数取的是**真正落进去的行数**
  // （`INSERT OR IGNORE` 对已存在的 `key_id` 不计），所以重发同一批不会报成"又发了这么多"。
  const uploaded = Array.isArray(ctx.body.one_time_prekeys) ? ctx.body.one_time_prekeys : []
  const inserted = ctx.storage.insertOneTimePrekeys(
    uploaded
      .filter(isPlainObject)
      .map((raw) => ({
        ownerDid: senderDid,
        ownerDeviceId: senderDeviceId,
        keyId: String(raw.key_id),
        publicKeyB64u: String(raw.public_key_b64u),
        state: 'available',
        uploadedAt: ctx.acceptedAt,
      })),
  )

  // §7.1 L487–493 的成功响应。
  return {
    published: true,
    owner_did: senderDid,
    owner_device_id: senderDeviceId,
    bundle_id: bundleId,
    published_at: ctx.acceptedAt,
    published_opk_count: inserted,
  }
}

/**
 * `direct.e2ee.get_prekey_bundle`（§7.2）。
 *
 * 两件事在这里发生：把存着的那份静态 Bundle 交回去，以及**按需**从池子里取一枚 OPK 并
 * 标记已分配。第二件是这次调用唯一写下的东西，所以它必须与幂等记录同生共死——那是
 * `acceptOperation` 的事务保证的：本函数整个跑在它里面。
 *
 * "同一幂等键拿回同一枚 OPK"（§7.2 L578）不需要另存一份分配键：命中同键时
 * `acceptOperation` **不调用** `perform`（`accept.ts` 里写明了），直接回放上次那份响应
 * ——里面就是同一枚 OPK。
 */
export function getPrekeyBundle(ctx: KeyContext): Record<string, unknown> {
  requireServiceTarget(ctx)

  const senderDid = senderOf(ctx.meta)
  const targetDid = String(ctx.body.target_did)
  const targetDeviceId = String(ctx.body.target_device_id)

  // §7.2 L572 那条 MUST 的资格判定已经在事务外跑过了（`dispatch.ts` 的资格门禁，两档
  // 里 `recheckOnReplay: true` 的那一档），所以这里拿得到目标设备的条目与文档。
  const target = device(ctx, 1, 'target')

  const stored = ctx.storage.prekeyBundle(targetDid, targetDeviceId)
  if (stored === undefined) {
    throw refusal(
      keyError('bundleNotFound', `${targetDid}#${targetDeviceId} has published no prekey_bundle`, {
        target_did: targetDid,
      }),
    )
  }
  const bundle: unknown = JSON.parse(stored.bundleJson)
  if (!isPlainObject(bundle)) {
    // 本服务自己写下的行必定是一个对象；走到这里说明库里那行被别的东西改过。
    throw new Error(`stored prekey_bundle for ${targetDid}#${targetDeviceId} is not an object`)
  }

  // §4.1.1 L178 第 4 项（"Before publishing, **returning**, or using P5 material"）。
  const stale = bundleBindingProblem(bundle, targetDid, target)
  if (stale !== undefined) throw refusal(stale)

  const requireOpk = ctx.body.require_opk === true
  if (requireOpk && ctx.storage.availableOneTimePrekeys(targetDid, targetDeviceId) === 0) {
    // §7.2 L576 + §13 L1537：**SHOULD** 显式报错，而不是伪造或复用旧的 OPK。
    throw refusal(
      keyError('opkUnavailable', `${targetDid}#${targetDeviceId} has no available one-time prekey`, {
        target_did: targetDid,
      }),
    )
  }

  // §6.6 L847：同一枚 OPK MUST NOT 被并发发给两个发送方。互斥由
  // `claimOneTimePrekey` 里那条 `WHERE state = 'available'` 的 UPDATE 保证，而不是"先查
  // 一次还有没有"——后者在读与写之间有一个两个调用方都能通过的窗口。
  const claimed = ctx.storage.claimOneTimePrekey(targetDid, targetDeviceId, senderDid, ctx.acceptedAt)
  if (claimed === undefined && requireOpk) {
    // 上面那次计数与这一次领取之间，池子被另一次调用取空了。只有 `require_opk` 时才是错
    // ——不带它的时候"这次没有 OPK"正是 §6.6 L852 允许的降级（正常返回 Bundle，不带 OPK）。
    throw refusal(
      keyError('opkUnavailable', `${targetDid}#${targetDeviceId} ran out of one-time prekeys`, {
        target_did: targetDid,
      }),
    )
  }

  // §7.2 L560–561：`target_did` / `target_device_id` 回显，后者 MUST 等于请求值**与**
  // `prekey_bundle.owner_device_id`。后半个等式在这里不可能不成立——存进来的时候
  // `publishPrekeyBundle` 已经按主键把这两者钉在一起了。
  return {
    target_did: targetDid,
    target_device_id: targetDeviceId,
    prekey_bundle: bundle,
    ...(claimed !== undefined
      ? { one_time_prekey: { key_id: claimed.keyId, public_key_b64u: claimed.publicKeyB64u } }
      : {}),
  }
}
