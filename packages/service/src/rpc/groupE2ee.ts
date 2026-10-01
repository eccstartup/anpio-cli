// C13 —— P6 §8 的两条 KeyPackage 控制面方法：发布与领取群加入材料。
//
// 形状与 P5 §7 那两条（`keys.ts`）同构，但**契约不同**，所以是两处代码而不是一处：
//
//   - P5 的 OPK 池是**耗尽型**两态，P6 的柜子是**三态**（§8.2.4 L765–770），而第三个状态
//     `consumed` 的触发者在**本服务自己**手里——对应的 `group.e2ee.add` 是经过本服务的控制
//     动作，它把 `group_key_package` 内联带着（§9.3.3），Host 因此能按 `key_package_id` 定位
//     到那一行。P5 那边我们看不到建链，这里看得到这次加入。这是一条真实的、有信息量的差异。
//   - P5 的发布材料是一份 Bundle，P6 的是一份 KeyPackage，两者的**凭据链**不同：Bundle 由
//     设备清单的 `signing_key_id` 直接签出（§6.5），KeyPackage 外面还包一层
//     `did_wba_binding`，那是一个**自带 proof 的对象**（§6.3 L412–418）。
//
// ## 服务端验的是绑定，不是 MLS
//
// §8.1.2 L701 要求"发布服务在接受 KeyPackage 前 MUST 验证当前 P2 Manifest 条目与第 6 节绑定"。
// 那两半分在两处实现，因为它们的输入不同：
//
//   - **清单那一半**（§6.4 L441–444 第 1–3 项）由资格门禁判（`eligibility.ts`，在事务外跑过），
//     报的是 P1 的四个设备码（1015–1018）。§17 L1930 逐字要求"设备绑定缺失、无效、不合资格
//     或状态过期时，复用 P1 Core 的……本 Profile 不定义第二套错误信封结构"。
//   - **绑定那一半**（§6.4 L445–448 第 4–8 项）在这里判：`did_wba_binding` 的 proof 算不算数
//     （附录 B）、它的 issuer 是不是 `agent_did`、它的 `verification_method` 是不是清单里那条
//     `signing_key_id`。这一半错的是"这份材料与那台设备对不上"，报 **5002**
//     `group.e2ee.did_binding_invalid`（§17 L1921 逐字："DID/设备与 MLS 绑定验证失败"）。
//
// §6.4 那十项里，本服务做得了的是 1–8 里不需要 MLS runtime 的部分；第 7、8 项（内嵌 MLS
// extension 与 sibling 的 JCS 字节相同）与 9–11 项都要解析 `mls_key_package_b64u`。§11.11
// L1386 明说 Host 不做最终 MLS 有效性判断，所以那些归接收方的 MLS runtime。这里判的是
// **包装对象的形状**与**绑定**，那两件是 §7.3 与 §6.3 定义的。
//
// ## 码的分派，两处判断与 P5 对齐
//
// "这个对象**是**一个 KeyPackage 吗" → **5001**（§17 L1920 "KeyPackage 无效"）。
// "它的 owner / 绑定与这次调用对不上" → **5002**。第二处的分法与 P5 §13 L1547 一致——那里
// 把 "P5 Bundle owner" 与证明/密钥引用一起归进 `invalid_security_binding`（4012），而 5002
// 正是 P6 的对应码。

import {
  anpRejection,
  profileRejection,
  verifyObjectProofDetailed,
  type AnpMeta,
  type AnpRejection,
  type DeviceRelationship,
} from '@agentx/core'
import type { Storage } from '../storage/types'
import type { DeviceRequirement, EligibleDevice } from './eligibility'
import { refusal } from './refusal'

export const PUBLISH_KEY_PACKAGE = 'group.e2ee.publish_key_package'
export const GET_KEY_PACKAGE = 'group.e2ee.get_key_package'

/** §4.1 L251。 */
export const GROUP_E2EE_PROFILE = 'anp.group.e2ee.v2'
/** §4.3 L272：两条 Key 方法与 `notice` 走这一档；四条控制方法走 `group-e2ee`（L273）。
 *  导出而不是复用 `methods.ts` 里 P5 那个同名常量：两者今天取值相同，但依据是**两条**规范
 *  行，合并成一处会让 P6 的那一档跟着 P5 的改动走。 */
export const GROUP_E2EE_KEY_SECURITY_PROFILE = 'transport-protected'

// ---- 错误码 ------------------------------------------------------------------

function pair(code: number, anpCode: string): { code: number; anpCode: string } {
  return { code, anpCode }
}

/**
 * §17 L1918–1931 里**这两条方法会发**的三个，加 `key_package_consumed`——末一个由
 * `group.e2ee.add` 那条路发，定义放在这里是因为"这枚已经用过了"这件事属于柜子，不属于
 * 某一处调用点。
 *
 * 走 `profileRejection` 而不是 `anpRejection`：这一段不在 P1 的公共表里，码值也不在
 * 1000–1021 之间。
 */
const GROUP_E2EE_ERRORS = {
  keyPackageNotFound: pair(5000, 'anp.group.e2ee.key_package_not_found'),
  invalidKeyPackage: pair(5001, 'anp.group.e2ee.invalid_key_package'),
  didBindingInvalid: pair(5002, 'anp.group.e2ee.did_binding_invalid'),
  keyPackageConsumed: pair(5012, 'anp.group.e2ee.key_package_consumed'),
} as const

export type GroupE2eeErrorName = keyof typeof GROUP_E2EE_ERRORS

export function groupE2eeError(
  name: GroupE2eeErrorName,
  message: string,
  details?: Record<string, unknown>,
): AnpRejection {
  const codes = GROUP_E2EE_ERRORS[name]
  return profileRejection(codes.code, codes.anpCode, message, details !== undefined ? { details } : {})
}

/** 形状问题一律 §10.3 L704 的 1003：错的是**请求**，不是材料，也不是权限。 */
function shapeProblem(message: string): AnpRejection {
  return anpRejection('anp.invalid_params_shape', message)
}

// ---- 小工具 ------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** §7.3 L550–556 要的都是"存在"，但空串能通过一个 `!== undefined` 的判断，而一个空的
 *  `key_package_id` 说明不了任何事（与 P5 那份同一个理由）。 */
function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== ''
}

// ---- 设备资格：P6 那一份要求 --------------------------------------------------

/**
 * P6 对一台设备资格的全部要求（§4.2 L253–262）。
 *
 * 三项依赖逐字来自 §4.2，加上 P6 自己。P2 §5.5 L267 规则 5 要求 `profiles` 是**完整**
 * 依赖集，少一项那条设备就不算数——所以 `anp.group.base.v2`（P4）也在里面：P6 控制的是
 * P4 已经定下的业务状态（§3.3），一台没宣告 P4 的设备在这条链上没有意义。
 *
 * `signing_key_id` 要落在 `assertionMethod`：§6.4 L443 第 3 项逐字"`verification_method`
 * 等于该条目当前 `signing_key_id`，**且被 `assertionMethod` 授权**"。`e2ee_key_id` 落在
 * `keyAgreement` 是 P2 §5.5 L266 规则 4 的通用要求。
 */
export const GROUP_E2EE_DEVICE: DeviceRequirement = {
  profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.group.base.v2', GROUP_E2EE_PROFILE],
  signingRelationship: 'assertionMethod' satisfies DeviceRelationship,
  e2eeRelationship: 'keyAgreement' satisfies DeviceRelationship,
}

// ---- §7.3 的 KeyPackage 定义 --------------------------------------------------

/** §7.3 L550–554：这五项 **MUST** 存在。第六项 `did_wba_binding` 是对象，单独判。
 *  `expires_at` 不在这里——§7.3 L555 给的是 SHOULD。 */
const KEY_PACKAGE_FIELDS = ['key_package_id', 'owner_did', 'owner_device_id', 'suite', 'mls_key_package_b64u'] as const

/**
 * §6.4 L446 第 6 项点名的六个字段。
 *
 * 这一项的字面是"**受保护文档**至少覆盖 agent_did、device_id、verification_method、
 * `leaf_signature_key_b64u`、`issued_at` 与 `expires_at`"——而按附录 B，受保护文档就是
 * "剥掉 `proof` 后的整个对象"（`objectProof.ts` 的 `didDocumentProofPayload`），"覆盖"
 * 因此对**在场**的字段自动成立。于是这一项唯一有内容的要求就是**它们得在场**，本服务按
 * 这个读法判：缺一个就是这份绑定不满足 §6.4。
 *
 * `issued_at` / `expires_at` 也在其中，尽管 §6.3 的推荐结构没给它们 MUST——§6.4 这一项
 * 是后出的、更具体的规则，且第 11 项（时间窗口有效）本来就以它们在场为前提。
 */
const BINDING_FIELDS = [
  'agent_did',
  'device_id',
  'verification_method',
  'leaf_signature_key_b64u',
  'issued_at',
  'expires_at',
] as const

/**
 * "这个对象**是**一个 KeyPackage 吗"（§7.3 L536–563）。不是就是 **5001**。
 *
 * 不在这里判的：`did_wba_binding` 的 proof 算不算数（要 issuer 文档，见 `bindingProblem`），
 * 以及 `owner_*` 与调用方对不对得上（那是"与另一处的比对"，5002）。`expires_at` 也不判
 * ——§7.3 L555 给的是 SHOULD，缺了它这份 KeyPackage 仍然合法，只是没有有效期可比。
 */
function keyPackageShapeProblem(keyPackage: Record<string, unknown>): AnpRejection | undefined {
  for (const field of KEY_PACKAGE_FIELDS) {
    if (!nonEmptyString(keyPackage[field])) {
      return groupE2eeError('invalidKeyPackage', `group_key_package.${field} MUST be a non-empty string`)
    }
  }
  const binding = keyPackage.did_wba_binding
  if (!isPlainObject(binding)) {
    return groupE2eeError('invalidKeyPackage', 'group_key_package.did_wba_binding MUST be an object')
  }
  for (const field of BINDING_FIELDS) {
    if (!nonEmptyString(binding[field])) {
      return groupE2eeError('invalidKeyPackage', `group_key_package.did_wba_binding.${field} MUST be a non-empty string`)
    }
  }
  // §6.4 L445 第 4 项：`proof` **MUST** 存在。它算不算数由 `bindingProblem` 判——那要
  // issuer 文档，是这一层的下一步，而不是形状。
  if (!isPlainObject(binding.proof)) {
    return groupE2eeError('invalidKeyPackage', 'group_key_package.did_wba_binding.proof MUST be an object')
  }
  // §7.3 L557：`owner_did` / `owner_device_id` **MUST** 等于绑定里的 `agent_did` / `device_id`。
  // 两者不一致是这份材料**自身**的两个说法互相矛盾，与本服务、与调用方都无关，所以是 5001。
  if (keyPackage.owner_did !== binding.agent_did) {
    return groupE2eeError('invalidKeyPackage', 'group_key_package.owner_did MUST equal did_wba_binding.agent_did')
  }
  if (keyPackage.owner_device_id !== binding.device_id) {
    return groupE2eeError('invalidKeyPackage', 'group_key_package.owner_device_id MUST equal did_wba_binding.device_id')
  }
  return undefined
}

/**
 * §6.4 L445–448 第 4–6 项：`did_wba_binding` 的 proof 与清单条目对不对得上。
 *
 * 这一半在**发布与领取两侧都要跑**。只跑发布的话，有一个很短但真实的窗口：设备换掉
 * `signing_key_id` 之后、重新发布 KeyPackage 之前，柜子里存着的那份已经**没有任何合规
 * 接收方会用它入群**（§13.2 的重定义检查会拒掉它），而我们还在照发。
 *
 * 码取 **5002**，与发布侧那几处比对取同一个：两处错的都是"这份材料与那台设备的当前清单
 * 对不上"，不是清单本身有问题（那是资格门禁那四个 Core 码的事）。
 */
function bindingProblem(
  keyPackage: Record<string, unknown>,
  ownerDid: string,
  device: EligibleDevice,
): AnpRejection | undefined {
  const binding = keyPackage.did_wba_binding
  if (!isPlainObject(binding)) {
    return groupE2eeError('invalidKeyPackage', 'group_key_package.did_wba_binding MUST be an object')
  }
  // §6.4 L445 第 5 项把"proof 的 issuer DID 等于 agent_did"与"proof 验证通过"合成一步。
  // 附录 B 的入口收的 `issuerDid` 就是那个 issuer，所以传 `ownerDid`（= agent_did，由形状
  // 检查保证）同时判掉了两件事。`expectedVerificationMethod` 是第 3 项的后半。
  const proof = verifyObjectProofDetailed({
    document: binding,
    issuerDid: ownerDid,
    issuerDocument: device.document,
    expectedVerificationMethod: device.entry.signingKeyId,
  })
  if (!proof.ok) {
    return groupE2eeError(
      'didBindingInvalid',
      `group_key_package.did_wba_binding does not verify against ${ownerDid}#${device.entry.deviceId}'s current signing_key_id ${device.entry.signingKeyId} (${proof.reason})`,
      { key_package_id: keyPackage.key_package_id },
    )
  }
  // §6.4 L443 第 3 项的前半：`verification_method` 等于该条目当前 `signing_key_id`。
  // proof 那一半已由上面那次调用按 `expectedVerificationMethod` 判过，这里判**声明的**这
  // 一半——两半都对上，这条绑定才指的是那把钥。
  if (binding.verification_method !== device.entry.signingKeyId) {
    return groupE2eeError(
      'didBindingInvalid',
      `group_key_package.did_wba_binding.verification_method MUST be the device's signing_key_id ${device.entry.signingKeyId}`,
      { key_package_id: keyPackage.key_package_id },
    )
  }
  return undefined
}

// ---- 请求正文校验（1003） ------------------------------------------------------

/**
 * §8.1.2 L697 的正文要求。`group_key_package` 的存在与"是个对象"是**请求**的形状；它内部
 * 像不像一个 KeyPackage 由 `keyPackageShapeProblem` 判，回的是 5001。
 *
 * 没有别的字段：§8.1.2 只点了这一个。不像 P5 §7.1 还有一批可选的 `one_time_prekeys`——
 * P6 的 KeyPackage 一次发布一个（每个 `key_package_id` 一行），没有"一批"这个形状。
 */
export function validatePublishKeyPackageBody(body: Record<string, unknown>): AnpRejection | undefined {
  if (!isPlainObject(body.group_key_package)) {
    return shapeProblem(`${PUBLISH_KEY_PACKAGE} requires an object body.group_key_package`)
  }
  return undefined
}

/**
 * §8.2.2 L735–744 的正文要求。
 *
 * `preferred_suite` 只做**形状**校验、不参与判断，与 P5 §7.2 那个同名字段同理：§8.2.2 把它
 * 与 `require_fresh` 并列放在 MAY 里，而本服务一个 `(did, device)` 名下的包**各自一行**、
 * 各带自己的 `suite`，没有"同一台设备的两个 suite 版本"这种候选可挑。把它当成筛选条件，会
 * 让"柜子里没有那个 suite"变成一个 5000，而调用方本来只是说了个偏好。
 */
export function validateGetKeyPackageBody(body: Record<string, unknown>): AnpRejection | undefined {
  if (!nonEmptyString(body.target_did)) {
    return shapeProblem(`${GET_KEY_PACKAGE} requires body.target_did`)
  }
  if (!nonEmptyString(body.target_device_id)) {
    return shapeProblem(`${GET_KEY_PACKAGE} requires body.target_device_id`)
  }
  if (body.preferred_suite !== undefined && !nonEmptyString(body.preferred_suite)) {
    return shapeProblem('body.preferred_suite MUST be a non-empty string when present')
  }
  // 只有真假两种取值。收一个 `"true"` 再按真值判，会让调用方以为它在要求"只要新鲜的"，
  // 而服务端以为它没要求（与 P5 的 `require_opk` 同一个坑）。
  if (body.require_fresh !== undefined && typeof body.require_fresh !== 'boolean') {
    return shapeProblem('body.require_fresh MUST be a boolean when present')
  }
  return undefined
}

// ---- 处理器 ------------------------------------------------------------------

export interface GroupE2eeKeyContext {
  storage: Storage
  /** 本服务的 `serviceDid`：两条方法的 `meta.target.did` **MUST** 等于它（§8.1.2 L696、
   *  §8.2.2 L732）。 */
  serviceDid: string
  meta: AnpMeta
  body: Record<string, unknown>
  /** RFC 3339，一次请求一个时刻。 */
  acceptedAt: string
  /** 这次调用点名的设备，**顺序同 `DeviceAddressed.pairs`**，且都已判过资格。
   *
   *  发布：[0] 是发布方自己。领取：[0] 是调用方，[1] 是 `body` 里的目标设备——后者是
   *  §8.2.4 L767 点名的那个 MUST（"返回前 MUST 根据当前 P2 Manifest 重新验证目标设备"）。
   *  文档随条目一起来，于是 `did_wba_binding` 的 proof 不必再解析一遍（同一次请求里解析
   *  两遍会得到两份可能不同的文档，而 proof 只能对着其中一份验）。 */
  devices: readonly EligibleDevice[]
}

/** §8.1.2 L696 / §8.2.2 L732：`meta.target.did` **MUST** 等于本服务的 `serviceDid`。
 *  `targetBindingHolds` 只判 `kind`（`methods.ts`），所以这一条由处理器自己判，与
 *  `keys.ts` / `attachments.ts` 同一处理。 */
function requireServiceTarget(ctx: GroupE2eeKeyContext): void {
  if (ctx.meta.target?.did !== ctx.serviceDid) {
    throw refusal(anpRejection('anp.invalid_target_binding', `P6 key methods MUST target ${ctx.serviceDid}`))
  }
}

/** `sender_did` / `sender_device_id` 由方法表的 `requiredMeta` 保证（§4.3 L266 要求每个设备
 *  发起的 P6 请求都带后者），缺一个都进不来。抛而不是兜空串：空串会算出一个谁也不会再命中
 *  的身份。 */
function senderOf(meta: AnpMeta): string {
  const did = meta.sender_did
  if (!nonEmptyString(did)) {
    throw new Error(`${GROUP_E2EE_PROFILE} requires meta.sender_did`)
  }
  return did
}

function senderDeviceOf(meta: AnpMeta): string {
  const deviceId = meta.sender_device_id
  if (!nonEmptyString(deviceId)) {
    throw new Error(`${GROUP_E2EE_PROFILE} requires meta.sender_device_id`)
  }
  return deviceId
}

function device(ctx: GroupE2eeKeyContext, index: number, what: string): EligibleDevice {
  const found = ctx.devices[index]
  if (found === undefined) {
    throw new Error(`${GROUP_E2EE_PROFILE}: ${what} device was not resolved before the transaction`)
  }
  return found
}

/**
 * `group.e2ee.publish_key_package`（§8.1）。
 *
 * 顺序是 §8.1.2 那几段的顺序：目标是不是本服务 → 对象像不像 KeyPackage → 它的 owner 是不是
 * 调用方 → 绑定算不算数 → 落库。
 *
 * **认证这件事由绑定 proof 承担。** §8.1.2 L706 说 v2 **不要求**为这条方法额外定义业务层的
 * `origin_proof`，而 L704 把"调用方 MUST 运行在已认证的本域会话或等价 hop / service 认证
 * 上下文中"交给部署。同域明文没有那一跳时，剩下的就是 `did_wba_binding.proof`：§6.4 L443
 * 第 3 项要求它由该设备清单里那条 `signing_key_id` 签出，而那颗私钥只有那台设备有。于是
 * "冒名发布"要拿到别人的设备钥才行——这条方法全部的认证就在这里
 * （[e2ee-group.md](../../../docs/design/e2ee-group.md) §15 与 P5 那条同源）。
 *
 * **与 P5 的一处不同**：这里没有"`key_package_id` 不可重定义"那条检查。§8.1.2 没有这句，
 * 而 §13.2 那类重定义检查归**接收方**（最终用这份材料入群的那个 MLS runtime）。本服务的
 * 柜子对同名重发是**忽略**（`insertGroupKeyPackage`），先写者赢——那同时保证了已经交出去的
 * 一枚不会被换掉。
 */
export function publishKeyPackage(ctx: GroupE2eeKeyContext): Record<string, unknown> {
  requireServiceTarget(ctx)

  const senderDid = senderOf(ctx.meta)
  const senderDeviceId = senderDeviceOf(ctx.meta)

  const keyPackage = ctx.body.group_key_package
  // `validatePublishKeyPackageBody` 已经保证它是对象。
  if (!isPlainObject(keyPackage)) {
    throw refusal(shapeProblem(`${PUBLISH_KEY_PACKAGE} requires an object body.group_key_package`))
  }

  const shape = keyPackageShapeProblem(keyPackage)
  if (shape !== undefined) throw refusal(shape)

  // §8.1.2 L699–700：owner 与**这次调用的发送方**必须一致。这是"与另一处的比对"，所以是
  // 5002 而不是 5001——这份 KeyPackage 自身可以完全合规，错的是它不属于送它来的那台设备。
  if (keyPackage.owner_did !== senderDid) {
    throw refusal(
      groupE2eeError('didBindingInvalid', `group_key_package.owner_did MUST equal meta.sender_did (${senderDid})`, {
        key_package_id: keyPackage.key_package_id,
      }),
    )
  }
  if (keyPackage.owner_device_id !== senderDeviceId) {
    throw refusal(
      groupE2eeError(
        'didBindingInvalid',
        `group_key_package.owner_device_id MUST equal meta.sender_device_id (${senderDeviceId})`,
        { key_package_id: keyPackage.key_package_id },
      ),
    )
  }

  // §6.4 第 4–6 项。清单那一半（第 1–3 项）已经由资格门禁在事务外判过，且它是对着**同一份**
  // 文档判的——所以这里直接用那次解析出来的文档验 proof，不重解析。
  const publisher = device(ctx, 0, 'publisher')
  const binding = bindingProblem(keyPackage, senderDid, publisher)
  if (binding !== undefined) throw refusal(binding)

  const keyPackageId = keyPackage.key_package_id as string
  ctx.storage.insertGroupKeyPackage({
    ownerDid: senderDid,
    ownerDeviceId: senderDeviceId,
    keyPackageId,
    // 原样存下整个对象（`did_wba_binding` 与它的 proof 都在内）：§8.2.3 要把**同一份**对象
    // 交给后面执行 `group.e2ee.add` 的那个 owner（§9.3.3），而接收方的 MLS runtime 接着要验
    // 的正是它带的这份绑定。本服务规范化掉的任何一处，都会改变下游每一个人的验证输入。
    packageJson: JSON.stringify(keyPackage),
    state: 'available',
    publishedAt: ctx.acceptedAt,
  })

  // §8.1.3 L718–722 的成功响应。
  return {
    published: true,
    owner_did: senderDid,
    owner_device_id: senderDeviceId,
    key_package_id: keyPackageId,
    published_at: ctx.acceptedAt,
  }
}

/**
 * 一个 KeyPackage 的 `expires_at` 是不是已经过去。
 *
 * `undefined` 表示"判不了"——§7.3 L555 让 `expires_at` 成为 SHOULD，所以它可能不在，也可能
 * 是一个本服务不该去解释的时间格式。判不了就当成没过期：§8.2.4 L763 对"返回未过期的"本身
 * 只说 SHOULD，而把一份说不出哪里不合规的材料拒掉，会让一个合规的调用方无从措手。
 */
function expired(keyPackage: Record<string, unknown>, at: string): boolean | undefined {
  const raw = keyPackage.expires_at
  if (!nonEmptyString(raw)) return undefined
  const expires = Date.parse(raw)
  const now = Date.parse(at)
  if (Number.isNaN(expires) || Number.isNaN(now)) return undefined
  return expires <= now
}

function storedObject(json: string, keyPackageId: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(json)
  if (!isPlainObject(parsed)) {
    // 本服务自己写下的行必定是一个对象；走到这里说明库里那行被别的东西改过。
    throw new Error(`stored group_key_package ${keyPackageId} is not an object`)
  }
  return parsed
}

/**
 * `group.e2ee.get_key_package`（§8.2）。
 *
 * 两件事：从柜子里挑一枚可用的，以及**在挑选的同时把它占住**（§8.2.4 L767 的 MAY）。第二件
 * 是这次调用唯一写下的东西，所以它必须与幂等记录同生共死——本函数整个跑在 `acceptOperation`
 * 的事务里。
 *
 * "同一幂等键拿回同一枚"不需要另存一份分配键：命中同键时 `acceptOperation` **不调用**
 * `perform`，直接回放上次那份响应——里面就是同一枚。
 *
 * ## `require_fresh` 的处置
 *
 * 规范只把这个字段列进 §8.2.2 L743 的 MAY 里，**没有给出语义**（全篇仅此一处提到它）。这里
 * 取它字面的意思，并只让它收紧 §8.2.4 L763 已有的那条 SHOULD：默认把过期的排在后面，全部
 * 都是过期的时候才回落；调用方要求了新鲜的，就不回落，直接 5000。这样这个字段要么不改变
 * 服务端行为，要么让它在**已经有 SHOULD 的那条线上**更严，不会发明出一条新的拒绝理由。
 */
export function getKeyPackage(ctx: GroupE2eeKeyContext): Record<string, unknown> {
  requireServiceTarget(ctx)

  const callerDid = senderOf(ctx.meta)
  const targetDid = String(ctx.body.target_did)
  const targetDeviceId = String(ctx.body.target_device_id)

  // §8.2.4 L767 那条 MUST 的判定已经在事务外跑过了（`dispatch.ts` 的资格门禁，
  // `recheckOnReplay: true` 那一档），所以这里拿得到目标设备的条目与文档。
  const target = device(ctx, 1, 'target')

  const candidates = ctx.storage.availableGroupKeyPackages(targetDid, targetDeviceId)
  if (candidates.length === 0) {
    // §8.2.4 L763 + §17 L1918 的 5000。**不是** 5012：那说的是"某一枚已经被用过了"，而这里
    // 是"柜子里没有可发的"——两者要调用方做的事不同（换一台设备问 vs. 等对方重新发布）。
    throw refusal(
      groupE2eeError('keyPackageNotFound', `${targetDid}#${targetDeviceId} has published no available key_package`, {
        target_did: targetDid,
      }),
    )
  }

  const claim = (keyPackageId: string): boolean =>
    ctx.storage.claimGroupKeyPackage(targetDid, targetDeviceId, keyPackageId, callerDid, ctx.acceptedAt)

  const requireFresh = ctx.body.require_fresh === true
  let claimed: string | undefined
  let expiredFallback: string | undefined
  for (const candidate of candidates) {
    const stored = storedObject(candidate.packageJson, candidate.keyPackageId)
    if (expired(stored, ctx.acceptedAt) === true) {
      // 留在手上而不是丢掉：柜子里全是过期的时，§8.2.4 L763 的 SHOULD 允许把它发出去。
      // 取**最早**的那一枚（候选已按发布顺序排好），与 §8.2.4 的先后一致。
      expiredFallback ??= candidate.keyPackageId
      continue
    }
    if (claim(candidate.keyPackageId)) {
      claimed = candidate.keyPackageId
      break
    }
    // 认领失败说明这一枚在同一次调用的两句之间被另一个进程拿走了（同一进程内
    // `BEGIN IMMEDIATE` 下发生不了）。挑下一枚——"池子变了"不是调用方的错。
  }
  if (claimed === undefined && !requireFresh && expiredFallback !== undefined && claim(expiredFallback)) {
    claimed = expiredFallback
  }
  if (claimed === undefined) {
    throw refusal(
      groupE2eeError('keyPackageNotFound', `${targetDid}#${targetDeviceId} has no key_package to hand out`, {
        target_did: targetDid,
      }),
    )
  }

  const chosen = ctx.storage.groupKeyPackage(targetDid, targetDeviceId, claimed)
  if (chosen === undefined) {
    throw new Error(`group_key_package ${claimed} disappeared between the claim and the read`)
  }
  const parsed = storedObject(chosen.packageJson, claimed)

  // §8.2.4 L767 的第 4 项（"返回前 MUST 根据当前 P2 Manifest 重新验证目标设备"）在这里落地：
  // 存下来的那份可能与**此刻**的清单已经对不上，而这条 MUST 要的正是"此刻"。
  const stale = bindingProblem(parsed, targetDid, target)
  if (stale !== undefined) throw refusal(stale)

  // §8.2.3 L751–755 的成功响应。那份对象按 §7.3 原样交回。
  return {
    target_did: targetDid,
    target_device_id: targetDeviceId,
    group_key_package: parsed,
  }
}
