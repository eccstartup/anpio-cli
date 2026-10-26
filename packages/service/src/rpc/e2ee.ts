// P5 `anp.direct.e2ee.v2` 在**方法表这一层**要求的东西。
//
// 这个 Profile 与 P3 共用一个方法名（`direct.send`），所以它带来的是"同一个方法在另一个
// Profile 下换了一套 wire 契约"，而不是一个新方法。契约本身很短，规范把它拆在三节里：
// §3.6 允许哪两个 `content_type`、§3.7 两个 id 必须相等、§3.8 不许带 `auth`，§9.3 再把
// 它们连同两个设备 selector 复述一遍给 `direct_init` 用。
//
// 这些规则**不是**通用的参数校验：它们在 Base 下一条都不成立（Base 恰恰要求带 `auth`、
// 恰恰禁止设备 selector），所以不能进方法表那两个静态数组，只能按 Profile 分派。
//
// 另外一条边界值得写在这里：本服务**不解析** v2 的正文。`direct_init` / `cipher` 的字段
// 与绑定由**收件设备**验（§9.4.1 L828–838 那四项要的都是设备侧才有的材料），服务端做的
// 是 §10.7 L1391 那一件事——把不透明密文放进收件设备的邮箱。所以下面没有一条正文规则。

import {
  anpRejection,
  ConnectxError,
  type AnpMeta,
  type AnpParams,
  type AnpRejection,
  type DeviceRelationship,
} from '@anpio-cli/core'
import type { DeviceAddressed, DeviceRequirement } from './eligibility'

/** §16.1–16.3 的线上形状里那个 `meta.profile`。 */
export const DIRECT_E2EE_PROFILE = 'anp.direct.e2ee.v2'
/** §9.3 L821：密文那一跳的安全模式。密钥控制面用的是 `transport-protected`（§7.1 L467）。 */
export const DIRECT_E2EE_SECURITY_PROFILE = 'direct-e2ee'
/** §3.6 L122。 */
export const DIRECT_INIT_CONTENT_TYPE = 'application/anp-direct-init+json'
/** §3.6 L123。 */
export const DIRECT_CIPHER_CONTENT_TYPE = 'application/anp-direct-cipher+json'

/**
 * §3.6 L120：`direct.send` 在 v2 下只认这两个 `content_type`。
 *
 * 两处都放进来是有理由的：`direct.init` 与后续密文走的是**同一条** `direct.send`，服务端
 * 无从（也不该）从正文分辨这是哪一跳——它不解密。允许哪两个是**外层**就知道的事，正文里
 * 是什么由收件设备判。
 */
const ALLOWED_CONTENT_TYPES: readonly string[] = [DIRECT_INIT_CONTENT_TYPE, DIRECT_CIPHER_CONTENT_TYPE]

/** P3 §7.1.2 L362：Base 的 `direct.send` 里不出现设备 selector。
 *
 *  它原来是 `DIRECT_SEND_SPEC` 上的 `forbiddenMeta`，搬到这里是**必须的**：那是一个静态
 *  数组，而同一个方法在 v2 下要求这两个字段各出现一次。留在方法表上就只能加一条"这个
 *  数组要看 profile 说话"的分支，那比把它和 v2 的对应规则放在一起更难看出两套要求正好互补。 */
const BASE_FORBIDDEN_FIELDS = ['sender_device_id', 'recipient_device_id'] as const

/**
 * P5 对一台设备资格的全部要求（§4.1.1 L166–178）。
 *
 * 四项依赖集来自 P2 §5.5 L245–250 那个例子——规范自己把它列全了：P1 是
 * `anp.core.binding.v1`、P2 是 `anp.identity.discovery.v1`、P3 是 `anp.direct.base.v1`，
 * 加上 P5 自己。§5.5 L267 规则 5 说 `profiles` **MUST** 是**完整**依赖集，所以这四项要
 * 一起查，少一项那条设备就不算数。
 *
 * `signing_key_id` 要落在 `assertionMethod`：§4.1.1 第 3 项说的是"Bundle 证明所需的签名
 * 方法"，而 Bundle 用的是 Object Proof（P2 §5.5 L266 规则 4 与 §10.2.1 L630 都点了
 * `assertionMethod`）。**不是** `authentication`：v2 的默认路径上根本没有 `origin_proof`
 * （§3.8 L140），拿登录钥去要求它会把一条合规的设备拒掉。
 */
export const DIRECT_E2EE_DEVICE: DeviceRequirement = {
  profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1', DIRECT_E2EE_PROFILE],
  signingRelationship: 'assertionMethod' satisfies DeviceRelationship,
  e2eeRelationship: 'keyAgreement' satisfies DeviceRelationship,
}

/**
 * §3.6–§3.8 那三条 wire 约束，外加 §9.3 复述的两个设备 selector。
 *
 * 两个 Profile 的规则都在这里，因为它们是**同一批字段上的两套互斥要求**：Base 禁设备
 * selector、v2 要求它，Base 要求 `auth`、v2 拒收它。拆成两个函数就会有两处各自判
 * `meta.profile`，而"这两套要求覆盖了所有可能的 profile"这件事就没有地方保证了。
 *
 * 码是**逐条对表**选的，规范在这三处都只说 MUST reject、没给码：
 *
 *   - 设备 selector 缺失 → **1015** `anp.device_binding_required`。P1 §10.3 L713 对这个码
 *     的定义就是"设备定址 E2EE Overlay 要求的设备 selector 缺失"，逐字命中。用 1003
 *     （参数形状）会把一条规范已经配好码的情形说成通用形状问题。
 *   - Base 收到设备 selector → **1003** `anp.invalid_params_shape`。P1 §10.3 L724 明说
 *     那是"非法参数"，且 1015–1018 四个码专给 Overlay，这里用不得。
 *   - `content_type` 不在白名单 → **1009** `anp.unsupported_content_type`。§3.6 L124 的
 *     措辞是"接收方 MUST 拒绝"，拒绝的是那个**类型**；1009 正是公共段里说这件事的码。
 *   - 两个 id 不相等、`auth` 在场 → **1003** `anp.invalid_params_shape`。这两条是"这个
 *     字段不该在这儿/这两个字段必须相等"，与 Base 那条同类——所以用同一个，让"参数形状
 *     不对"在整张方法表里只有一个码。
 */
export function directSendParams(params: AnpParams): AnpRejection | undefined {
  const { meta, auth } = params

  // P3 §7.1.2 L362：设备 selector 只属于 P5 v2，Base 操作收到一个就按非法参数处理。
  if (meta.profile !== DIRECT_E2EE_PROFILE) {
    for (const field of BASE_FORBIDDEN_FIELDS) {
      if (meta[field] !== undefined) {
        return anpRejection('anp.invalid_params_shape', `${meta.profile} forbids meta.${field}`)
      }
    }
    return undefined
  }

  // §9.3 L823–824：两个 selector **MUST** 存在。它们既是"投给哪台设备"（§10.7 L1391），
  // 也是幂等键的两段（§10.7 L1391 第 3 项），少一个这次调用就没有地址。
  if (meta.sender_device_id === undefined) {
    return anpRejection('anp.device_binding_required', `${DIRECT_E2EE_PROFILE} requires meta.sender_device_id`)
  }
  if (meta.recipient_device_id === undefined) {
    return anpRejection('anp.device_binding_required', `${DIRECT_E2EE_PROFILE} requires meta.recipient_device_id`)
  }

  // §3.6 L120：不改动的 MTI 路径上只有这两个 wire 对象类型。
  const contentType = meta.content_type ?? ''
  if (!ALLOWED_CONTENT_TYPES.includes(contentType)) {
    return anpRejection(
      'anp.unsupported_content_type',
      `${DIRECT_E2EE_PROFILE} carries only ${ALLOWED_CONTENT_TYPES.join(' or ')} (got ${contentType})`,
      { details: { content_type: contentType } },
    )
  }

  // §3.7 L134。这条 MUST 把外层幂等键与消息标识绑成同一个值（§11.1 L1456），所以它同时
  // 是"消息级重复识别"那一半——重发同一份密文必然带着同一对 id。
  if (meta.operation_id !== meta.message_id) {
    return anpRejection(
      'anp.invalid_params_shape',
      `${DIRECT_E2EE_PROFILE} requires meta.operation_id to equal meta.message_id`,
    )
  }

  // §3.8 L140：未协商扩展时 `params.auth` **MUST** 缺省。这不是"忽略它"——规范写的是
  // 接收方 **MUST** 拒绝。`Direct Init Accountability Extension` 没实现，所以这里没有
  // 例外分支：将来协商它的时候，协商状态是**部署级**的，不是这一层能读到的。
  if (auth !== undefined) {
    return anpRejection(
      'anp.invalid_params_shape',
      `${DIRECT_E2EE_PROFILE} forbids params.auth unless the Direct Init Accountability Extension is negotiated`,
    )
  }
  return undefined
}

/**
 * §9.1 L639 / §11.5 L1458：只有设备定址的 E2EE Overlay 才把设备 selector 放进幂等键、
 * 才要验两台设备的资格（§10.7 L1388）。
 *
 * 这一档**不重判重放**：§9.1 L630 要求同一个幂等键重试拿到同一个结果，而资格是**当下**的
 * 事实（§4.1.1 L171）。`eligibilityFor` 上写了完整理由。
 *
 * 这个函数**假定** `checkMethod` 已经放行——`directSendParams` 保证两个 selector 都在
 * （§9.3 L823–824 的 1015 就在前面一步），静态的 `requiredMeta` 与 `targetMode` 保证
 * `sender_did` 与 `target` 也在。到不了的情形当场抛而不是交回 `undefined`：交回
 * `undefined` 的意思是"这次调用不是设备定址的"，而它**是**——那会让幂等键少两段、资格
 * 一次都不查，且没有任何东西会红（与下面 `targetScope` 抛掉空串是同一个理由）。
 */
export function directSendDeviceAddressed(meta: AnpMeta): DeviceAddressed | undefined {
  if (meta.profile !== DIRECT_E2EE_PROFILE) return undefined
  const sender = meta.sender_device_id
  const recipient = meta.recipient_device_id
  const senderDid = meta.sender_did
  const target = meta.target
  if (sender === undefined || recipient === undefined || senderDid === undefined || target === undefined) {
    throw new ConnectxError('message_invalid', `${DIRECT_E2EE_PROFILE} requires both device selectors and meta.target`)
  }
  // 两台各自带自己的 identity：发送设备挂在**发送方**的清单下，收件设备挂在**收件 DID** 的
  // 清单下。少了这一层，`checkDevice` 就只能拿一个 DID 去查两台设备的条目。
  return {
    pairs: [
      { identity: senderDid, deviceId: sender },
      { identity: target.did, deviceId: recipient },
    ],
    requirement: DIRECT_E2EE_DEVICE,
  }
}
