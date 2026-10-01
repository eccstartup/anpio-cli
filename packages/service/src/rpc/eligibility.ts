// P5 §4.1.1 —— 设备资格。
//
// "这台设备现在算不算数"**不是启动时校验一次**，而是每次操作的前置（§4.1.1 L171–178、
// §12.4 L1515、P2 §12 L947）。所以这里没有缓存：每次问都去解析当前文档、读当前清单。
// P2 §12 L947 把这件事说得最直白——资格**只能**来自当前 `deviceManifest`、它引用的钥、
// 宣告的能力与该 Profile 自己的规则，**不得**依赖任何未声明的注册表版本或检查点。
//
// 这一层只做**判定**，不做政策：要宣告哪些 Profile、钥引用要落在哪个关系里，都是 Profile
// 的事（P5 §4.1.1 第 2、3 项），由调用方作为 {@link DeviceRequirement} 传进来。把它们写成
// 本模块的常量，就等于让 P6 的资格判定跟着 P5 的答案走。
//
// 与错误码的对应是**逐字对表**，不是就近取一个（P1 §10.3 L713–716）：
//
//   1015 `anp.device_binding_required`   "selector 缺失"      —— 由方法表 / Profile 规则报，
//                                                               不在本模块（本模块收到时它已经在了）
//   1016 `anp.device_binding_invalid`    "selector 或其 DID/密钥绑定无效"
//   1017 `anp.device_not_eligible`       "所选设备当前不具备所请求安全 Profile 的资格"
//   1018 `anp.device_state_changed`      "先前解析的资格或密钥状态已不再是当前状态"
//
// 1018 在这里**没有产生路径**：它说的是"我们手里那份旧结论过期了"，而本服务对这些设备不
// 保存任何旧结论——每次都是当下解析。将来 Key 方法那边有一条，因为 `prekey_bundles` 里
// 存着 `(owner_did, owner_device_id)` 这一行（见 [e2ee-direct.md](../../../docs/design/e2ee-direct.md) §2）。

import {
  anpRejection,
  type AnpRejection,
  type DeviceEntry,
  type DeviceRelationship,
  type DeviceResolver,
  type LocateOptions,
} from '@agentx/core'

/** 一个 Profile 对"这台设备算不算数"的全部要求。 */
export interface DeviceRequirement {
  /** 该条目必须**全部**宣告的 Profile。P2 §5.5 L267 规则 5 要求 `profiles` 是**完整**
   *  依赖集，所以这里给的是 Profile 自己加上它的依赖（P5 → P1/P2/P3/P5 四项）。 */
  profiles: readonly string[]
  /** `signing_key_id` 必须落在哪个验证关系里。P2 §10.2.1 L629 说同一个 keyid 在
   *  `origin_proof` 场合要 `authentication`、在 Object Proof 场合要 `assertionMethod`，
   *  所以这是**每个 Profile 自己选的**，不是这里定死的。 */
  signingRelationship: DeviceRelationship
  /** `e2ee_key_id` 必须落在哪个验证关系里。P2 §5.5 L266 规则 4：**MUST** 是 `keyAgreement`。 */
  e2eeRelationship: DeviceRelationship
}

/**
 * 这次调用是**设备定址**的，以及这意味着什么。
 *
 * 两件事放在一个返回值里而不是方法表上两个字段，是因为它们**只有一个前提**："这次调用
 * 点名了两台设备"。断成两处就会有两处各自判这个前提，而漏掉一处不会编译失败——表现是
 * 幂等键少了设备段（同一个操作从两台设备发出被当成两件事），或者资格根本没查。
 */
export interface DeviceAddressed {
  /** `[sender_device_id, recipient_device_id]`，按 §11.5 L1458 写的顺序。它们进幂等键
   *  （§9.1 L639），所以顺序由 Profile 说了算；`idempotencyKey()` 会再排序。 */
  readonly selectors: readonly [string, string]
  /** 这两台设备各自要满足的资格（§4.1.1）。 */
  readonly requirement: DeviceRequirement
}

export interface DeviceEligibilityInput {
  resolver: DeviceResolver
  requirement: DeviceRequirement
  /** 拥有这台设备的 Agent DID。 */
  identity: string
  /** P5 的 `meta.sender_device_id` / `meta.recipient_device_id`。 */
  deviceId: string
  opts?: LocateOptions
}

/** 设备的显示名，只进日志与错误消息——它是对端写的字符串，不得进任何判定。 */
function name(identity: string, deviceId: string): string {
  return `${identity}#${deviceId}`
}

/**
 * 判定一台设备当前是否合格；合格就把条目交回，不合格就交回一条拒绝。
 *
 * 四步与 §4.1.1 的四项一一对应，顺序也是规范的顺序：先"选中恰好一条"，再"宣告了本
 * Profile"，最后"密钥引用落在要求的关系里"。把顺序反过来会让一条恶意的清单选择把错误码
 * 引到别的分支上。
 */
export async function checkDevice(input: DeviceEligibilityInput): Promise<DeviceEntry | AnpRejection> {
  const { resolver, requirement, identity, deviceId } = input
  const entries = await resolver.resolveDevice(identity, deviceId, input.opts ?? {})

  // §4.1.1 第 1 项：`d` **恰好**选中当前清单里的一条。零条与多条是两回事——零条是"这台
  // 设备不存在了"，多条是"这份文档违反 P2 §5.5 规则 3（`device_id` MUST 唯一）"。前者的
  // 处置是"换一台设备再试"，后者是"这份文档不能用来定址"，所以不能共用一个码。
  if (entries.length === 0) {
    return anpRejection('anp.device_not_eligible', `${name(identity, deviceId)} is not in the DID's deviceManifest`)
  }
  if (entries.length > 1) {
    return anpRejection(
      'anp.device_binding_invalid',
      `the deviceManifest for ${identity} lists device_id "${deviceId}" ${String(entries.length)} times`,
      { details: { device_id: deviceId } },
    )
  }
  const entry = entries[0]
  if (entry === undefined) return anpRejection('anp.device_not_eligible', `${name(identity, deviceId)} is not eligible`)

  // §4.1.1 第 2 项：这一条要宣告本 Profile 与它的依赖集。少宣告一项就整条不算数——
  // 依赖集不完整意味着这台设备没有承诺它会处理哪个族，而"没承诺"不能读成"承诺了"。
  const missing = requirement.profiles.filter((profile) => !entry.profiles.includes(profile))
  if (missing.length > 0) {
    return anpRejection(
      'anp.device_not_eligible',
      `${name(identity, deviceId)} does not declare ${missing.join(', ')}`,
      { details: { device_id: deviceId, missing_profiles: missing } },
    )
  }

  // §4.1.1 第 3 项 + P2 §5.5 规则 4：两个 keyid 各自要落在要求的关系里。分两次报而不是
  // 合成一条，是因为诊断要指出**是哪一个**引用不对，而对端要改的正是那一处。
  if (!entry.signingAuthorizedBy.includes(requirement.signingRelationship)) {
    return anpRejection(
      'anp.device_binding_invalid',
      `${name(identity, deviceId)}: signing_key_id ${entry.signingKeyId} is not authorized by ${requirement.signingRelationship}`,
      { details: { device_id: deviceId, signing_key_id: entry.signingKeyId } },
    )
  }
  if (!entry.e2eeAuthorizedBy.includes(requirement.e2eeRelationship)) {
    return anpRejection(
      'anp.device_binding_invalid',
      `${name(identity, deviceId)}: e2ee_key_id ${entry.e2eeKeyId} is not authorized by ${requirement.e2eeRelationship}`,
      { details: { device_id: deviceId, e2ee_key_id: entry.e2eeKeyId } },
    )
  }
  return entry
}

/** 交回的是条目还是拒绝——调用点写 `if (isRejection(outcome)) return …`，
 *  否定分支就被收窄成条目。`code` 是 `AnpRejection` 独有的数字字段，所以这个判别不会
 *  因为将来给条目加一个字段而失效。 */
export function isRejection(outcome: DeviceEntry | AnpRejection): outcome is AnpRejection {
  return 'code' in outcome
}
