// 本服务对外声明的能力清单 —— 发现的两种呈现取同一份事实。
//
// 静态 hint（`.well-known/anp-message-service.json` 那条服务条目里的 `profiles` /
// `securityProfiles`，DID 文档里就是同一份字段）与运行时权威（`anp.get_capabilities` 的
// `supported_profiles`）在这里汇合。两边各写一份的话，不一致只会在客户端缓存过期之后才
// 发作：P1 §8.3 L591–593 要求冲突时以运行时为准并刷新缓存，也就是说客户端会先拿一个过期
// 的 hint 去发一条注定被 1001 拒掉的请求，然后才走到刷新那一步。
//
// 清单从方法表**推**出来而不是手写。手写的那份在加了方法之后不会红，而它正是客户端用来
// 决定"能不能发"的东西——一处漏改就是一次拒绝，且拒绝的理由看起来像客户端的错。
//
// 扩展（`x_` 命名空间）与规范 Profile 分开列。P1 §8.1 L457 的 `profiles` 是"服务端点
// 直接支持的 ANP Profile 集合"，把 `x_anpiocli.*` 塞进去等于让一个只实现规范的服务看起来
// 支持它们（message-service.md §13 L834–838），而扩展另有 `x_anpiocli` 块这条路。

import type { Config } from './config'
import { allMethods, type MethodSpec } from './rpc/methods'
import { ACCEPTED_CONTENT_TYPES } from './rpc/payload'

/** 扩展所在的命名空间。P1 §6.2.2 L277 要求 `meta.profile` 是一个标识，本服务的扩展用
 *  `x_` 打头（realtime.md §9）；"哪些是本服务的扩展"这个判断因此只有这一处。 */
const EXTENSION_PREFIX = 'x_'

/**
 * 实现了、但**不得对外声明为稳定 Profile** 的那些。
 *
 * 今天只有 P6 一条，依据是它自己的规范：§6.3.1 L430 说本草案为
 * `anp_did_wba_device_binding` 暂定的 MLS `ExtensionType` `0xF0A1` **不是** IANA 分配，
 * 且"ANP 在发布 v2 前 **MUST** 公布稳定的注册 code point"；§20 L2457 把那条注册列为后续
 * 版本 **SHOULD** 建立的注册表之一。
 *
 * 也就是说：**协议本体还没定稿**。把它列进 `supported_profiles` 是让一个标准客户端按
 * §8.3 L591–593 把它当成"对端已实现、可以发"的运行时权威，而对方发出的 KeyPackage 里
 * 那个 extension 值明天就可能变。所以实现照做、声明留白——`lookupMethod` 仍然认这两条方法，
 * 直接发过来是能受理的（§6.3.1 L431 说该值"**MUST** 仅在显式协商 `anp.group.e2ee.v2` 后
 * 使用"，显式协商就是调用方自己写明 `meta.profile`，不是靠这份清单）。
 *
 * 与此并列的一条后果：官方 Rust 参考实现把同一件事做成了显式门禁
 * `ErrP6V2PublicReleaseBlocked`（`rust/src/group_e2ee/v2_errors.rs:84`）。上游公布稳定
 * codepoint 之后，删掉这一项即可，方法表不用改。
 */
const WITHHELD_PROFILES: ReadonlySet<string> = new Set(['anp.group.e2ee.v2'])

/** 上面那一份，导出给测试用。
 *
 *  它不是"实现细节"：`capabilities.test.ts` 钉住的正是**这份清单被改动**这件事——每多扣留
 *  一条 Profile，都要有人在那个测试里说明依据，而不是让它跟着方法表悄悄改变对外承诺。 */
export const WITHHELD_PROFILE_LIST: readonly string[] = [...WITHHELD_PROFILES]

export interface ServiceCapabilities {
  /** 规范定义的 Profile。可以进 `.well-known` 的 `profiles` 与 `anp.get_capabilities`
   *  的 `supported_profiles`。 */
  profiles: string[]
  securityProfiles: string[]
  /** `x_` 命名空间下的 Profile，以及分属它们的方法。**不得**进上面那两项。 */
  extensionProfiles: string[]
  extensionMethods: string[]
}

export function serviceCapabilities(): ServiceCapabilities {
  const profiles = new Set<string>()
  const securityProfiles = new Set<string>()
  const extensionProfiles = new Set<string>()
  const extensionMethods = new Set<string>()
  for (const spec of allMethods()) {
    const extension = isExtension(spec)
    for (const profile of spec.profiles) {
      if (WITHHELD_PROFILES.has(profile)) continue
      ;(extension ? extensionProfiles : profiles).add(profile)
    }
    // 安全模式**不**做同一件事：`transport-protected` 是 P1 的公共值、P7 与 P5 也在用它，
    // 少列一个只是少说一句真话。而 withheld 的那条 Profile 带来的**新**值 `group-e2ee`
    // 也一样要列：它只由 P6 的四条控制方法使用（§4.3 L273），那四条在方法表里，所以它跟着
    // 一起出现。扣留的是 Profile 的**名字**（§6.3.1 L430 的 codepoint 还没稳定），不是这个
    // 服务与客户端之间关于"安全模式叫什么"的约定——安全模式的取值是 P1 §6.2.3 的词表，不是
    // 那条 Profile 定义的东西。
    for (const security of spec.securityProfiles) securityProfiles.add(security)
    if (extension) extensionMethods.add(spec.name)
  }
  return {
    profiles: [...profiles].sort(),
    securityProfiles: [...securityProfiles].sort(),
    extensionProfiles: [...extensionProfiles].sort(),
    extensionMethods: [...extensionMethods].sort(),
  }
}

/** 一个方法的 Profile **全部**在 `x_` 下，它才属于扩展面。用 `every` 而不是看第一个：
 *  将来一个方法同时挂规范 Profile 与扩展 Profile 时它归规范那一侧，而规范清单多列一个
 *  只是多说一句话，少列一个却会让客户端以为对方不会。 */
function isExtension(spec: MethodSpec): boolean {
  return spec.profiles.length > 0 && spec.profiles.every((profile) => profile.startsWith(EXTENSION_PREFIX))
}

/**
 * P1 §8.2.2 L547–581 的 `result`：`anp.get_capabilities` 的答复。
 *
 * 只放规范定义的字段。扩展能力不在这里报——这个结果是"**规范**能力"的运行时权威
 * （§8.3 L592），往里掺扩展会让一个标准客户端按规范理解出一个错误的结论；扩展的自我
 * 描述有另外两处（`.well-known` 的 `x_anpiocli` 块与 `stream.hello` 的 `profiles`）。
 */
export function capabilitiesResult(config: Config): Record<string, unknown> {
  const { profiles, securityProfiles } = serviceCapabilities()
  // 本服务只强制一个上限：请求体的大小（`ANPIOCLI_MAX_BODY`）。消息是装在请求里走的，所以
  // 它不可能比请求上限更大——报同一个数是一句真话，报一个更小的数则是在发明一条没有执行
  // 的约束。
  const cap = String(config.maxBody)
  return {
    service_did: config.serviceDid,
    supported_profiles: profiles,
    supported_security_profiles: securityProfiles,
    // §8.2.2 L570–573：值是**十进制字符串**（§7.3 L491），不是数字。
    limits: { max_request_bytes: cap, max_message_bytes: cap },
    supported_content_types: [...ACCEPTED_CONTENT_TYPES],
  }
}
