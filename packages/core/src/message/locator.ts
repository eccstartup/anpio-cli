// 身份解析的**可插拔层**（[vendored-core.md](../../../docs/design/vendored-core.md) §6）。
//
// 为什么要有这一层：ANP 的身份材料是**取**来的（查 DID server），CAIP-10 的身份
// 材料是**随请求内联带过来**的，两者连"信任来自哪里"都不是一回事。把差异关在这里，
// 调用点就永远不需要问"这是 DID 还是账户 id"——一旦某个调用点开始 `if (isDid(x))`，
// 这道门就关上了，而且关得很安静。
//
// v1 只实现 DID 那一个。接口先立着不是过度设计：实现只有一个，但**留不留门**是
// 用户明确裁定过的取舍。

import { resolveDidDocument, resolveVerificationKey } from '../crypto/resolveDid'
import type { ResolveDidOptions, ResolvedKey } from '../crypto/resolveDid'
import { ConnectxError } from '../errors'

/**
 * 这份密钥材料**凭什么可信**。三种不可比，所以是判别联合而不是一个布尔标志：
 *
 * - `fetched` —— did:web：域 + TLS。信任来自传输，材料本身不自证
 * - `fingerprint` —— did:wba：标识符里承诺了指纹，文档里的钥必须对上
 * - `derived-address` —— CAIP-10：地址由公钥派生，**必须先派生校验、再验签**
 *   （提案 §5.1）。顺序反了就等于没校验
 */
export type TrustAnchor =
  | { kind: 'fetched'; url: string }
  | { kind: 'fingerprint'; thumbprint: string }
  | { kind: 'derived-address'; address: string }

/** P2 §8.1 L337–347：服务条目的三个必填成员，外加两个标准提示。 */
export interface ServiceEntry {
  id: string
  type: string
  serviceEndpoint: string
  /** P2 §8.7 L377：跨域服务身份，**裸域名 DID**，不是 DID URL。
   *  参与跨域服务间调用时 MUST 存在。 */
  serviceDid?: string
  /** P2 §8.1 L339：文档里是驼峰。运行时 `anp.get_capabilities` 的结果用
   *  `supported_profiles`——**两处拼法不同，不是笔误**。 */
  profiles?: string[]
  securityProfiles?: string[]
}

/** 定位选项。`didDocument` 是内联文档——CAIP-10 §4.3 禁止网络解析，
 *  本地开发也用它（本机还没有可达的 `.well-known` 时）。 */
export interface LocateOptions extends ResolveDidOptions {
  didDocument?: unknown
}

/** 身份 + keyid → 用来验签的密钥，**以及这份材料是怎么可信的**。 */
export interface ResolvedIdentityKey extends ResolvedKey {
  /** keyid 所属的身份（`resolveVerificationKey` 从 keyid 推出来的那个）。 */
  identity: string
  anchor: TrustAnchor
}

/** 身份 → 它宣告的服务条目（可能为空）。 */
export interface ServiceLocator {
  locate(identity: string, opts?: LocateOptions): Promise<ServiceEntry[]>
}

/** 身份 + keyid → 验签用的钥。 */
export interface KeyResolver {
  resolve(identity: string, keyid: string, opts?: LocateOptions): Promise<ResolvedIdentityKey>
}

/**
 * 本模块唯一接受的"不是 DID"的判定，且**只在这里使用**。
 *
 * 导出它是为了让上层能给出"这个身份我根本不处理"的说明，**不是**为了在命令层
 * 复制一份判断——§6.3 的评审清单针对的正是那种复制。
 */
export function isDidIdentity(identity: string): boolean {
  return identity.startsWith('did:')
}

/**
 * v1 的 DID 实现：读 DID 文档的 `service` 列表，原样交出去。
 *
 * **选哪一条是 `discovery.ts` 的事**，不是这里的事——"每个 DID 文档只允许一个可跨域
 * 的 ANPMessageService"（P2 §7.1 L352）是一条业务规则，而这层只回答"文档里有什么"。
 * 把选择塞进来，会让这个定位器对 agent description 之类的其它服务条目也变得不能用。
 */
export class DidServiceLocator implements ServiceLocator {
  async locate(identity: string, opts: LocateOptions = {}): Promise<ServiceEntry[]> {
    if (!isDidIdentity(identity)) {
      // 账户 id 上**没有任何地方**可以问入口服务（§6.1）。这与"DID 文档里没有服务条目"
      // 是两件不同的事实，所以给两个不同的码：空数组会被上层读成后者。
      throw new ConnectxError(
        'caip10_has_no_ingress',
        `"${identity}" is not a DID, so it names no service endpoint`,
      )
    }
    const document =
      opts.didDocument !== undefined
        ? (opts.didDocument as Record<string, unknown>)
        : (await resolveDidDocument(identity, opts)).document
    const services = document.service
    if (!Array.isArray(services)) return []
    return services.filter(isServiceEntry).map(toServiceEntry)
  }
}

/**
 * v1 的 DID 实现：委托给 `resolveVerificationKey`——它已经把该做的全做了
 * （解析文档、按 keyid 找 verification method、**校验 `authentication` 授权**、
 * 解出公钥、以及 did:wba 的指纹绑定）。
 *
 * 这里**刻意不重写**那套逻辑：验签侧少做一步"是否被 authentication 授权"，
 * 就是"名字里带 keyid"与"这个 keyid 真的能用来认证"之间的全部差别。
 */
export class DidKeyResolver implements KeyResolver {
  async resolve(identity: string, keyid: string, opts: LocateOptions = {}): Promise<ResolvedIdentityKey> {
    if (!isDidIdentity(identity)) {
      // CAIP-10 的钥今天走不通，但**不是**因为"没入口"——它内联带文档，不需要入口。
      // 走不通是因为 `Caip10KeyResolver` 还没实现（§6.4：抽象现在做，实现以后做）。
      // 用 `invalid_did` 而不是 `caip10_has_no_ingress`，是为了别让诊断撒谎。
      throw new ConnectxError(
        'invalid_did',
        `"${identity}" is not a DID; account-id key resolution is not implemented in v1`,
      )
    }
    const key = await resolveVerificationKey(keyid, opts.didDocument, opts)
    return {
      ...key,
      identity: keyid.includes('#') ? keyid.slice(0, keyid.indexOf('#')) : keyid,
      anchor: trustAnchorFor(identity, key),
    }
  }
}

/** 文档里的服务条目是否可用——P2 §8.1 三个必填成员都在。 */
function isServiceEntry(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const v = value as Record<string, unknown>
  return typeof v.id === 'string' && typeof v.type === 'string' && typeof v.serviceEndpoint === 'string'
}

function toServiceEntry(value: Record<string, unknown>): ServiceEntry {
  const entry: ServiceEntry = {
    id: value.id as string,
    type: value.type as string,
    serviceEndpoint: value.serviceEndpoint as string,
  }
  if (typeof value.serviceDid === 'string') entry.serviceDid = value.serviceDid
  if (Array.isArray(value.profiles)) entry.profiles = value.profiles.filter((p): p is string => typeof p === 'string')
  if (Array.isArray(value.securityProfiles)) {
    entry.securityProfiles = value.securityProfiles.filter((p): p is string => typeof p === 'string')
  }
  return entry
}

/**
 * 这份材料凭什么可信——从标识符的形状读出来，而不是从"我们做了一次网络请求"读出来。
 *
 * did:wba 的信任来自标识符里的指纹（`resolveVerificationKey` 已经校验过它），
 * 所以**不能**因为这次是内联文档就降级成 `fetched`：那样会把"标识符承诺了钥"
 * 与"我从某个 URL 拿到了文档"混为一谈。
 */
function trustAnchorFor(identity: string, key: ResolvedKey): TrustAnchor {
  if (identity.startsWith('did:wba:')) {
    const last = identity.slice(identity.lastIndexOf(':') + 1)
    return { kind: 'fingerprint', thumbprint: last }
  }
  return { kind: 'fetched', url: key.docUrl ?? '' }
}
