// A3c —— P4 §8.12 的触发路，以及它们共用的那一段受理前验证。
//
// 场景是"对端的 DID 换了，我们还没同步"，而它下一步就拿着新 DID 来办事、或者我们正往那个旧
// DID 投东西。规范把这件事写成一个宿主动作而不是一个方法：`group.member_did_update` 被调用
// MUST 回 `-32601`（§8.12 L934），所以**没有任何客户端能让它发生**——它只能由 Host 自己在一件
// 别的事的路上顺手做完。规范点名了三条路（§8.12 L946 "MAY trigger …" 那一句）：一条新 DID
// 发起的请求（{@link adoptMemberDidForRequest}）、往旧 DID 投递时发现了合规的后继
// （{@link adoptMemberDidForDelivery}），以及定时刷新（A3c-4，尚未落地，见 TODO2.md）。前两条
// 都收敛到 `groups.ts` 的 `applyMemberDidUpdate`，靠 §8.12 那个确定性操作标识幂等收敛。
//
// 这个文件拥有三件事：
//
//   1. **请求触发的触发面**。§8.12 L946 逐字列了五个方法：`group.send`、`group.leave`、
//      `group.update_profile`、`group.update_policy`，以及**私有群的** `group.get_info`。
//      多一个都不做：`group.create` 那时还没有名册，`group.join` / `group.add` 的目标是别人，
//      `group.remove` 要的是调用方已有的权限。
//   2. **受理前那五条**（§8.12 L940–946）。其中"从记录里当前存着的那个 DID 出发、用 P2 验证
//      到主张的新 DID 的完整转移"要网络往返，所以整块在事务外跑；判出来的是一对 DID 加一个
//      保证档位，落库交给 `groups.ts` 的 `applyMemberDidUpdate`。
//   3. **档位口径**。用户 2026-10-02 裁定按**甲**：只接受 `verified` / `recovery_verified`，
//      `provider_asserted` 一律拒绝（规范把这一档写成"由自己的业务策略决定"，所以这不是
//      规范要求，是本服务的选择）。`unverified` 是规范硬性要求不能建立连续性的。
//
// ## 为什么"同步"这件事可以等，以及等到什么程度
//
// ANP 不为 DID 文档变化提供推送（P2 §5.5 规则 8），所以"对端换了 DID"这件事本服务**只能**
// 在用的时候才发现，窗口封不到零。窗口里发生的事是：旧 DID 的请求照常被当成成员受理——因为
// 名册里就是它。这不是漏洞，是"我们相信的还是上一次读到的那个事实"，而 A3a 的 TTL 就是这个
// 事实的新鲜度上界。真正必须挡住的是**反向**：旧 DID 已经不该被授权，而名册还认它。那正是
// 这里和投递触发、定时刷新一起要做的事。
//
// 顺带一件不能省的事：**旧 DID 为任何新操作都 MUST NOT 再被授权**（§8.12 L962）。改名把成员
// 行从旧 DID 上搬走之后，旧 DID 的请求自然落到 `group.not_member`（3000），不需要另写一条
// 判定——`requireActiveMember` 查的就是这一行。

import { resolveDidChain, stableSubjectId, type DidChain, type DidChainAssurance } from '@agentx/core'
import type { Config } from '../config'
import type { DeliveryRecord, Storage } from '../storage/types'
import {
  GROUP_GET_INFO,
  GROUP_LEAVE,
  GROUP_SEND,
  GROUP_UPDATE_POLICY,
  GROUP_UPDATE_PROFILE,
  applyMemberDidUpdate,
  memberDidUpdateOperationId,
} from './groups'

/**
 * 走一次转移链。抽成这一层是为了让测试不必上网——与 `DidDeviceResolver` / `DidServiceLocator`
 * 在别处可换是同一个理由，不是为了让生产代码有第二种实现。
 */
export type DidChainResolver = (did: string) => Promise<DidChain>

/** §8.12 L942：这两档才建立连续性。第三档 `provider_asserted` 由业务策略定，本服务不收；
 *  第四档 `unverified` 是规范硬性禁止的（"MUST NOT establish continuity"）。 */
const ACCEPTED_ASSURANCES: readonly DidChainAssurance[] = ['verified', 'recovery_verified']

/**
 * §8.12 L946 点名的五个方法里，无条件触发的那四个。
 *
 * 第五个 `group.get_info` **有条件**：对公开群，谁都能读它的资料快照（§8.2.2 L658），换没换
 * DID 与这次读取无关，所以不触发；只有私有群才需要先入册再受理（见
 * {@link requestTriggersDidUpdate}）。
 */
const UNCONDITIONAL_TRIGGERS: ReadonlySet<string> = new Set([
  GROUP_SEND,
  GROUP_LEAVE,
  GROUP_UPDATE_PROFILE,
  GROUP_UPDATE_POLICY,
])

/** 默认的链解析：core 的实现，选项就是本服务的解析策略（A3a 的缓存 + 那份共享的边台账）。
 *
 *  `reportLowAssurance: true` 是要拿到**档位本身**而不是一个异常：`provider_asserted` 被拒
 *  是一个要记下来的判定，不是一个出错的解析。core 的缺省策略恰好也是这两档，但在这里显式
 *  再判一次，是因为"我们收哪几档"是本服务的业务决定，不该藏在 core 的缺省值里。
 *
 *  `trustedDocuments` 传的是那份共享的文档缓存：§2.5.5 规则 2 只肯信一把**停用之前**的文档
 *  授权过的恢复钥，而"停用之前的那份文档"正是这个缓存在上一次解析时留下的那一份。所以
 *  `recovery_verified` 的可达范围就是缓存的 TTL 窗口——这个界记在
 *  [message-service.md](../docs/design/message-service.md) §14，不假装它更宽。 */
function chainResolverFor(config: Config): DidChainResolver {
  return (did) =>
    resolveDidChain(did, {
      ...config.didResolution,
      reportLowAssurance: true,
      trustedDocuments: config.didResolution.documentStore,
    })
}

/**
 * 这次请求该不该顺路看一眼换 DID。
 *
 * 先按方法名挡掉绝大多数调用（一个 `Set` 查表），只有 `group.get_info` 要读一次群资料来分辨
 * 公开与私有——那一次读 `getGroupInfo` 自己马上还要做，所以没有多出来的往返。
 */
export function requestTriggersDidUpdate(storage: Storage, method: string, groupDid: string): boolean {
  if (UNCONDITIONAL_TRIGGERS.has(method)) return true
  if (method !== GROUP_GET_INFO) return false
  const group = storage.group(groupDid)
  if (group === undefined) return false
  // 公开群的资料快照对匿名者都开放，所以"新 DID 来读一次资料"没有任何需要先补上的名册事实。
  return (JSON.parse(group.groupProfileJson) as Record<string, unknown>).discoverability === 'private'
}

export interface MemberDidUpdateTriggerInput {
  storage: Storage
  config: Config
  groupDid: string
  /** 这次请求自称的发起者——也就是那个**可能**是后继的 DID。 */
  actorDid: string
  acceptedAt: string
  onDelivery?: (record: DeliveryRecord) => void
  /** 测试注入点，见 {@link DidChainResolver}。 */
  resolveChain?: DidChainResolver
  log?: (line: string) => void
}

/**
 * 受理前的五条（§8.12 L940–946），从第 1 条走到第 3 条，然后交给 §8.12 的原子那一段。
 *
 * 一条也不成立时**静默返回 `false`**，让这次请求走它本来就走的路（多半是一句 3000）。这是
 * 有意的：这里的每一条"不成立"都不是这个请求的错误，而是"这次调用不构成一次换 DID"。给它们
 * 各造一个错误码，等于让一次普通的 `group.send` 因为对端 DID 服务器的状态而变成另一个错误。
 */
export async function adoptMemberDidForRequest(input: MemberDidUpdateTriggerInput): Promise<boolean> {
  const { storage, groupDid, actorDid } = input
  const log = input.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))

  const group = storage.group(groupDid)
  // 不托管这个群：没有名册可改。让处理器去回它的 3000。
  if (group === undefined) return false

  // 已经是 active 成员就是名册已经认它了，没有要补的事。这一条同时替 §8.12 第 4 条的"新 DID
  // 不属于另一个 active 成员"兜住了正向的一半。
  const existing = storage.groupMember(groupDid, actorDid)
  if (existing !== undefined && existing.membershipStatus === 'active') return false

  // 第 1 条的同族判断，先做一次**离线**的：同一个稳定主体路径下，名册里有没有一个 active 成员
  // 可能是它的前身。这是本地解析，不发网络——一个稳定主体在群里最多占一行，所以候选集极小。
  const candidates = predecessorCandidates(storage, groupDid, actorDid)
  if (candidates.length === 0) return false
  if (candidates.length > 1) {
    // §8.12 第 4 条的 "no candidate ambiguity"：两行 active 成员共享一个稳定主体路径，本服务
    // 无从判断来的是哪一行的后继。不猜——拒绝采信，这次请求落回它本来的拒绝。
    log(`anp: ${actorDid} has ${candidates.length} candidate predecessors in ${groupDid}; refusing to guess`)
    return false
  }
  const previousDid = candidates[0] as string

  // 第 2 条：从**记录里当前存着的那个 DID** 出发走完整的转移链。
  const resolveChain = input.resolveChain ?? chainResolverFor(input.config)
  let chain: DidChain
  try {
    chain = await resolveChain(previousDid)
  } catch (err) {
    // 链断了、成环了、超长、或对端 DID 服务器不可达。前三种是 §8.12 第 4 条要拒的，最后一种
    // 是"现在判不了"——三种在这里的处置相同（不采纳），而它们的区别在日志里。
    log(
      `anp: could not resolve the DID chain of ${previousDid} for ${groupDid}: ${err instanceof Error ? err.message : String(err)}`,
    )
    return false
  }

  if (!chain.superseded) return false
  if (chain.currentDid !== actorDid) {
    // 前身确实换了 DID，但换成的是**别人**。也许是这个 DID 又换了一轮还没传过来，也许是有人在
    // 拿一个同主体的 DID 冒名。两种都不采纳。
    return false
  }
  // 第 3 条：档位。用户裁定按甲——只收这两档。
  if (!ACCEPTED_ASSURANCES.includes(chain.assurance)) {
    log(
      `anp: refusing the DID update of ${groupDid} member ${previousDid} -> ${actorDid}: assurance ${chain.assurance} is below policy`,
    )
    return false
  }

  // §8.12 第 5 条的比较并交换，以及"after acceptance"那一整段，都在这里。返回 `false` 表示
  // 另一条触发路（定时刷新，或一次并发请求）已经改完了——那是收敛，不是失败。
  const applied = applyMemberDidUpdate({
    storage,
    hostServiceDid: input.config.serviceDid,
    groupDid,
    previousDid,
    subjectDid: actorDid,
    acceptedAt: input.acceptedAt,
    ...(input.onDelivery !== undefined ? { onDelivery: input.onDelivery } : {}),
  })
  if (applied) {
    log(
      `anp: ${groupDid} member ${previousDid} -> ${actorDid} (assurance ${chain.assurance}, operation ${memberDidUpdateOperationId(groupDid, previousDid, actorDid)})`,
    )
  }
  return applied
}

/**
 * 名册里那些**稳定主体路径与 `actorDid` 相同、但 DID 不是它**的 active 成员。
 *
 * 用 `stableSubjectId` 而不是"去掉最后一段"：那个函数是 core 里"哪一段是主体、哪一段是指纹"
 * 的权威判断，在命令层再写一份就是同一个问题有两份答案（[vendored-core.md](../docs/design/vendored-core.md)
 * §6.3 的评审清单钉的就是这条）。
 *
 * `stableSubjectId` 只对 `did:wba` 有定义，别的 DID 方法会抛。群成员是 DID（§3.8 DID-only），
 * 但一个非 `did:wba` 的 DID 完全可能出现，而它在这里的答案是"没有稳定主体可判"——于是既不是
 * 候选，也不该让一次请求炸掉。
 */
function predecessorCandidates(storage: Storage, groupDid: string, actorDid: string): string[] {
  let subject: string
  try {
    subject = stableSubjectId(actorDid)
  } catch {
    return []
  }
  const candidates: string[] = []
  for (const member of storage.groupMembers(groupDid)) {
    if (member.membershipStatus !== 'active') continue
    if (member.memberDid === actorDid) continue
    try {
      if (stableSubjectId(member.memberDid) === subject) candidates.push(member.memberDid)
    } catch {
      // 这一行不是 `did:wba`：它没有可比的主体路径，跳过。
    }
  }
  return candidates
}

// ---- 投递触发 ----------------------------------------------------------------

export interface MemberDidDeliveryTriggerInput {
  storage: Storage
  config: Config
  groupDid: string
  /** 队列行上那个 DID，也就是**名册里当前存着的那个**——要投递的目标。 */
  recipientDid: string
  acceptedAt: string
  /** 测试注入点，见 {@link DidChainResolver}。 */
  resolveChain?: DidChainResolver
  log?: (line: string) => void
}

/**
 * §8.12 L946：**投递触发**。与 {@link adoptMemberDidForRequest} 是同一件事的两个方向——那边
 * 来的是一个**新 DID 发起的请求**（所以要从名册往前找它的前身），这边是我们正要往一个**名册里
 * 的旧 DID** 投东西（所以那个旧 DID 就是起点，往前走的步子是直接读出来的）。
 *
 * 规范把它写成 MAY（"MAY trigger an update when … delivery fails …"），触发面因此很宽；本服务
 * 只在**投递前那次资格复核**上顺路问一次，理由记在 `delivery/deviceQueue.ts` 那处调用。
 *
 * 一条也不成立时**静默返回 `false`**，让这次投递照常往下走。与请求触发同一个取舍：这里的每
 * 一条"不成立"都不是投递的错误，而是"这次投递不构成一次换 DID"，不该把一次正常的投递变成失败。
 */
export async function adoptMemberDidForDelivery(
  input: MemberDidDeliveryTriggerInput,
): Promise<boolean> {
  const { storage, groupDid, recipientDid } = input
  const log = input.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))

  const group = storage.group(groupDid)
  // 不托管这个群：没有名册可改。（队列行理论上不会指到一个我们不托管的群，但读完再判比假设便宜。）
  if (group === undefined) return false

  // §8.12 第 1 条：恰好一条 `active` 且当前 DID 是这个旧 DID 的记录。不是 active（已移除 /
  // 已离开）就没有要补的名册事实，§8.12 的原子那一段也明确要求改名针对一条 active 记录。
  const member = storage.groupMember(groupDid, recipientDid)
  if (member === undefined || member.membershipStatus !== 'active') return false

  // §8.12 第 2 条：从**记录里当前存着的那个 DID**出发走完整的转移链。
  const resolveChain = input.resolveChain ?? chainResolverFor(input.config)
  let chain: DidChain
  try {
    chain = await resolveChain(recipientDid)
  } catch (err) {
    // 链断了、成环了、超长、或对端 DID 服务器不可达。前三种是 §8.12 第 4 条要拒的，最后一种
    // 是"现在判不了"——三种都不采纳，投递本身接下去照常走（合格就投，不合格由资格复核那一层
    // 丢弃）。与请求触发同一处置。
    log(
      `anp: could not resolve the DID chain of ${recipientDid} for ${groupDid}: ${err instanceof Error ? err.message : String(err)}`,
    )
    return false
  }
  // 名册里那个 DID 就是当前的：没有要补的事。（这是绝大多数投递走的那条路。）
  if (!chain.superseded) return false
  // §8.12 第 3 条：档位。用户裁定按甲——只收这两档，与请求触发同一口径。
  if (!ACCEPTED_ASSURANCES.includes(chain.assurance)) {
    log(
      `anp: refusing the DID update of ${groupDid} member ${recipientDid} -> ${chain.currentDid}: assurance ${chain.assurance} is below policy`,
    )
    return false
  }
  // §8.12 第 4 条："confirm that the new DID does not belong to another active member"。请求触发
  // 那一侧靠"候选唯一"兜住，这边没有候选可言（起点就是确定的一行），所以直接查新 DID。
  const clash = storage.groupMember(groupDid, chain.currentDid)
  if (clash !== undefined && clash.membershipStatus === 'active') {
    log(
      `anp: ${chain.currentDid} is already an active member of ${groupDid}; not adopting it as the successor of ${recipientDid}`,
    )
    return false
  }

  // §8.12 第 5 条的比较并交换，以及 "after acceptance" 那一整段。返回 `false` 表示另一条触发路
  // （一次并发请求，或定时刷新）已经改完了——那是收敛，不是失败。
  const applied = applyMemberDidUpdate({
    storage,
    hostServiceDid: input.config.serviceDid,
    groupDid,
    previousDid: recipientDid,
    subjectDid: chain.currentDid,
    acceptedAt: input.acceptedAt,
  })
  if (applied) {
    log(
      `anp: ${groupDid} member ${recipientDid} -> ${chain.currentDid} (assurance ${chain.assurance}, operation ${memberDidUpdateOperationId(groupDid, recipientDid, chain.currentDid)}, via delivery)`,
    )
  }
  return applied
}
