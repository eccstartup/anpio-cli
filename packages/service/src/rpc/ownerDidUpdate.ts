// 换钥之后那批投递的归属（TODO7 §3 第 4 条，用户 2026-10-03 裁定：
// 「服务端换钥时把投递挪到新 DID 名下」）。
//
// ## 问题
//
// `deliveries.owner_did` 存的是**收件人当时那个 DID**，而 `did:wba` 的身份把钥指纹嵌在
// DID 里——换钥换的就是 DID 本身。于是同一个人的信箱会被劈成两半：对端换钥后重新解析、
// 把信投到新 DID 上，新旧两批分居两个 `owner_did`，而客户端只认自己**当前**那个 DID。
// 它读新的一半，旧的那批一条都取不到，失败方式还是最难发现的一种：一次**退出 0 的空搬**
// （`msg fetch` 答 "brought in: 0"，而"真的没有"与"有，但挂在旧 DID 下"分不出来）。
//
// ## 与 §8.12 是同一件事的两个面
//
// 群名册那边（`memberDidUpdate.ts`）已经有一套完整的做法：**从一个记下来的旧 DID 出发、
// 用 P2 验到新 DID 的完整转移、按档位决定采不采信**。这里缺的只是"记下来的旧 DID"——
// 群有 `group_members`，账号没有名册。`account_dids` 那张表就是补上这一点，键取稳定主体
// 路径（`subjectOf`），于是"这个人现在用的是哪个 DID"有了一个可以对照的水位线。
//
// 采信的门槛**逐字复用 §8.12 那一条**（`ACCEPTED_ASSURANCES`）：同一个问题不能有两套答案，
// 而且用户 2026-10-02 对档位的裁定说的是"建立连续性要哪几档"，与这里问的是同一件事。
//
// ## 触发面：自址请求
//
// 与群那边一样，这不是一个方法（没有任何客户端能"上报换钥"），只能是别的事的路上顺手做完。
// 触发条件只有一条：**这次调用是账号以自己的身份、对自己的信箱发起的**（`meta.target.did`
// 等于验过签的调用方 DID）。`sync.delta` 正是那一类，而它也正是发现不了旧投递的那条路。
//
// 发现是**按需的**：水位线与调用方 DID 一致时一次索引读就返回了，只有真的不一致才走网络
// 解析转移链——也就是一次换钥最多解析一次，之后水位线跟上，不再解析。

import { subjectOf, type DidChain } from '@agentx/core'
import type { Config } from '../config'
import type { Storage } from '../storage/types'
import { ACCEPTED_ASSURANCES, chainResolverFor, type DidChainResolver } from './memberDidUpdate'

export interface OwnerDidUpdateInput {
  storage: Storage
  config: Config
  /** 验过签的调用方 DID——也就是**可能**是水位线上那个旧 DID 的后继的那一个。 */
  actorDid: string
  acceptedAt: string
  /** 测试注入点，见 `DidChainResolver`。 */
  resolveChain?: DidChainResolver
  log?: (line: string) => void
}

/**
 * 这次调用该不该顺路看一眼账号自己的换钥。
 *
 * 判据是"自址"：`meta.target.did` 与验过签的调用方同值。取 `target` 而不是 `sender_did`
 * 是有意的——它保证了这次调用说的是**这个账号自己的**信箱，而不是它替别人做的事
 * （`direct.send` 投给对端时两者不同，不自址，也就不该在这里动账号的归属）。
 */
export function isSelfAddressed(actorDid: string, targetDid: string | undefined): boolean {
  return targetDid !== undefined && targetDid !== '' && targetDid === actorDid
}

/**
 * 受理前的那一步。返回 `true` 表示这次真的把一批投递挪了家（值得记一行日志）。
 *
 * 一条也不成立时**静默返回 `false`**，让这次请求走它本来就走的路——这里的每一条"不成立"
 * 都不是这个请求的错误，而是"这次调用不构成一次换钥"。给它们各造一个错误码，等于让一次
 * 普通的取件因为对端 DID 服务器的状态而变成另一个错误；这与 §8.12 那三条触发路的处置一致。
 */
export async function adoptOwnerDidForRequest(input: OwnerDidUpdateInput): Promise<boolean> {
  const { storage, actorDid } = input
  const log = input.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))

  // `subjectOf` 是全函数（`did:web` / CAIP-10 原样返回），所以不需要 try——一个不会换 DID 的
  // 身份，它的主体路径就等于它自己，水位线永远不会与它对不上。
  const subject = subjectOf(actorDid)
  const known = storage.accountDid(subject)
  if (known === undefined) {
    // 第一次见这个主体：记下水位线，没有前身可谈。
    storage.rememberAccountDid(subject, actorDid, input.acceptedAt)
    return false
  }
  if (known === actorDid) return false

  // 到这里是"水位线上记着的是另一个 DID"。可能是这个账号换了钥，也可能是一个同主体路径的
  // DID 在冒名——两者的区别只有转移链说得出来，所以往下走一次解析。
  //
  // **走 `fresh` 档：这一次解析绕过文档缓存。** 缓存里那份是换钥**之前**抓的，它自己看不见
  // "这条 DID 已经换过了"，靠它只会把发现推到 `AGENTX_DID_CACHE_TTL_MS` 之后（出厂 5 分钟）。
  // 而这一步正是整个功能的目的所在，代价又只落在"水位线对不上"这一种状态上——一次真换钥之后
  // 水位线就跟上了，只解析这一次。详见 `chainResolverFor` 的 `fresh` 说明与
  // [message-service.md](../docs/design/message-service.md) §9.6。
  const resolveChain = input.resolveChain ?? chainResolverFor(input.config, { fresh: true })
  let chain: DidChain
  try {
    chain = await resolveChain(known)
  } catch (err) {
    // 链断了、成环了、超长、或对端 DID 服务器不可达。三种都不采纳，而且**不动水位线**——
    // 动了下一次就没得对照了。这与 §8.12 那边"判不了就不采纳"同一处置。
    log(
      `anp: could not resolve the DID chain of ${known} for ${actorDid}: ${err instanceof Error ? err.message : String(err)}`,
    )
    return false
  }
  // 链上那个旧 DID 没有被取代，而它的后继也不是眼前这个：那是两个人在用同一个主体路径，
  // 本服务无从判断谁是谁。不猜，水位线也不动。
  if (!chain.superseded || chain.currentDid !== actorDid) {
    log(
      `anp: ${actorDid} claims the mailbox of ${known} but the chain says ${chain.superseded ? chain.currentDid : 'no successor'}`,
    )
    return false
  }
  // 档位。与 §8.12 同一份清单、同一句理由（`memberDidUpdate.ts` 上写着）。
  if (!ACCEPTED_ASSURANCES.includes(chain.assurance)) {
    log(
      `anp: refusing to move ${known}'s mailbox to ${actorDid}: assurance ${chain.assurance} is below policy`,
    )
    return false
  }

  // 水位线跟着迁移一起走：**迁移成功才写**。反过来的顺序会让一次失败留下一行"已经是新 DID"
  // 的水位线，下一轮连"该不该迁"都问不出来了。
  const moved = storage.migrateOwner(known, actorDid)
  storage.rememberAccountDid(subject, actorDid, input.acceptedAt)
  log(
    `anp: mailbox of ${known} -> ${actorDid} (assurance ${chain.assurance}, ${String(moved)} deliveries, subject ${subject})`,
  )
  return true
}
