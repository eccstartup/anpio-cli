// C13 —— P6 §12.6 的 Device Delivery Queue 出站。
//
// 与 `delivery/worker.ts` 并排、不共用：那张表按 **DID** 键控（P4 / P3 的通知，一个账号一条
// 队列），这张按 **`(recipient_did, recipient_device_id)`** 键控（P6 的信封逐设备不可互换，
// §12.6 第一段）。同一个 DID 的两台设备是两条独立的队列，谁也不知道对方在收什么——那正是
// §12.6 第 4 条要的。
//
// 这个文件拥有四件别处不该知道的事：
//
//   1. **队内顺序**。§12.6 要一台设备的 `group.incoming` 按 `group_event_seq` 投、Commit 按
//      epoch 投，所以队列是**严格队头优先**的：一条投不出去，它后面的都不许走。`storage` 的
//      `dueDeviceEnvelopes` 已经把这条规则做进查询里（队头没到期的队列一行都不返回），这里
//      只负责"这条失败之后别再碰它的后续行"。
//   2. **投递前的资格复核**。§12.6 第 3 条：入队前与**每次投递尝试前**都要拿当前资格复核，
//      让投递在一台不再是当前合格 leaf 的设备上停下。两层：投影（`group_leaves` /
//      `group_members`）判"它还是不是这个群当前的 leaf"，对方的**当前 DID 文档**判"它还是不是
//      主人清单里的一台设备"。第二层非做不可——一台设备被主人从清单里删掉，不经过任何我们看得
//      见的控制动作，只有再读一次文档才知道，而 P6 §10.4 L1074 要求 Host MUST NOT 继续向一台
//      已撤销的设备投递新的服务数据。两个例外也在这里：§12.3 的最终 Remove 通知（它生来就是发
//      给一台已经不在群里的设备的），以及**已经被移除的那条 leaf 队列里已经入队的信封**
//      （§12.3 选定的 SHOULD 那条：让它们按序投完，最终通知压在最后）。
//      §8.12 的**投递触发**也挂在这一层（`deliver()` 里那次资格复核之前）：正要投的这个旧 DID
//      也许已经有合规后继，那样先把名册改过来再说（`rpc/memberDidUpdate.ts`）。
//   3. **本地投递**。收件人就住在本服务上时不走 HTTP 回环（与 P4 worker 同一条理由），而是
//      直接推给它自己那条 WebSocket 订阅——P6 的信封在 `deliveries` 里没有行，所以这里没有
//      第二条路可走（[e2ee-group.md] §6 记了为什么不给它写行）。设备不在线不当成失败：推一次
//      很廉价，每个 tick 重推换"设备一上线就收到"，真正的收尾交给下面那条在队时长闸门。
//   4. **有界保留**。§12.6 逐字要求保留上限是"显式、由部署声明"的。两条闸门：单条尝试次数
//      （与 P4 同形，管 HTTP 那头）与单条在队时长（管本地这头也在内的整条队列）。任一触发就
//      丢弃并记一笔——丢弃是**有意的放弃**，不是成功。两个数值是**部署档位**，来自 Config
//      （`AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS` / `..._MAX_AGE_MS`，见 `config.ts`），缺省 8 次 / 24 小时。
//
// ## 那三条 MUST NOT
//
//   - **不扇出给 sibling**：投递地址取的是队列行自己的 `(recipient_did, recipient_device_id)`，
//     不查这个 DID 还有哪些设备（§12.6 第 4 条）。
//   - **不改写信封**：`envelope_json` 原样当载荷发出去，一个字段都不重排、不重编号（第 2 条）。
//   - **不落明文**：本服务手里只有它自己发出去的那份密文（第 5 条）。

import {
  discoverMessageService,
  DidDeviceResolver,
  DidServiceLocator,
  postNotification,
  type AnpNotification,
  type DeviceResolver,
  type LocateOptions,
  type ServiceLocator,
} from '@agentx/core'
import type { Config } from '../config'
import { isOurOwnIngress } from '../http/server'
import { checkDevice, isRejection } from '../rpc/eligibility'
import { GROUP_E2EE_DEVICE } from '../rpc/groupE2ee'
import { adoptMemberDidForDelivery, type DidChainResolver } from '../rpc/memberDidUpdate'
import type { Storage, StoredDeviceEnvelope } from '../storage/types'
import type { SubscriberRegistry } from '../stream/registry'

/** 一轮最多处理多少条待发。 */
const DEFAULT_BATCH_SIZE = 20
const DEFAULT_BASE_BACKOFF_MS = 5_000
const DEFAULT_MAX_BACKOFF_MS = 5 * 60_000
const DEFAULT_INTERVAL_MS = 1_000

/** 最终通知在 §12.6 里有专门待遇，所以它是个有名字的取值，不写成裸字符串。 */
const FINAL_NOTICE = 'final-notice'

export interface DeviceQueueOptions {
  config: Config
  storage: Storage
  /** 本地设备的推送口。收件人住在本服务上时信封直接推给它那条订阅——P6 的信封在
   *  `deliveries` 里没有行，没有第二条路可走。 */
  registry: SubscriberRegistry
  /** 默认 core 的 `DidServiceLocator`。可换，是为了让测试不必上网就能回答"对端的入口在哪"。 */
  locator?: ServiceLocator
  /** 默认 core 的 `DidDeviceResolver`。与 {@link locator} 同一个理由可换：投递前的资格复核
   *  要读对方的 `deviceManifest`，测试不该为此上网。 */
  deviceResolver?: DeviceResolver
  /** §8.12 投递触发用的转移链解析（`rpc/memberDidUpdate.ts`）。默认就是那个模块自己的实现，
   *  可换是为了让测试不必上网——与 {@link deviceResolver} 同一个理由。 */
  chainResolver?: DidChainResolver
  locateOptions?: LocateOptions
  log?: (line: string) => void
  now?: () => Date
  batchSize?: number
  maxAttempts?: number
  baseBackoffMs?: number
  maxBackoffMs?: number
  intervalMs?: number
  maxQueueAgeMs?: number
  /** 退避抖动用的 `[0, 1)`。注入是为了让测试钉住重试时刻，不是为了放宽策略。 */
  random?: () => number
}

export interface DeviceQueueWorker {
  /** 跑一轮：把当下能投的都尝试一次。单条的失败会变成重排或丢弃，不会抛出来。 */
  runOnce(): Promise<void>
  start(): void
  stop(): void
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function queueKey(did: string, deviceId: string): string {
  // `\u0000` 不出现在 DID 或设备 ID 里，所以两个字段串起来不会与另一对相撞。
  return `${did}\u0000${deviceId}`
}

export function createDeviceQueueWorker(options: DeviceQueueOptions): DeviceQueueWorker {
  const { config, storage, registry } = options
  const locator = options.locator ?? new DidServiceLocator()
  const deviceResolver = options.deviceResolver ?? new DidDeviceResolver()
  const chainResolver = options.chainResolver
  const locateOptions = options.locateOptions ?? config.didResolution
  const log = options.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  const now = options.now ?? ((): Date => new Date())
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE
  // 两条有界保留闸门来自 Config（A5）：数值是部署档位，worker 选项只是让测试能钉住它们。
  const maxAttempts = options.maxAttempts ?? config.deviceQueue.maxAttempts
  const baseBackoffMs = options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS
  const maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS
  const maxQueueAgeMs = options.maxQueueAgeMs ?? config.deviceQueue.maxAgeMs
  const random = options.random ?? Math.random

  /** 第 `attempts` 次失败之后的等待时长（`attempts` 从 1 起）。与 P4 同一条算法与同一条
   *  理由（抖动在下半段，让同一个 tick 里一起失败的那批错开）。 */
  function backoffMs(attempts: number): number {
    const capped = Math.min(baseBackoffMs * 2 ** (attempts - 1), maxBackoffMs)
    return Math.round(capped * (0.5 + random() * 0.5))
  }

  /**
   * §12.6 第 3 条的复核，**第一层**：只读投影能得出的结论。
   *
   *   - leaf 行是 `terminal`（这台设备已经被 Remove 掉了）→ **能投**。这是第 3 条点名的第二个
   *     例外：§12.3 选定的那条路要求把已经入队的应用信封按序投完，最终通知压在最后；而"被移除
   *     过的 leaf 队列里还躺着的应用信封"正是这一档（这条 leaf 不再是 active 之后，只有
   *     `emitRemoveEnvelopes` 会碰它，而那一位只写最终通知）。
   *   - leaf 行是 `active`，但它的 `member_did` 已经不是 P4 `active` 成员 → **不能投**，留在
   *     队里。这是 §10.4 L1074 / §10.5 L1094 的中间态：整个成员要在 MLS 那边收尾，中间的 epoch
   *     MUST NOT 承载应用消息。等 owner 把这条 leaf Remove 掉，上面的第一条就接管了。
   *   - leaf 行是 `active`、成员也是 → **还要再问一层**（`'check'`），见 {@link deliver}。
   *
   * `final-notice` 直接放行：它生来就是发给一台已经不在群里的设备的，第 3 条把它列成第一个
   * 例外。
   */
  function projected(row: StoredDeviceEnvelope): 'deliver' | 'hold' | 'check' {
    if (row.kind === FINAL_NOTICE) return 'deliver'
    // leaf 行不会被删（`upsertGroupLeaf` 的注释），所以查不到只可能是队列行与投影对不上——
    // 这种行没有投递对象，按不可投处理（下一轮由超龄闸门收掉）。
    const leaf = storage.groupLeaf(row.groupDid, row.recipientDid, row.recipientDeviceId)
    if (leaf === undefined) return 'hold'
    if (leaf.state === 'terminal') return 'deliver'
    const member = storage.groupMember(row.groupDid, row.recipientDid)
    return member !== undefined && member.membershipStatus === 'active' ? 'check' : 'hold'
  }

  /**
   * 投一条。返回**这条行是否离开了队列**（投出去了，或按有界保留丢掉了）：
   *
   *   - `true`  = 队列前进了，调用方可以接着看下一条；
   *   - `false` = 这条行还在队头（投不出去 / 现在还不能投），**它后面的都不许走**。
   */
  async function deliver(row: StoredDeviceEnvelope): Promise<boolean> {
    const at = now()
    const drop = (reason: string): boolean => {
      log(`anp: device envelope to ${row.recipientDid}#${row.recipientDeviceId} (${row.kind}, seq ${row.seq}) dropped: ${reason}`)
      storage.dropDeviceEnvelope(row.recipientDid, row.recipientDeviceId, row.seq)
      return true
    }

    // 有界保留的第一道闸：在队时长。放在资格复核之前——它管的是"这条行还有没有资格待在队里"，
    // 与"这台设备还有没有资格收"是两件事。
    if (at.getTime() - Date.parse(row.enqueuedAt) > maxQueueAgeMs) {
      return drop(`queued longer than the ${maxQueueAgeMs}ms retention bound`)
    }

    const step = projected(row)
    if (step === 'hold') {
      // 不动它，也不重排：它是一个**临时**状态（成员要收尾），到期的那一天由 owner 的 Remove
      // 打开，或被保留上限收掉。重排反而会把"等我"记成"我失败了"。
      return false
    }

    try {
      // 第二层：对方的**当前**文档里还有没有这台设备。投影说不了这件事——一台设备被主人从
      // `deviceManifest` 里删掉，不经过任何我们看得见的控制动作，只有再读一次文档才知道。
      // P6 §10.4 L1074 要的就是这个：Host MUST NOT 继续把新的服务数据投给一台已撤销的设备。
      //
      // 放在 `try` 里是有意的：**解析不到**（对端 DID 服务器不可达）不是"这台设备没了"，那是
      // 一次投递失败，应当记一次尝试、退避重试。只有文档取回来了、而它里面没有这台设备
      // （或它的钥引用不再被授权），才是一个**判定**。
      if (step === 'check') {
        // §8.12 L946 的**投递触发**（MAY）：这个收件人的 DID 也许已经有合规的后继，名册该先改
        // 过来。问在资格复核**之前**，是因为"主人换了 DID"与"设备被撤销"在资格复核那里可能长
        // 得一样（都读不到当前文档），而处置相反：前者只改名册、群随之按 §10.5 暂停，后者才
        // 丢弃。这次解析与紧接着的 `checkDevice` 共用同一份文档缓存（`config.didResolution`），
        // 所以热路径上没有多出来的网络往返。
        //
        // 采纳之后就停手：名册搬到了新 DID，旧 DID 的 leaf 还在投影里，§10.5 的暂停成立，这条
        // 信封留在队里——它等的不是时间是一次控制动作（owner 按编排退役旧 leaf），之后走 §12.3
        // 的例外（被移除 leaf 的已入队信封按序投完）。重排没有意义，所以返回 `false`。
        const adopted = await adoptMemberDidForDelivery({
          storage,
          config,
          groupDid: row.groupDid,
          recipientDid: row.recipientDid,
          acceptedAt: at.toISOString(),
          ...(chainResolver !== undefined ? { resolveChain: chainResolver } : {}),
          log,
        })
        if (adopted) return false

        const outcome = await checkDevice({
          resolver: deviceResolver,
          requirement: GROUP_E2EE_DEVICE,
          identity: row.recipientDid,
          deviceId: row.recipientDeviceId,
          opts: locateOptions,
        })
        if (isRejection(outcome)) {
          // 投影还说它是个 leaf，文档里已经没有它了：主人的清单比我们的投影新。留在队里没有
          // 意义——它等的那一天不会来（`group.e2ee.remove` 只会把这条 leaf 转成 terminal，而
          // 那是"按序投完再补一封最终通知"的待遇，不是发给一台已撤销设备的）。丢弃并记一笔，
          // 与 §12.6 对每一种信封写明的丢弃处置一致。
          return drop(`no longer an eligible device: ${outcome.message}`)
        }
      }

      const target = await discoverMessageService(row.recipientDid, { locator, ...locateOptions })
      if (isOurOwnIngress(config, target.endpoint)) {
        // P6 的信封在 `deliveries` 里没有行，所以不能像 P4 那样"已经在本机躺着了"就丢掉——
        // 得真推给那条订阅。推不到（设备没连着）不算失败，见文件头第 3 条。
        const served = registry.publishDevice(row.recipientDid, row.recipientDeviceId, row.envelopeJson)
        if (!served) return false
      } else {
        await postNotification(target.endpoint, JSON.parse(row.envelopeJson) as AnpNotification, locateOptions)
      }
      // §12.6：传输确认（一次完成的写）之后 MAY 出队。这条链路是单向通知，没有应用层确认，
      // 所以"写成功"就是这里的全部判据。
      if (row.kind === FINAL_NOTICE) {
        log(`anp: final notice delivered to ${row.recipientDid}#${row.recipientDeviceId} (${row.groupDid})`)
      }
      storage.dropDeviceEnvelope(row.recipientDid, row.recipientDeviceId, row.seq)
      return true
    } catch (err) {
      const attempts = row.attempts + 1
      const reason = describe(err)
      // 有界保留的第二道闸：尝试次数。到顶即丢弃——收件人可能永远不会知道这条信封存在过，
      // §12.6 对每一种信封都写了丢弃之后怎么办（Welcome 要 Remove 再 Add、Commit 要 Remove
      // 让设备重新加入、应用信封只丢这一条、最终通知本来就不用管）。
      if (attempts >= maxAttempts) return drop(`no transport confirmation after ${attempts} attempts: ${reason}`)
      storage.rescheduleDeviceEnvelope(
        row.recipientDid,
        row.recipientDeviceId,
        row.seq,
        attempts,
        new Date(at.getTime() + backoffMs(attempts)).toISOString(),
        reason,
      )
      log(`anp: device envelope to ${row.recipientDid}#${row.recipientDeviceId} failed (attempt ${attempts}): ${reason}`)
      return false
    }
  }

  async function runOnce(): Promise<void> {
    let due: StoredDeviceEnvelope[]
    try {
      due = storage.dueDeviceEnvelopes(now().toISOString(), batchSize)
    } catch (err) {
      log(`anp: device queue worker could not read the queue: ${describe(err)}`)
      return
    }
    // 查询已经按 `(did, device, seq)` 排好，所以同一队列的行是连续的，且队头在前。一条行
    // 失败（或暂时不能投）之后，它后面那些**已经到期**的行这一轮一律跳过——否则就是在一条
    // 投不出队头的队列上按乱序投递，那正是 §12.6 禁止的。
    const blocked = new Set<string>()
    // 逐条串行：一次 tick 里并发几十个出站请求只是把对端的限流一次撞满。
    for (const row of due) {
      const key = queueKey(row.recipientDid, row.recipientDeviceId)
      if (blocked.has(key)) continue
      if (!(await deliver(row))) blocked.add(key)
    }
  }

  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false

  function schedule(): void {
    timer = setTimeout(() => void tick(), intervalMs)
    // 不挂住事件循环：worker 是服务的附属物，进程该不该活着由 socket 决定。
    timer.unref?.()
  }

  async function tick(): Promise<void> {
    try {
      await runOnce()
    } catch (err) {
      log(`anp: device queue worker tick failed: ${describe(err)}`)
    } finally {
      if (!stopped) schedule()
    }
  }

  return {
    runOnce,
    start(): void {
      if (timer !== undefined || stopped) return
      schedule()
    },
    stop(): void {
      stopped = true
      if (timer !== undefined) clearTimeout(timer)
      timer = undefined
    },
  }
}
