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
//      让投递在一台不再是当前合格 leaf 的设备上停下。两个例外也在这里：§12.3 的最终 Remove
//      通知（它生来就是发给一台已经不在群里的设备的），以及**已经被移除的那条 leaf 队列里
//      已经入队的信封**（§12.3 选定的 SHOULD 那条：让它们按序投完，最终通知压在最后）。
//   3. **本地投递**。收件人就住在本服务上时不走 HTTP 回环（与 P4 worker 同一条理由），而是
//      直接推给它自己那条 WebSocket 订阅——P6 的信封在 `deliveries` 里没有行，所以这里没有
//      第二条路可走（[e2ee-group.md] §6 记了为什么不给它写行）。设备不在线不当成失败：推一次
//      很廉价，每个 tick 重推换"设备一上线就收到"，真正的收尾交给下面那条在队时长闸门。
//   4. **有界保留**。§12.6 逐字要求保留上限是"显式、由部署声明"的。两条闸门：单条尝试次数
//      （与 P4 同形，管 HTTP 那头）与单条在队时长（管本地这头也在内的整条队列）。任一触发就
//      丢弃并记一笔——丢弃是**有意的放弃**，不是成功。
//
// ## 那三条 MUST NOT
//
//   - **不扇出给 sibling**：投递地址取的是队列行自己的 `(recipient_did, recipient_device_id)`，
//     不查这个 DID 还有哪些设备（§12.6 第 4 条）。
//   - **不改写信封**：`envelope_json` 原样当载荷发出去，一个字段都不重排、不重编号（第 2 条）。
//   - **不落明文**：本服务手里只有它自己发出去的那份密文（第 5 条）。

import {
  discoverMessageService,
  DidServiceLocator,
  postNotification,
  type AnpNotification,
  type LocateOptions,
  type ServiceLocator,
} from '@agentx/core'
import type { Config } from '../config'
import { isOurOwnIngress } from '../http/server'
import type { Storage, StoredDeviceEnvelope } from '../storage/types'
import type { SubscriberRegistry } from '../stream/registry'

/** 一轮最多处理多少条待发。 */
const DEFAULT_BATCH_SIZE = 20
/** 同一条最多尝试几次，到顶丢弃。与 P4 的 outbox 同形，同一条理由（P3 §8.4 L477 交给本地策略）。 */
const DEFAULT_MAX_ATTEMPTS = 8
const DEFAULT_BASE_BACKOFF_MS = 5_000
const DEFAULT_MAX_BACKOFF_MS = 5 * 60_000
const DEFAULT_INTERVAL_MS = 1_000
/** 一条信封最多在队里待多久。§12.6 要有界的、部署声明的保留上限；一天是本实现声明的值，
 *  不是规范的值。超龄的行在**投递前**扫掉，所以一台卡住的设备不会把自己的队列永久冻住。 */
const DEFAULT_MAX_QUEUE_AGE_MS = 24 * 60 * 60_000

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
  const locateOptions = options.locateOptions ?? config.didResolution
  const log = options.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  const now = options.now ?? ((): Date => new Date())
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS
  const baseBackoffMs = options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS
  const maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS
  const maxQueueAgeMs = options.maxQueueAgeMs ?? DEFAULT_MAX_QUEUE_AGE_MS
  const random = options.random ?? Math.random

  /** 第 `attempts` 次失败之后的等待时长（`attempts` 从 1 起）。与 P4 同一条算法与同一条
   *  理由（抖动在下半段，让同一个 tick 里一起失败的那批错开）。 */
  function backoffMs(attempts: number): number {
    const capped = Math.min(baseBackoffMs * 2 ** (attempts - 1), maxBackoffMs)
    return Math.round(capped * (0.5 + random() * 0.5))
  }

  /**
   * §12.6 第 3 条的复核：这条信封现在还能不能投给这台设备。
   *
   * 判据只有两个来源，都在投影里：
   *
   *   - leaf 行是 `terminal`（这台设备已经被 Remove 掉了）→ **能投**。这是第 3 条点名的第二个
   *     例外：§12.3 选定的那条路要求把已经入队的应用信封按序投完，最终通知压在最后；而"被移除
   *     过的 leaf 队列里还躺着的应用信封"正是这一档（这条 leaf 不再是 active 之后，只有
   *     `emitRemoveEnvelopes` 会碰它，而那一位只写最终通知）。
   *   - leaf 行是 `active`，但它的 `member_did` 已经不是 P4 `active` 成员 → **不能投**，留在
   *     队里。这是 §10.4 L1074 / §10.5 L1094 的中间态：整个成员要在 MLS 那边收尾，中间的 epoch
   *     MUST NOT 承载应用消息。等 owner 把这条 leaf Remove 掉，上面的第一条就接管了。
   *   - leaf 行是 `active`、成员也是 → **能投**。
   *
   * `final-notice` 直接放行：它生来就是发给一台已经不在群里的设备的，第 3 条把它列成第一个
   * 例外。
   */
  function deliverable(row: StoredDeviceEnvelope): boolean {
    if (row.kind === FINAL_NOTICE) return true
    // leaf 行不会被删（`upsertGroupLeaf` 的注释），所以查不到只可能是队列行与投影对不上——
    // 这种行没有投递对象，按不可投处理（下一轮由超龄闸门收掉）。
    const leaf = storage.groupLeaf(row.groupDid, row.recipientDid, row.recipientDeviceId)
    if (leaf === undefined) return false
    if (leaf.state === 'terminal') return true
    const member = storage.groupMember(row.groupDid, row.recipientDid)
    return member !== undefined && member.membershipStatus === 'active'
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

    if (!deliverable(row)) {
      // 不动它，也不重排：它是一个**临时**状态（成员要收尾），到期的那一天由 owner 的 Remove
      // 打开，或被保留上限收掉。重排反而会把"等我"记成"我失败了"。
      return false
    }

    try {
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
