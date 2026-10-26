// C5b —— outbox 的出站推送与退避重试。
//
// **C11 之后这个 outbox 只装通知**（P8 §3.4）：请求（`direct.send` / `group.*` /
// `attachment.*`）有人在等答复，走的是请求路径里的同步转发（`federation/forward.ts`），
// 因为 §6.7 L464 要求最终服务的错误**走回原始调用方**——异步 outbox 在受理那一刻就已经
// 答复过了，之后没有通道可回。这个文件保留的是 `group.incoming` / `group.state_changed` /
// `group.e2ee.notice` 那一档：没人在等，可以慢慢来。
//
// 分成两半的理由是事务：受理的整个操作（消息 + 投递 + 幂等记录）必须在一个事务里，而事务
// 里不得有网络往返——一次慢连接会让所有并发受理在锁上等。
//
// 这个文件拥有三件别处不该知道的事：
//
//   1. **推送目标**。解析收件人的 `ANPMessageService`，不是钉住受理那一刻的答案：域名
//      可以在两次重试之间换入口服务（`storage/types.ts` 里 `recipientDid` 的注释）。
//   2. **本地投递**。收件人就住在本服务上时，`deliveries` 那一行已经写好了，C7 的
//      订阅 / 取件面会把它交出去。再走一次 HTTP 回环只是绕远路，还会逼运营商把自己
//      的公网地址加进 `ANPIOCLI_ALLOWED_DID_HOSTS` 才转得动。
//   3. **退避**。P3 §8.4 L477 把这件事明确交给本地策略："发送失败后是否自动重发，
//      MAY 由服务按本地策略自行决定；本 Profile MUST NOT 要求必须重发、固定重发次数或
//      固定退避算法"。所以下面的数值是本实现的选择，不是规范的值。
//
// 出站的这条腿**幂等**：重发用同一份 `operation_id` / `message_id`，收件人按 P3 §8.2
// 的重复识别把它认出来。所以"可能重复推送"在这里不是缺陷，而是 §8.4 L471–477 允许的
// 那一档；反过来，宁可重发也不丢。

import {
  discoverMessageService,
  DidServiceLocator,
  postNotification,
  type AnpNotification,
  type LocateOptions,
  type ServiceLocator,
} from '@anpio-cli/core'
import type { Config } from '../config'
import { isOurOwnIngress } from '../http/server'
import type { OutboxEntry, Storage } from '../storage/types'

/** 一轮最多处理多少条待发。 */
const DEFAULT_BATCH_SIZE = 20
/** 同一条推送最多尝试几次，到顶丢弃。 */
const DEFAULT_MAX_ATTEMPTS = 8
/** 第一次失败之后等多久。 */
const DEFAULT_BASE_BACKOFF_MS = 5_000
/** 单次等待的上限。 */
const DEFAULT_MAX_BACKOFF_MS = 5 * 60_000
/** 轮询间隔。退避决定某一条**什么时候**到期，这个决定多久来看一次。 */
const DEFAULT_INTERVAL_MS = 1_000

export interface DeliveryOptions {
  config: Config
  storage: Storage
  /** 默认 core 的 `DidServiceLocator`。可换，是为了让测试不必上网就能回答"对端的入口在哪"。 */
  locator?: ServiceLocator
  /** 解析对端文档**与**推送时共用的网络策略。默认取 `config.didResolution`——两个
   *  地址（文档、入口服务）都由对端选定，没有理由用两套闸门。 */
  locateOptions?: LocateOptions
  log?: (line: string) => void
  now?: () => Date
  batchSize?: number
  maxAttempts?: number
  baseBackoffMs?: number
  maxBackoffMs?: number
  intervalMs?: number
  /** 退避抖动用的 `[0, 1)`。注入是为了让测试钉住重试时刻，不是为了放宽策略。 */
  random?: () => number
}

export interface DeliveryWorker {
  /** 跑一轮：把当下到期的都尝试一次。单条的失败会变成重排或丢弃，不会抛出来。 */
  runOnce(): Promise<void>
  /** 开始轮询。重复调用是空操作。 */
  start(): void
  stop(): void
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export function createDeliveryWorker(options: DeliveryOptions): DeliveryWorker {
  const { config, storage } = options
  const locator = options.locator ?? new DidServiceLocator()
  const locateOptions = options.locateOptions ?? config.didResolution
  const log = options.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  const now = options.now ?? ((): Date => new Date())
  const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS
  const baseBackoffMs = options.baseBackoffMs ?? DEFAULT_BASE_BACKOFF_MS
  const maxBackoffMs = options.maxBackoffMs ?? DEFAULT_MAX_BACKOFF_MS
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS
  const random = options.random ?? Math.random

  /** 本服务自己的入口地址。收件人指的是它，就等于消息已经在本机躺着了。
   *  这个判断只有一处（`http/server.ts` 的 `isOurOwnIngress`）——C11 的请求路径也要用它
   *  决定"本地办完还是转出去"，两处各写一遍就是将来只改了一边。 */
  const isOwn = (endpoint: string): boolean => isOurOwnIngress(config, endpoint)

  /** 第 `attempts` 次失败之后的等待时长（`attempts` 从 1 起）。 */
  function backoffMs(attempts: number): number {
    const capped = Math.min(baseBackoffMs * 2 ** (attempts - 1), maxBackoffMs)
    // 抖动在下半段（50%–100%）：全抖动会让等待趋近于 0，等于没有退避，而在同一个
    // tick 里一起失败的那批条目需要一个能错开的量。
    return Math.round(capped * (0.5 + random() * 0.5))
  }

  async function deliver(entry: OutboxEntry): Promise<void> {
    const at = now()
    try {
      const target = await discoverMessageService(entry.recipientDid, { locator, ...locateOptions })
      if (isOwn(target.endpoint)) {
        storage.dropOutbox(entry.seq)
        return
      }
      await postNotification(
        target.endpoint,
        JSON.parse(entry.payloadJson) as AnpNotification,
        locateOptions,
      )
      storage.dropOutbox(entry.seq)
    } catch (err) {
      const attempts = entry.attempts + 1
      const reason = describe(err)
      if (attempts >= maxAttempts) {
        // 丢弃是**有意的放弃**，不是成功：收件人可能永远不会知道这条消息存在。日志里
        // 说清楚次数与最后的错误，运维才有得查。
        log(`anp: outbound push to ${entry.recipientDid} dropped after ${attempts} attempts: ${reason}`)
        storage.dropOutbox(entry.seq)
        return
      }
      storage.rescheduleOutbox(entry.seq, attempts, new Date(at.getTime() + backoffMs(attempts)).toISOString(), reason)
      log(`anp: outbound push to ${entry.recipientDid} failed (attempt ${attempts}): ${reason}`)
    }
  }

  async function runOnce(): Promise<void> {
    let due: OutboxEntry[]
    try {
      due = storage.dueOutbox(now().toISOString(), batchSize)
    } catch (err) {
      log(`anp: delivery worker could not read the outbox: ${describe(err)}`)
      return
    }
    // 逐条串行：一次 tick 里并发几十个出站请求只是把对端的限流一次撞满。
    for (const entry of due) await deliver(entry)
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
      // 走到这里说明存储本身坏了（写盘满、库被锁）。记一笔，循环继续——一个后台轮询
      // 因为一次 I/O 失败就永久停下，是比那次失败更坏的事。
      log(`anp: delivery worker tick failed: ${describe(err)}`)
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
