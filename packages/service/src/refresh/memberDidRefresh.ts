// A3c-4 —— §8.12 的第三条触发路：**定时刷新**。
//
// 这个文件只是一个钟。所有判定都在 `rpc/memberDidUpdate.ts` 的 `refreshMemberDids` 里，与请求
// 触发、投递触发共用同一段受理前验证；这里负责的是"什么时候问一次"和"上一轮没跑完怎么办"。
//
// ## 为什么单开一个 worker 而不是挂在 deviceQueue 上
//
// 它的节奏与投递队列差四个数量级：投递一轮一秒，刷新一轮六小时（`Config.memberDidRefresh`）。
// 挂在一起要么把刷新拖成每秒一次（那正是用户 2026-10-02 说的"不要太多负载"要避免的），要么
// 给投递队列加一个"这一秒要不要顺便刷新"的分支。分开之后两边的失败也互不牵连——一次 DID 服务
// 器不可达不该影响任何一封正在投递的信封。
//
// ## 两条与别处一致、但在这里更重要的性质
//
//   - **一轮的解析次数有上限**（`batch`），且由 `groupMembersDueForDidCheck` 的排序保证轮转，
//     没有成员会被饿着。见 `refreshMemberDids` 的注释。
//   - **单行的失败不中断这一轮**。刷新是兜底，不是关键路径；一行解析不出来不该让这一轮剩下的
//     行等到下一个周期（六小时之后）。`refreshMemberDids` 逐行串行、单行内部吞掉异常，所以这里
//     只需要接住"整批都读不出来"那种（比如库被关了）。
//
// 进程退出时不做什么收尾：一轮要么跑完、要么被中断，而戳记是逐行盖的——下一轮从没盖到的那行
// 接着走，不需要"半轮"这个状态。

import type { Config } from '../config'
import { refreshMemberDids, type DidChainResolver } from '../rpc/memberDidUpdate'
import type { Storage } from '../storage/types'

export interface MemberDidRefreshOptions {
  config: Config
  storage: Storage
  /** 测试注入点，见 `rpc/memberDidUpdate.ts` 的 `DidChainResolver`：让测试不必上网。 */
  chainResolver?: DidChainResolver
  log?: (line: string) => void
  now?: () => Date
  /** 覆盖 `Config.memberDidRefresh`，只给测试用——两个数值是部署档位。 */
  intervalMs?: number
  batch?: number
}

export interface MemberDidRefreshWorker {
  /** 跑一轮。返回这一轮看过的行数，让调用方（与测试）能判断批次取满了没有。 */
  runOnce(): Promise<number>
  start(): void
  stop(): void
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export function createMemberDidRefreshWorker(
  options: MemberDidRefreshOptions,
): MemberDidRefreshWorker {
  const { config, storage } = options
  const log = options.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  const now = options.now ?? ((): Date => new Date())
  const intervalMs = options.intervalMs ?? config.memberDidRefresh.intervalMs
  const batch = options.batch ?? config.memberDidRefresh.batch

  async function runOnce(): Promise<number> {
    const at = now().toISOString()
    try {
      return await refreshMemberDids({
        storage,
        config,
        at,
        batch,
        // 与"多久轮一遍"是同一个数：一行在这个间隔内刚被看过（无论是被上一轮刷新、还是一次
        // 投递或请求顺手看的）就不必再看。于是这个值同时是**每个成员的最短复查周期**。
        staleAfterMs: intervalMs,
        ...(options.chainResolver !== undefined ? { resolveChain: options.chainResolver } : {}),
        log,
      })
    } catch (err) {
      // 读不出这一批（库关了、语句坏了）。记一笔，等下一个周期——刷新不是关键路径，立刻重试
      // 只是把同一个错误再打一遍。
      log(`anp: DID refresh could not read a batch of members: ${describe(err)}`)
      return 0
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
      // `runOnce` 自己不抛，所以走到这里只可能是它之外的事（比如日志回调）。仍然不能让它成为
      // 未处理的拒绝，否则整个进程会带着一个静默死掉的钟继续跑。
      log(`anp: DID refresh tick failed: ${describe(err)}`)
    } finally {
      if (!stopped) schedule()
    }
  }

  return {
    runOnce,
    start(): void {
      if (timer !== undefined || stopped) return
      // 启动时**不**立刻跑一轮：这一轮的结果要等 6 小时才有下一次，而刚启动的进程正在忙着
      // 打开端口、装订阅——把几十次 DID 解析压在这个时刻没有好处。第一个周期之后再说。
      schedule()
    },
    stop(): void {
      stopped = true
      if (timer !== undefined) clearTimeout(timer)
      timer = undefined
    },
  }
}
