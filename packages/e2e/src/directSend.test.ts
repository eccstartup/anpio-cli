// TODO2 的 B2：把 P4/P5/P6 从"方法级测过"推进到"端到端跑过"。
//
// 这一条路是：`connectx msg send` → 真服务 → `connectx msg inbox` / `msg listen`。
// 两端跑的都是各自仓库里的真代码，中间是真 HTTP、真签名、真 DID 解析，只有"DID 文档谁托管"
// 是替身（见 `harness.ts` 的文件头）。
//
// 每一条用例自带一对身份。共用一对会串味：`msg listen` 不带游标就是从 0 开始，上一条用例
// 留下的消息会作为历史在 backfill 里重放——那既不是失败也不是成功，是一条关于"用例之间
// 谁先跑"的断言。分开之后每条用例的状态只属于它自己。

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { runMsg } from '../../cli/src/commands/msg'
import { runListen } from '../../cli/src/commands/listen'
import { isMessage, type ListenEvent, type ListenView } from '../../cli/src/commands/listen-view'
import { captureStdout, startWorld, until, type Agent, type World } from './harness'

let world: World

beforeAll(async () => {
  world = await startWorld()
})

afterAll(async () => {
  await world?.stop()
})

/** 只看消息、并按到达顺序把正文记下来的一双眼睛。 */
function collector(): { view: ListenView; messages: string[]; events: ListenEvent[]; connected: () => boolean } {
  const messages: string[] = []
  const events: ListenEvent[] = []
  let connected = false
  return {
    messages,
    events,
    connected: () => connected,
    view: {
      event(event) {
        events.push(event)
        // `ListenEvent` 是个联合：`state` 只在非消息那几支上，收窄一下才读得到。
        if (!isMessage(event) && event.state === 'connected') connected = true
        if (isMessage(event) && event.text !== undefined) messages.push(event.text)
      },
    },
  }
}

describe('connectx → AgentXAgent → connectx', () => {
  it('carries a direct message from one identity to another', async () => {
    const alice = await world.createAgent('alice')
    const bob = await world.createAgent('bob')

    const send = await captureStdout(() =>
      runMsg({ ...alice.values, to: bob.did, text: 'hello bob' }, 'send', []),
    )

    // 收据是这条命令的对外契约：受理编号与受理时刻都印在这里。
    expect(send.out).toContain('accepted at:')
    expect(send.out).toContain(bob.did)

    const inbox = await captureStdout(() => runMsg({ ...bob.values, json: true }, 'inbox', []))
    const page = JSON.parse(inbox.out) as { messages: Array<Record<string, unknown>> }
    expect(page.messages).toHaveLength(1)
    expect(page.messages[0]!.sender_did).toBe(alice.did)
    expect(page.messages[0]!.body).toEqual({ text: 'hello bob' })
  })
})

// realtime.md §5.2：连上之后先补历史，再转实时。补历史这一段在 `--once` 下有个确定的收束
// （补完就结束，不转实时），所以它不需要中断线，也不需要等。
describe('msg listen backfill over a real WebSocket', () => {
  it('replays what was waiting before the listener ever connected', async () => {
    const erin = await world.createAgent('erin')
    const frank = await world.createAgent('frank')

    await captureStdout(() => runMsg({ ...erin.values, to: frank.did, text: 'first' }, 'send', []))
    await captureStdout(() => runMsg({ ...erin.values, to: frank.did, text: 'second' }, 'send', []))

    const eye = collector()
    await runListen({ ...frank.values, once: true }, { view: eye.view })

    expect(eye.messages).toEqual(['first', 'second'])
    expect(eye.events.some((event) => !isMessage(event) && event.state === 'connected')).toBe(true)
  })
})

// 推送这一段（realtime.md §5）在今天只有 `listen.test.ts` 的注入式传输测过——真 socket
// 从没插上过。这一段补的就是那一截。
describe('msg listen push over a real WebSocket', () => {
  it('pushes a message that is sent while it is connected', async () => {
    const carol = await world.createAgent('carol')
    const dave = await world.createAgent('dave')

    const eye = collector()
    // 一条已经拿在手里、由测试按下的中断线：真进程靠 SIGINT 退出，而测试里发信号是发给
    // 测试运行器自己的（`listen.ts` 的 `ListenDeps.signal` 就是为这件事留的）。
    const interrupt = new AbortController()
    const listening = runListen({ ...carol.values }, { view: eye.view, signal: interrupt.signal })
    listening.catch(() => {
      /* 中断不是失败；断言看的是 eye.messages。收尾时统一吞掉。 */
    })

    try {
      // 先等订阅真的立起来再发。反过来的话这条用例会变成关于时序的猜测：推送给的是一个
      // 还没连上的设备，那条消息就只能靠 backfill 补——测的就不是推这条路了。
      await until(eye.connected, 'the listener to finish its handshake')

      await captureStdout(() => runMsg({ ...dave.values, to: carol.did, text: 'live push' }, 'send', []))

      await until(() => eye.messages.length > 0, 'the pushed message to arrive')
      expect(eye.messages).toEqual(['live push'])
    } finally {
      interrupt.abort()
      await listening
    }
  })
})
