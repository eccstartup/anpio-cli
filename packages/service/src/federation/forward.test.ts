import { describe, expect, it } from 'vitest'
import {
  buildMessageRequest,
  type AnpRequest,
  type ServiceEntry,
  type ServiceLocator,
} from '@anpio-cli/core'
import { loadConfig } from '../config'
import type { Egress, EgressAnswer } from './egress'
import { createRelay } from './forward'

// 这一层要证明的只有一件事：**对端说的和它没说清的，走的是两条不同的路**（P8 §2.4）。
// 对端自己的错误对象原样穿过（§6.7 L464 要 `current_did` 回到原始调用方），而"这一趟
// 根本没走通"是我们自己的观察，只能说成 1012，不能伪装成对端的答复。

const PEER_DID = 'did:wba:peer.example:user:bob:e1_xyz'
const PEER_ENDPOINT = 'https://peer.example/anp-im/rpc'

const REQUEST: AnpRequest = buildMessageRequest({
  id: 'req-1',
  method: 'direct.send',
  meta: {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: 'did:wba:sender.example:user:alice:e1_abc',
    target: { kind: 'agent', did: PEER_DID },
    operation_id: 'op-1',
    message_id: 'msg-1',
    content_type: 'text/plain',
  },
  body: { text: 'hello' },
})

/** 只在被调用时失败：`{kind:'local'}` 那条路一个字节都不该发出去，而"没被调用"与
 *  "被调用后返回空"在断言里是两件事。 */
function spyEgress(answer?: EgressAnswer | Error): { egress: Egress; calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    egress: {
      async post(endpoint: string): Promise<EgressAnswer> {
        calls.push(endpoint)
        if (answer instanceof Error) throw answer
        return answer ?? { status: 200, headers: {}, body: undefined }
      },
    },
  }
}

function locatorOf(entries: ServiceEntry[] | Error): ServiceLocator {
  return {
    async locate(): Promise<ServiceEntry[]> {
      if (entries instanceof Error) throw entries
      return entries
    },
  }
}

const PEER_ENTRY: ServiceEntry = {
  id: '#anp-message-service',
  type: 'ANPMessageService',
  serviceEndpoint: PEER_ENDPOINT,
}

function relay(egress: Egress, entries: ServiceEntry[] | Error) {
  return createRelay({
    config: loadConfig({}),
    egress,
    locator: locatorOf(entries),
    log: () => undefined,
  })
}

function answer(status: number, body: string): EgressAnswer {
  return { status, headers: {}, body: JSON.parse(body) as unknown }
}

describe('createRelay', () => {
  it('keeps a call for our own ingress local, without sending anything (§3.3)', async () => {
    // 本机联调时收件人就住在这里，判断必须是"解析出来的端点是不是我"，而不是"两个 DID
    // 看起来像不像同一个域"——后者我们无从权威得知。
    const config = loadConfig({})
    const { egress, calls } = spyEgress()
    const r = relay(egress, [{ ...PEER_ENTRY, serviceEndpoint: `${config.publicUrl}/anp-im/rpc` }])

    expect(await r.forward(REQUEST, PEER_DID)).toEqual({ kind: 'local' })
    expect(calls).toEqual([])
  })

  it('hands back the peer result verbatim when it accepts', async () => {
    const { egress, calls } = spyEgress(
      answer(200, JSON.stringify({ jsonrpc: '2.0', id: 'p-1', result: { accepted: true, message_id: 'm-9' } })),
    )
    const outcome = await relay(egress, [PEER_ENTRY]).forward(REQUEST, PEER_DID)

    expect(calls).toEqual([PEER_ENDPOINT])
    // §3.2 说"翻回给调用方"：不是我们重新拼一份等价的，就是它那一份。
    expect(outcome).toEqual({ kind: 'answered', result: { accepted: true, message_id: 'm-9' } })
  })

  it('passes the peer own rejection through, keeping what the caller needs to retry', async () => {
    // §6.7 L464 是 MTI 第 14 项：`anp.did_superseded` 必须**原样**回到原始调用方，因为
    // 重建请求要私钥，而私钥在 agent 手里。翻译一下就丢掉 `current_did`。
    const { egress } = spyEgress(
      answer(
        200,
        JSON.stringify({
          jsonrpc: '2.0',
          id: 'p-1',
          error: {
            code: 1019,
            message: 'the DID was superseded',
            data: { anp_code: 'anp.did_superseded', retryable: true, details: { current_did: 'did:wba:new' } },
          },
        }),
      ),
    )
    const outcome = await relay(egress, [PEER_ENTRY]).forward(REQUEST, PEER_DID)

    expect(outcome).toEqual({
      kind: 'refused',
      rejection: {
        code: 1019,
        anpCode: 'anp.did_superseded',
        retryable: true,
        message: 'the DID was superseded',
        details: { current_did: 'did:wba:new' },
      },
    })
  })

  it('does not dress an HTTP refusal up as the peer position (§2.4 + §6.6)', async () => {
    // 401 说的是"我不收这一次"。它不是 `direct.send` 的结果，所以不能当成 `result` 返回
    // ——那正是一种静默降级。状态写进 details，日志里记全。
    const { egress } = spyEgress({ status: 401, headers: {}, body: { code: 401, error: 'invalid_signature' } })
    const outcome = await relay(egress, [PEER_ENTRY]).forward(REQUEST, PEER_DID)

    expect(outcome.kind).toBe('refused')
    expect(outcome).toMatchObject({
      rejection: { code: 1012, anpCode: 'anp.temporarily_unavailable', retryable: true, details: { status: 401 } },
    })
  })

  it('tells a transport failure apart from an answer', async () => {
    // §2.4 分的就是这两件事：对端**回了**才是答复。连不上是我们的观察，没有对端的错误
    // 对象可以保留。
    const { egress } = spyEgress(new Error('ECONNREFUSED'))
    const outcome = await relay(egress, [PEER_ENTRY]).forward(REQUEST, PEER_DID)

    expect(outcome).toMatchObject({ kind: 'refused', rejection: { code: 1012, retryable: true } })
  })

  it('refuses when the target has no reachable service, rather than guessing one', async () => {
    // §7.5 L495 明令不得按域名猜 Host；这里连猜的机会都没有——解析不出来就是失败。
    const { egress, calls } = spyEgress()
    const outcome = await relay(egress, []).forward(REQUEST, PEER_DID)

    expect(calls).toEqual([])
    expect(outcome).toMatchObject({ kind: 'refused', rejection: { code: 1012, retryable: true } })
  })

  it('refuses a 200 that is not a JSON-RPC response', async () => {
    const { egress } = spyEgress({ status: 200, headers: {}, body: undefined })
    const outcome = await relay(egress, [PEER_ENTRY]).forward(REQUEST, PEER_DID)

    expect(outcome).toMatchObject({ kind: 'refused', rejection: { code: 1012 } })
  })

  it('refuses a service entry whose endpoint is not a URL, instead of calling it a bug of ours', async () => {
    // 写坏的是**对端**的文档。让它冒到最外面就会变成 -32603（"本服务内部错误"），
    // 而重试其实是对的——所以这一档要说成 1012。
    const { egress, calls } = spyEgress()
    const outcome = await relay(egress, [{ ...PEER_ENTRY, serviceEndpoint: 'not a url' }]).forward(REQUEST, PEER_DID)

    expect(calls).toEqual([])
    expect(outcome).toMatchObject({ kind: 'refused', rejection: { code: 1012, retryable: true } })
  })
})
