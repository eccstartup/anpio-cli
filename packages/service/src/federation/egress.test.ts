import { describe, expect, it } from 'vitest'
import {
  buildMessageNotification,
  buildMessageRequest,
  ConnectxError,
  createAnpIdentity,
  DidKeyResolver,
  verifyHttpSignatureForServer,
  type AnpRequest,
  type LocateOptions,
} from '@anpio-cli/core'
import { buildContentDigestValue, utf8 } from '@anpio-cli/core/advanced'
import { loadConfig } from '../config'
import { createHttpSigner, type HttpSigner } from './signing'
import { createEgress } from './egress'

// P8 §2.4 的那句话是这一份用例的全部内容：**非 2xx 不是异常，是答复**。所以每个用例都
// 让对端真的回一个状态码，断言它从 `post` 里原样出来，而不是被抛掉。

const PEER_DID = 'did:wba:peer.example:user:bob:e1_xyz'
const ENDPOINT = 'https://peer.example/anp-im/rpc'
/** 签名覆盖 `@method` / `@target-uri`，所以对端地址是这份用例里的一条真值。 */
const identity = createAnpIdentity('sender.example')

const meta = {
  profile: 'anp.direct.base.v1',
  security_profile: 'transport-protected',
  sender_did: 'did:wba:sender.example:user:alice:e1_abc',
  target: { kind: 'agent' as const, did: PEER_DID },
  operation_id: 'op-1',
  message_id: 'msg-1',
  content_type: 'text/plain',
}

const NOTIFICATION = buildMessageNotification({ method: 'direct.incoming', meta, body: { text: 'hello' } })
const REQUEST: AnpRequest = buildMessageRequest({ id: 'req-1', method: 'direct.send', meta, body: { text: 'hello' } })

/** 与 `delivery/worker.test.ts` 同一套：白名单与解析地址两道闸照跑，只有连接本身交给
 *  假 transport。出站与解析文档走的是同一条路，这里就不该另开一条。 */
function policy(handler: (url: string, init: RequestInit) => Promise<Response>): LocateOptions {
  return {
    allowedHosts: ['peer.example'],
    resolveAddresses: async () => ['93.184.216.34'],
    fetch: handler,
    allowUncontrolledFetch: true,
  }
}

interface Sent {
  url: string
  init: RequestInit
  /** `init.headers` 是按字面收的普通对象，取出来就是上线的头。 */
  headers: Record<string, string>
  body: string
}

interface Harness {
  egress: ReturnType<typeof createEgress>
  /** 每一次真的发出去的请求。 */
  sent: Sent[]
}

function harness(
  reply: (sent: Sent) => Response | Promise<Response>,
  signer?: HttpSigner,
): Harness {
  const sent: Sent[] = []
  const egress = createEgress({
    config: loadConfig({}),
    ...(signer !== undefined ? { signer } : {}),
    locateOptions: policy(async (url, init) => {
      const record: Sent = {
        url,
        init,
        headers: (init.headers ?? {}) as Record<string, string>,
        body: typeof init.body === 'string' ? init.body : '',
      }
      sent.push(record)
      return reply(record)
    }),
    // nonce 钉住。**不钉 `created`**：签名的有效期是相对真实施刻判的，把时钟按到过去
    // 只会让 `verifyHttpSignatureForServer` 判成 `invalid_timestamp`，验的就成了另一件事。
    nonce: () => 'nonce-1',
  })
  return { egress, sent }
}

function json(status: number, body: string, headers: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json', ...headers } })
}

describe('createEgress', () => {
  it('posts the envelope to the endpoint and hands back a 2xx answer', async () => {
    const h = harness(() => json(200, JSON.stringify({ jsonrpc: '2.0', id: 'req-1', result: { status: 'accepted' } })))
    const answer = await h.egress.post(ENDPOINT, REQUEST)

    expect(h.sent[0]?.url).toBe(ENDPOINT)
    expect(h.sent[0]?.init.method).toBe('POST')
    expect(h.sent[0]?.headers['content-type']).toBe('application/json')
    // 发出去的必须**就是**信里那一份：序列化一次，签名覆盖它，然后原样发走。
    expect(h.sent[0]?.body).toBe(JSON.stringify(REQUEST))
    expect(answer.status).toBe(200)
    expect(answer.body).toEqual({ jsonrpc: '2.0', id: 'req-1', result: { status: 'accepted' } })
  })

  it('reads a 401 as an answer instead of throwing it away', async () => {
    // 这一条是 §2.4 本身：ANP-02 §3.2.4.1 把外层认证的失败放在状态和挑战头上，
    // 被拒是**跑通了的交换**。core 的 `postMessage` 在这里会抛，所以不能走它。
    const h = harness(() =>
      json(401, JSON.stringify({ code: 401, error: 'invalid_nonce' }), {
        'www-authenticate': 'DIDWba realm="peer.example", error="invalid_nonce"',
      }),
    )
    const answer = await h.egress.post(ENDPOINT, REQUEST)

    expect(answer.status).toBe(401)
    expect(answer.body).toEqual({ code: 401, error: 'invalid_nonce' })
    // 挑战头是 401 上唯一有内容的部分，丢在路上的话调用方就只剩一个数字。
    expect(answer.headers['www-authenticate']).toContain('error="invalid_nonce"')
  })

  it('reads a 503 the same way, since a retry is a decision the caller makes', async () => {
    const h = harness(() => new Response('', { status: 503 }))
    const answer = await h.egress.post(ENDPOINT, REQUEST)

    expect(answer.status).toBe(503)
    expect(answer.body).toBeUndefined()
  })

  it('treats an empty or unreadable body as no body rather than as a failure', async () => {
    // §5.6 L199/L204：通知的答复不必是 JSON，200 带空 body 是合规的一种。
    const empty = harness(() => new Response('', { status: 200 }))
    expect((await empty.egress.post(ENDPOINT, NOTIFICATION)).body).toBeUndefined()

    const html = harness(() => new Response('<html>nope</html>', { status: 200 }))
    expect((await html.egress.post(ENDPOINT, NOTIFICATION)).body).toBeUndefined()
  })

  it('sends nothing that claims an outer identity when the deployment has no key', async () => {
    // §2.3：不带外层身份的调用方失去的是域级归属，不是受理资格，所以这不是错误形态。
    const h = harness(() => json(200, '{}'))
    await h.egress.post(ENDPOINT, REQUEST)
    const headers = h.sent[0]?.headers ?? {}
    expect(headers.signature).toBeUndefined()
    expect(headers['signature-input']).toBeUndefined()
    // 摘要只作为被签名的组件才有意义，单独发一份什么也不证明。
    expect(headers['content-digest']).toBeUndefined()
  })

  it('signs for the bytes it actually sends, which is what the peer verifies', async () => {
    // 这里不复述 `signing.test.ts` 的九个形态，只钉住出站这一层的那个风险：
    // 签的和发的是不是同一份。对端是拿收到的字节验的。
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const h = harness(() => json(200, '{}'), signer)
    await h.egress.post(ENDPOINT, REQUEST)

    const { headers, body } = h.sent[0]!
    // 摘要覆盖的正是上线的那串字节。
    expect(headers['content-digest']).toBe(await buildContentDigestValue(utf8(body)))
    expect(headers['signature-input']).toContain(identity.keyid)

    const url = new URL(ENDPOINT)
    const key = await new DidKeyResolver().resolve(identity.did, identity.keyid, {
      didDocument: identity.didDocument,
    })
    const outcome = await verifyHttpSignatureForServer({
      method: 'POST',
      path: url.pathname,
      authority: url.host,
      targetUri: url.href,
      search: url.search,
      headers,
      body,
      key,
    })
    expect(outcome).toEqual({ ok: true })
  })

  it('lets a network failure stay a failure', async () => {
    // 这一条与上面几条的分界就是 §2.4 的分界：对端**回了**才是答复。连不上不是。
    const h = harness(() => {
      throw new Error('ECONNREFUSED')
    })
    const error = await h.egress.post(ENDPOINT, REQUEST).catch((err: unknown) => err)

    expect(error).toBeInstanceOf(ConnectxError)
    expect((error as ConnectxError).code).toBe('message_send_failed')
  })
})
