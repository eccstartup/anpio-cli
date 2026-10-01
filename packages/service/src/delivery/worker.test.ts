import { describe, expect, it } from 'vitest'
import {
  buildMessageNotification,
  ConnectxError,
  type AnpNotification,
  type LocateOptions,
  type ServiceEntry,
  type ServiceLocator,
} from '@agentx/core'
import { loadConfig } from '../config'
import { openStorage } from '../storage/sqlite'
import { SCHEMA_VERSION } from '../storage/schema'
import { createDeliveryWorker } from './worker'
import type { Storage } from '../storage/types'

const RECIPIENT = 'did:wba:peer.example:user:bob:e1_xyz'
const ENDPOINT = 'https://peer.example/anp-im/rpc'
/** One instant per tick, so `nextAttemptAt` after a backoff is a literal. */
const NOW = new Date('2026-10-01T12:00:00Z')

const NOTIFICATION = buildMessageNotification({
  method: 'direct.incoming',
  meta: {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: 'did:wba:sender.example:user:alice:e1_abc',
    target: { kind: 'agent', did: RECIPIENT },
    operation_id: 'op-1',
    message_id: 'msg-1',
    content_type: 'text/plain',
  },
  body: { text: 'hello' },
})

/** A locator that answers from a table, so the worker's real `discoverMessageService`
 *  rule ("exactly one ANPMessageService") still runs. */
function locatorOf(entries: ServiceEntry[] | Error): ServiceLocator {
  return {
    async locate(): Promise<ServiceEntry[]> {
      if (entries instanceof Error) throw entries
      return entries
    },
  }
}

const PEER: ServiceEntry = {
  id: '#anp-message-service',
  type: 'ANPMessageService',
  serviceEndpoint: ENDPOINT,
}

/** Options that let a fake transport stand in for the network while the allowlist and
 *  resolved-address gates still run for real — the push goes out under the same policy
 *  a DID fetch does. */
function policy(handler: (url: string, init: RequestInit) => Promise<Response>, extra: LocateOptions = {}): LocateOptions {
  return {
    allowedHosts: ['peer.example'],
    resolveAddresses: async () => ['93.184.216.34'],
    fetch: handler,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

interface Harness {
  storage: Storage
  logs: string[]
  worker: ReturnType<typeof createDeliveryWorker>
  /** Deliveries the caller queued, ready to be pushed. */
  queue(recipientDid?: string, payload?: AnpNotification): void
  /** Move the worker's clock. A fixed instant per step keeps `nextAttemptAt` a literal
   *  and lets a retry be reached without sleeping through the real backoff. */
  at(ms: number): void
  /** The instant the worker is currently pinned to. */
  clock(): number
}

function harness(
  overrides: {
    locator?: ServiceLocator
    locateOptions?: LocateOptions
    maxAttempts?: number
    random?: () => number
    batchSize?: number
    intervalMs?: number
  } = {},
): Harness {
  const storage = openStorage({ path: ':memory:' })
  const logs: string[] = []
  let clock = NOW.getTime()
  const worker = createDeliveryWorker({
    config: loadConfig({}),
    storage,
    locator: overrides.locator ?? locatorOf([PEER]),
    locateOptions: overrides.locateOptions ?? policy(async () => new Response('', { status: 200 })),
    log: (line) => logs.push(line),
    now: () => new Date(clock),
    maxAttempts: overrides.maxAttempts ?? 3,
    baseBackoffMs: 1000,
    maxBackoffMs: 60_000,
    random: overrides.random ?? (() => 0),
    ...(overrides.batchSize !== undefined ? { batchSize: overrides.batchSize } : {}),
    ...(overrides.intervalMs !== undefined ? { intervalMs: overrides.intervalMs } : {}),
  })
  return {
    storage,
    logs,
    worker,
    queue(recipientDid = RECIPIENT, payload = NOTIFICATION): void {
      storage.enqueueOutbox({
        recipientDid,
        payloadJson: JSON.stringify(payload),
        nextAttemptAt: NOW.toISOString(),
      })
    },
    at(ms: number): void {
      clock = ms
    },
    clock(): number {
      return clock
    },
  }
}

describe('delivering direct.incoming', () => {
  it('POSTs the queued notification to the recipient endpoint and clears the row', async () => {
    let seen: { url: string; init: RequestInit } | undefined
    const h = harness({
      locateOptions: policy(async (url, init) => {
        seen = { url, init }
        return new Response('', { status: 200 })
      }),
    })
    h.queue()

    await h.worker.runOnce()

    expect(seen?.url).toBe(ENDPOINT)
    expect(seen?.init.method).toBe('POST')
    expect(JSON.parse(String(seen?.init.body))).toEqual(NOTIFICATION)
    expect(h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)).toEqual([])
  })

  it('treats our own ingress as local, leaving the delivery row for the stream to serve', async () => {
    // The endpoint the recipient's document names IS this service. The delivery row is
    // already durable and C7 hands it out, so a loopback HTTP request would be a detour
    // that also demands the operator allowlist their own public address.
    let called = false
    const own = loadConfig({})
    const h = harness({
      locator: locatorOf([{ ...PEER, serviceEndpoint: `${own.publicUrl}/anp-im/rpc/` }]),
      locateOptions: policy(async () => {
        called = true
        return new Response('', { status: 200 })
      }),
    })
    h.storage.appendDelivery({
      ownerDid: RECIPIENT,
      messageId: 'msg-1',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: NOW.toISOString(),
    })
    h.queue()

    await h.worker.runOnce()

    expect(called).toBe(false)
    expect(h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)).toEqual([])
    expect(h.storage.headSeq(RECIPIENT)).toBe(1)
  })

  it('reschedules with a growing backoff when the push fails', async () => {
    const h = harness({
      locateOptions: policy(async () => new Response('', { status: 503 })),
      random: () => 0,
    })
    h.queue()

    await h.worker.runOnce()

    const [entry] = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
    expect(entry?.attempts).toBe(1)
    expect(entry?.lastError).toContain('503')
    // Full jitter is not used: `random: () => 0` still waits half the window, so the
    // delay never collapses to zero.
    expect(entry?.nextAttemptAt).toBe(new Date(NOW.getTime() + 500).toISOString())
    // Nothing is due at the time it just failed.
    expect(h.storage.dueOutbox(NOW.toISOString(), 10)).toHaveLength(0)
    expect(h.logs.join('\n')).toContain('attempt 1')
  })

  it('doubles the wait on each subsequent attempt', async () => {
    const h = harness({
      locateOptions: policy(async () => new Response('', { status: 503 })),
      maxAttempts: 10,
      random: () => 1, // the top of the jitter window, so the base is readable
    })
    h.queue()

    const delays: number[] = []
    for (let i = 0; i < 3; i++) {
      await h.worker.runOnce()
      const [entry] = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
      const at = new Date(entry?.nextAttemptAt ?? '').getTime()
      delays.push(at - h.clock())
      h.at(at)
    }
    expect(delays).toEqual([1000, 2000, 4000])
  })

  it('gives up after maxAttempts instead of retrying forever', async () => {
    const h = harness({
      locateOptions: policy(async () => {
        throw new ConnectxError('message_send_failed', 'connection refused')
      }),
      maxAttempts: 2,
    })
    h.queue()

    await h.worker.runOnce()
    // Reach the retry by moving the clock to it, not by sleeping through the real wait.
    const [pending] = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
    h.at(new Date(pending?.nextAttemptAt ?? '').getTime())
    await h.worker.runOnce()

    expect(h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)).toEqual([])
    expect(h.logs.join('\n')).toContain('dropped after 2 attempts')
    expect(h.logs.join('\n')).toContain('connection refused')
  })

  it('keeps the payload across retries, so a late attempt sends the original notification', async () => {
    const bodies: string[] = []
    let up = false
    const h = harness({
      locateOptions: policy(async (_url, init) => {
        if (!up) throw new ConnectxError('message_send_failed', 'not yet')
        bodies.push(String(init.body))
        return new Response('', { status: 200 })
      }),
    })
    h.queue()

    await h.worker.runOnce()
    up = true
    const [pending] = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
    h.at(new Date(pending?.nextAttemptAt ?? '').getTime())
    await h.worker.runOnce()

    expect(bodies).toHaveLength(1)
    expect(JSON.parse(bodies[0] ?? '{}')).toEqual(NOTIFICATION)
    // The same `message_id` / `operation_id` as the first attempt — §8.4 L471–477 relies
    // on that for the recipient's duplicate recognition.
    expect(JSON.parse(bodies[0] ?? '{}').params.meta.message_id).toBe('msg-1')
  })

  it('reports a recipient with no ANPMessageService rather than inventing an endpoint', async () => {
    const h = harness({ locator: locatorOf([{ ...PEER, type: 'SomethingElse' }]) })
    h.queue()

    await h.worker.runOnce()

    const [entry] = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
    expect(entry?.attempts).toBe(1)
    expect(entry?.lastError).toContain('ANPMessageService')
  })

  it('reports an unusable endpoint from the peer document', async () => {
    const h = harness({ locator: locatorOf([{ ...PEER, serviceEndpoint: 'not a url' }]) })
    h.queue()

    await h.worker.runOnce()

    expect(h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)[0]?.lastError).toContain('serviceEndpoint')
  })

  it('does not let one recipient failure stop the others', async () => {
    const sent: string[] = []
    const h = harness({
      locator: locatorOf([PEER]),
      locateOptions: policy(async (_url, init) => {
        const body = JSON.parse(String(init.body)) as AnpNotification
        const who = String(body.params.meta.target?.did)
        if (who === RECIPIENT) throw new ConnectxError('message_send_failed', 'refused')
        sent.push(who)
        return new Response('', { status: 200 })
      }),
    })
    const other = 'did:wba:peer.example:user:carol:e1_def'
    h.queue()
    h.queue(other, buildMessageNotification({
      method: 'direct.incoming',
      meta: { ...NOTIFICATION.params.meta, target: { kind: 'agent', did: other }, message_id: 'msg-2' },
      body: { text: 'second' },
    }))

    await h.worker.runOnce()

    expect(sent).toEqual([other])
    const left = h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)
    expect(left).toHaveLength(1)
    expect(left[0]?.recipientDid).toBe(RECIPIENT)
  })

  it('does not start again once it has been stopped', async () => {
    // `stop()` runs on the shutdown path and `start()` is idempotent, so the guard that
    // matters is that a stopped worker stays stopped: a timer resurrected after
    // `storage.close()` would throw on every tick of a loop nobody is watching.
    const sent: string[] = []
    const h = harness({
      intervalMs: 5,
      locateOptions: policy(async (_url, init) => {
        sent.push(String((JSON.parse(String(init.body)) as AnpNotification).params.meta.message_id))
        return new Response('', { status: 200 })
      }),
    })
    h.queue()
    h.worker.stop()
    h.worker.start()
    await new Promise((resolve) => setTimeout(resolve, 30))
    // A live timer would have had several ticks in this window, and there is something
    // for it to push.
    expect(sent).toEqual([])
  })

  it('polls on its own until it is stopped', async () => {
    const sent: string[] = []
    const h = harness({
      intervalMs: 5,
      locateOptions: policy(async (_url, init) => {
        sent.push(String((JSON.parse(String(init.body)) as AnpNotification).params.meta.message_id))
        return new Response('', { status: 200 })
      }),
    })
    h.queue()

    h.worker.start()
    await waitFor(() => sent.length > 0)
    h.worker.stop()
    // A tick already in flight finishes after `stop()` returns, so let it settle before
    // taking the reading that must not change.
    await new Promise((resolve) => setTimeout(resolve, 30))
    const settled = sent.length
    await new Promise((resolve) => setTimeout(resolve, 30))
    expect(sent.length).toBe(settled)
  })

  it('bounds the page it works on in one tick', async () => {
    const sent: string[] = []
    const h = harness({
      batchSize: 2,
      locateOptions: policy(async (_url, init) => {
        sent.push(String((JSON.parse(String(init.body)) as AnpNotification).params.meta.message_id))
        return new Response('', { status: 200 })
      }),
    })
    for (let i = 0; i < 3; i++) {
      h.queue(RECIPIENT, buildMessageNotification({
        method: 'direct.incoming',
        meta: { ...NOTIFICATION.params.meta, message_id: `msg-${i}`, operation_id: `op-${i}` },
        body: { text: 'hi' },
      }))
    }

    await h.worker.runOnce()
    expect(sent).toEqual(['msg-0', 'msg-1'])
    expect(h.storage.dueOutbox('2099-01-01T00:00:00Z', 10)).toHaveLength(1)

    await h.worker.runOnce()
    expect(sent).toEqual(['msg-0', 'msg-1', 'msg-2'])
  })
})

/** Spin until `done`, or give up. A poll loop with a deadline rather than a fixed sleep,
 *  so a loaded machine slows the test down instead of failing it. */
async function waitFor(done: () => boolean, deadlineMs = 2000): Promise<void> {
  const until = Date.now() + deadlineMs
  while (!done()) {
    if (Date.now() > until) throw new Error('timed out waiting for the worker to tick')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

describe('the schema the worker reads', () => {
  it('is at least the version whose outbox holds a recipient DID, not an endpoint', () => {
    // §8.1 L731: a retry re-resolves, and `outbox.recipient_did` (v2) is what makes that
    // possible. The assertion is pinned to the CURRENT version rather than to `>= 2` so
    // that a bump lands here and gets read: the worker reads `dueOutbox` and writes it
    // back, so any change to the outbox shape has to be checked against this file.
    // v7 changed `deliveries`, which this file does not touch — checked, no action.
    // v8 added `one_time_prekeys`, a new table — checked, no action.
    expect(SCHEMA_VERSION).toBe(8)
  })
})
