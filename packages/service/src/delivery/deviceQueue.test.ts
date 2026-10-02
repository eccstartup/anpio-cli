// P6 §12.6 的 Device Delivery Queue 出站。与 `worker.test.ts` 一样，网络那一层是注入的，
// 所以"这一轮到底发了几封、发给谁、发的是哪一份字节"全部可观测。

import { describe, expect, it } from 'vitest'
import type { LocateOptions, ServiceEntry, ServiceLocator } from '@agentx/core'
import { loadConfig } from '../config'
import { openStorage } from '../storage/sqlite'
import type { Storage, StoredDeviceEnvelope } from '../storage/types'
import { createSubscriberRegistry } from '../stream/registry'
import type { SubscriberTarget } from '../stream/registry'
import { createDeviceQueueWorker } from './deviceQueue'

const GROUP = 'did:wba:host.example:group:g1:e1_grp'
const ALICE = 'did:wba:peer.example:user:alice:e1_aaa'
const BOB = 'did:wba:peer.example:user:bob:e1_bbb'
const ALICE_DEVICE = 'dev-alice-1'
const BOB_DEVICE = 'dev-bob-1'
const NOW = new Date('2026-10-01T12:00:00Z')
const CRYPTO_GROUP_ID = 'Z3JvdXAtb25l'

const PEER: ServiceEntry = {
  id: '#anp-message-service',
  type: 'ANPMessageService',
  serviceEndpoint: 'https://peer.example/anp-im/rpc',
}

function locatorOf(entries: ServiceEntry[] | Error): ServiceLocator {
  return {
    async locate(): Promise<ServiceEntry[]> {
      if (entries instanceof Error) throw entries
      return entries
    },
  }
}

function policy(handler: (url: string, init: RequestInit) => Promise<Response>, extra: LocateOptions = {}): LocateOptions {
  return {
    allowedHosts: ['peer.example'],
    resolveAddresses: async () => ['93.184.216.34'],
    fetch: handler,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

/** 一条 leaf 的投影，加上它所属的 P4 成员行。`status` 传非 active 就是 §10.4 那个"整个成员
 *  要在 MLS 那边收尾"的中间态。 */
function seedLeaf(
  storage: Storage,
  memberDid: string,
  deviceId: string,
  state: 'active' | 'terminal' = 'active',
  status = 'active',
): void {
  storage.upsertGroupMember({
    groupDid: GROUP,
    memberDid,
    role: 'member',
    membershipStatus: status,
    stateVersion: 1,
    joinedAt: NOW.toISOString(),
  })
  storage.upsertGroupLeaf({
    groupDid: GROUP,
    memberDid,
    memberDeviceId: deviceId,
    cryptoGroupId: CRYPTO_GROUP_ID,
    epoch: '1',
    state,
    addedByRefJson: '{}',
    updatedAt: NOW.toISOString(),
  })
}

function envelope(deviceId: string, kind = 'incoming'): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    method: 'group.incoming',
    params: { meta: { recipient_device_id: deviceId }, body: { group_did: GROUP } },
  })
}

interface Harness {
  storage: Storage
  logs: string[]
  worker: ReturnType<typeof createDeviceQueueWorker>
  registry: ReturnType<typeof createSubscriberRegistry>
  /** 入队一条。默认现在到期。 */
  enqueue(
    recipientDid: string,
    deviceId: string,
    options?: { kind?: string; nextAttemptAt?: string; enqueuedAt?: string; groupDid?: string },
  ): number
  at(ms: number): void
}

function harness(
  overrides: {
    locator?: ServiceLocator
    locateOptions?: LocateOptions
    maxAttempts?: number
    maxQueueAgeMs?: number
    batchSize?: number
    random?: () => number
  } = {},
): Harness {
  const storage = openStorage({ path: ':memory:' })
  const logs: string[] = []
  const registry = createSubscriberRegistry()
  let clock = NOW.getTime()
  const worker = createDeviceQueueWorker({
    config: loadConfig({}),
    storage,
    registry,
    locator: overrides.locator ?? locatorOf([PEER]),
    locateOptions: overrides.locateOptions ?? policy(async () => new Response('', { status: 200 })),
    log: (line) => logs.push(line),
    now: () => new Date(clock),
    maxAttempts: overrides.maxAttempts ?? 3,
    baseBackoffMs: 1000,
    maxBackoffMs: 60_000,
    random: overrides.random ?? (() => 0),
    ...(overrides.maxQueueAgeMs !== undefined ? { maxQueueAgeMs: overrides.maxQueueAgeMs } : {}),
    ...(overrides.batchSize !== undefined ? { batchSize: overrides.batchSize } : {}),
  })
  return {
    storage,
    logs,
    worker,
    registry,
    enqueue(recipientDid, deviceId, options = {}): number {
      return storage.enqueueDeviceEnvelope({
        recipientDid,
        recipientDeviceId: deviceId,
        groupDid: options.groupDid ?? GROUP,
        kind: options.kind ?? 'incoming',
        envelopeJson: envelope(deviceId, options.kind ?? 'incoming'),
        attempts: 0,
        nextAttemptAt: options.nextAttemptAt ?? NOW.toISOString(),
        enqueuedAt: options.enqueuedAt ?? NOW.toISOString(),
      })
    },
    at(ms: number): void {
      clock = ms
    },
  }
}

/** 队列里的每一条（`due` 取远未来，于是"队头已到期"对每条队列都成立）。 */
function queued(storage: Storage): StoredDeviceEnvelope[] {
  return storage.dueDeviceEnvelopes('9999-12-31T00:00:00Z', 1000)
}

/** 一个收帧的记录器，用来验本地推送。 */
function recorder(): SubscriberTarget & { sent: string[]; closes: string[] } {
  const sent: string[] = []
  const closes: string[] = []
  const target = {
    sent,
    closes,
    send: (frame: string) => sent.push(frame),
    close: (reason: string) => closes.push(reason),
    bufferedAmount: () => 0,
  }
  return target
}

describe('delivering a device envelope', () => {
  it('POSTs the stored envelope verbatim and clears the row', async () => {
    // §12.6 第 2 条：重投要**原样**复现。这里存的字节与发出去的字节逐字相同。
    let seen: { url: string; body: unknown } | undefined
    const h = harness({
      locateOptions: policy(async (url, init) => {
        seen = { url, body: JSON.parse(String(init.body)) }
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)

    await h.worker.runOnce()

    expect(seen?.url).toBe(PEER.serviceEndpoint)
    expect(seen?.body).toEqual(JSON.parse(envelope(ALICE_DEVICE)))
    expect(queued(h.storage)).toEqual([])
  })

  it('sends each device its own envelope and never a sibling copy', async () => {
    // §12.6 第 4 条：同一 DID 的两台设备各有各的信封，一条都不能拿另一条的顶替。
    const bodies: Record<string, unknown>[] = []
    const h = harness({
      locateOptions: policy(async (_url, init) => {
        bodies.push(JSON.parse(String(init.body)))
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    seedLeaf(h.storage, ALICE, 'dev-alice-2')
    h.enqueue(ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, 'dev-alice-2')
    // BOB 没有队列行，所以一个字节都不该发给他。
    seedLeaf(h.storage, BOB, BOB_DEVICE)

    await h.worker.runOnce()

    const devices = bodies.map((b) => (b as { params: { meta: { recipient_device_id: string } } }).params.meta.recipient_device_id)
    expect(devices).toEqual([ALICE_DEVICE, 'dev-alice-2'])
  })

  it('pushes to the device itself when the recipient is one of our own', async () => {
    // 收件人住在本服务上：P6 的信封在 `deliveries` 里没有行，所以不能像 P4 那样就地丢掉，
    // 得真推给那条订阅。
    const own = loadConfig({})
    const h = harness({
      locator: locatorOf([{ ...PEER, serviceEndpoint: `${own.publicUrl}/anp-im/rpc/` }]),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)

    const target = recorder()
    h.registry.subscribe(target, ALICE, ALICE_DEVICE, 0).goLive(0)
    await h.worker.runOnce()

    expect(target.sent).toEqual([envelope(ALICE_DEVICE)])
    expect(queued(h.storage)).toEqual([])
  })

  it('keeps the row when the local device has no live socket, and does not retire it', async () => {
    // 设备没连着不是"这条信封投失败了"，是"还没到时候"：本地这步是廉价的，每个 tick 重试一次
    // 换设备一上线就立刻收到。所以它**不记尝试**——否则一台离线几秒的设备会撞满尝试上限，
    // 有界保留就轮到在队时长那条闸门来收。
    const own = loadConfig({})
    const h = harness({
      locator: locatorOf([{ ...PEER, serviceEndpoint: `${own.publicUrl}/anp-im/rpc/` }]),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    const seq = h.enqueue(ALICE, ALICE_DEVICE)

    await h.worker.runOnce()

    const [row] = queued(h.storage)
    expect(row?.seq).toBe(seq)
    expect(row?.attempts).toBe(0)
    // 另一个设备的订阅不该收到它。
    const sibling = recorder()
    h.registry.subscribe(sibling, ALICE, 'dev-alice-2', 0).goLive(0)
    await h.worker.runOnce()
    expect(sibling.sent).toEqual([])
  })
})

describe('the queue is delivered head-first (§12.6 / §6.1)', () => {
  it('does not deliver behind a head that has not gone out', async () => {
    // 一台设备的 `group.incoming` MUST 按 `group_event_seq` 顺序投。队头失败之后，它后面那些
    // **已经到期**的行这一轮一律不走——另一条队列不受影响。
    const posted: string[] = []
    const h = harness({
      locateOptions: policy(async (_url, init) => {
        const body = JSON.parse(String(init.body)) as { params: { meta: { recipient_device_id: string } } }
        const device = body.params.meta.recipient_device_id
        posted.push(device)
        return device === ALICE_DEVICE ? new Response('', { status: 503 }) : new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    seedLeaf(h.storage, BOB, BOB_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)
    h.enqueue(BOB, BOB_DEVICE)

    await h.worker.runOnce()

    // alice 只试了队头一次；她那第二条一次都没试。bob 那条照常投出去了。
    expect(posted).toEqual([ALICE_DEVICE, BOB_DEVICE])
    expect(queued(h.storage).map((r) => `${r.recipientDid === ALICE ? 'alice' : 'bob'}#${r.seq}`)).toEqual([
      'alice#1',
      'alice#2',
    ])
  })

  it('delivers the application envelopes first and the final notice last', async () => {
    // §12.3 选定的 SHOULD 那条：已经为这条 leaf 入队的应用信封按序投完，最终通知压在最后。
    const posted: string[] = []
    const h = harness({
      locateOptions: policy(async (_url, init) => {
        posted.push(JSON.parse(String(init.body)).params.body.kind ?? 'incoming')
        return new Response('', { status: 200 })
      }),
    })
    // 这台设备已经被 Remove 了（leaf 是 terminal）——§12.6 第 3 条的第二个例外正是这一档。
    seedLeaf(h.storage, ALICE, ALICE_DEVICE, 'terminal')
    h.enqueue(ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE, { kind: 'final-notice' })

    await h.worker.runOnce()

    expect(posted).toEqual(['incoming', 'incoming', 'incoming'])
    expect(h.storage.dueDeviceEnvelopes('9999-12-31T00:00:00Z', 10)).toEqual([])
    expect(h.logs.some((line) => line.includes('final notice delivered'))).toBe(true)
  })
})

describe('delivery is revalidated against current eligibility (§12.6 item 3)', () => {
  it('holds a queue whose member is mid-change, without spending an attempt', async () => {
    // leaf 还是 active，但它的 P4 成员已经不是 active 了：§10.4/§10.5 的中间态，epoch MUST NOT
    // 承载应用消息。等 owner 把这条 leaf Remove 掉，它就落进上面那条例外。
    let called = false
    const h = harness({
      locateOptions: policy(async () => {
        called = true
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE, 'active', 'removed')
    const seq = h.enqueue(ALICE, ALICE_DEVICE)

    await h.worker.runOnce()

    expect(called).toBe(false)
    const [row] = queued(h.storage)
    // 不动它：这是一个"等我"，不是一个失败。重排会把它记成失败并推向丢弃。
    expect(row?.seq).toBe(seq)
    expect(row?.attempts).toBe(0)
    expect(row?.nextAttemptAt).toBe(NOW.toISOString())
  })

  it('resumes that queue once the leaf is removed (the §12.3 exception)', async () => {
    const posted: string[] = []
    const h = harness({
      locateOptions: policy(async (_url, init) => {
        posted.push(JSON.parse(String(init.body)).params.body.kind ?? 'incoming')
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE, 'active', 'removed')
    h.enqueue(ALICE, ALICE_DEVICE)
    await h.worker.runOnce()
    expect(posted).toEqual([])

    // owner 把这条 leaf Remove 掉：投影转 terminal，最终通知入队。队列于是整体解锁。
    seedLeaf(h.storage, ALICE, ALICE_DEVICE, 'terminal', 'removed')
    h.enqueue(ALICE, ALICE_DEVICE, { kind: 'final-notice' })
    await h.worker.runOnce()

    expect(posted).toEqual(['incoming', 'incoming'])
    expect(queued(h.storage)).toEqual([])
  })
})

describe('retention is bounded (§12.6)', () => {
  it('drops a row at the attempt limit and says so', async () => {
    const h = harness({
      maxAttempts: 3,
      locateOptions: policy(async () => new Response('', { status: 503 })),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE)

    await h.worker.runOnce()
    h.at(NOW.getTime() + 60_000)
    await h.worker.runOnce()
    h.at(NOW.getTime() + 120_000)
    await h.worker.runOnce()

    expect(queued(h.storage)).toEqual([])
    expect(h.logs.some((line) => line.includes('dropped') && line.includes('3 attempts'))).toBe(true)
  })

  it('drops a row that has been queued past the age bound, without delivering it', async () => {
    // 有界保留的另一条闸门。它管的是"这条行还有没有资格待在队里"，所以排在资格复核之前。
    let called = false
    const h = harness({
      maxQueueAgeMs: 60_000,
      locateOptions: policy(async () => {
        called = true
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE, { enqueuedAt: '2026-10-01T10:00:00Z' })

    await h.worker.runOnce()

    expect(called).toBe(false)
    expect(queued(h.storage)).toEqual([])
    expect(h.logs.some((line) => line.includes('retention bound'))).toBe(true)
  })

  it('takes both bounds from Config when no worker option overrides them (A5)', async () => {
    // 有界保留是部署档位：不传 maxAttempts / maxQueueAgeMs 时，worker 取 config.deviceQueue。
    const build = (env: NodeJS.ProcessEnv, locateOptions: LocateOptions): { storage: Storage; logs: string[]; worker: ReturnType<typeof createDeviceQueueWorker>; at: (ms: number) => void } => {
      const storage = openStorage({ path: ':memory:' })
      const logs: string[] = []
      let clock = NOW.getTime()
      const worker = createDeviceQueueWorker({
        config: loadConfig(env),
        storage,
        registry: createSubscriberRegistry(),
        locator: locatorOf([PEER]),
        locateOptions,
        log: (line) => logs.push(line),
        now: () => new Date(clock),
        baseBackoffMs: 1000,
        maxBackoffMs: 60_000,
        random: () => 0,
      })
      return { storage, logs, worker, at: (ms) => { clock = ms } }
    }

    const attempts = build({ AGENTX_DEVICE_QUEUE_MAX_ATTEMPTS: '2' }, policy(async () => new Response('', { status: 503 })))
    seedLeaf(attempts.storage, ALICE, ALICE_DEVICE)
    attempts.storage.enqueueDeviceEnvelope({
      recipientDid: ALICE, recipientDeviceId: ALICE_DEVICE, groupDid: GROUP, kind: 'incoming',
      envelopeJson: envelope(ALICE_DEVICE), attempts: 0, nextAttemptAt: NOW.toISOString(), enqueuedAt: NOW.toISOString(),
    })
    await attempts.worker.runOnce()
    attempts.at(NOW.getTime() + 60_000)
    await attempts.worker.runOnce()
    expect(queued(attempts.storage)).toEqual([])
    expect(attempts.logs.some((line) => line.includes('dropped') && line.includes('2 attempts'))).toBe(true)

    let delivered = false
    const age = build({ AGENTX_DEVICE_QUEUE_MAX_AGE_MS: '1000' }, policy(async () => {
      delivered = true
      return new Response('', { status: 200 })
    }))
    seedLeaf(age.storage, ALICE, ALICE_DEVICE)
    age.storage.enqueueDeviceEnvelope({
      recipientDid: ALICE, recipientDeviceId: ALICE_DEVICE, groupDid: GROUP, kind: 'incoming',
      envelopeJson: envelope(ALICE_DEVICE), attempts: 0, nextAttemptAt: NOW.toISOString(), enqueuedAt: new Date(NOW.getTime() - 60_000).toISOString(),
    })
    await age.worker.runOnce()
    expect(delivered).toBe(false)
    expect(queued(age.storage)).toEqual([])
    expect(age.logs.some((line) => line.includes('retention bound'))).toBe(true)
  })

  it('unblocks the queue behind a discarded head', async () => {
    // 丢弃 MUST NOT 卡住后面的投递：队头超龄被扫掉之后，下一条立刻成为队头并出去。
    const posted: string[] = []
    const h = harness({
      maxQueueAgeMs: 60_000,
      locateOptions: policy(async (_url, init) => {
        posted.push(JSON.parse(String(init.body)).params.meta.recipient_device_id)
        return new Response('', { status: 200 })
      }),
    })
    seedLeaf(h.storage, ALICE, ALICE_DEVICE)
    h.enqueue(ALICE, ALICE_DEVICE, { enqueuedAt: '2026-10-01T10:00:00Z' })
    h.enqueue(ALICE, ALICE_DEVICE)

    await h.worker.runOnce()

    expect(posted).toEqual([ALICE_DEVICE])
    expect(queued(h.storage)).toEqual([])
  })
})
