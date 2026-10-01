// The registry, tested without a socket: `SubscriberTarget` is the seam, so every entry
// on it is recorded and every decision the registry makes about a slow or absent client is
// observable here rather than inferred from a network trace.

import { describe, expect, it } from 'vitest'
import type { DeliveryRecord } from '../storage/types'
import {
  MAX_PENDING,
  MAX_PENDING_BYTES,
  createSubscriberRegistry,
  notificationFrame,
  type SubscriberTarget,
} from './registry'

function record(overrides: Partial<DeliveryRecord> = {}): DeliveryRecord {
  return {
    ownerDid: 'did:web:example.com:alice',
    seq: 1,
    messageId: 'm-1',
    method: 'direct.incoming',
    paramsJson: '{"meta":{"method":"direct.incoming"},"body":{"text":"hi"}}',
    acceptedAt: '2026-10-01T00:00:00.000Z',
    ...overrides,
  }
}

interface Recorder extends SubscriberTarget {
  sent: string[]
  closes: string[]
  queue: number
}

function recorder(): Recorder {
  const sent: string[] = []
  const closes: string[] = []
  const target: Recorder = {
    sent,
    closes,
    queue: 0,
    send: (frame) => sent.push(frame),
    close: (reason) => closes.push(reason),
    bufferedAmount: () => target.queue,
  }
  return target
}

describe('notificationFrame', () => {
  it('is the §7.2.3 envelope with the stored params passed through untouched', () => {
    const frame = JSON.parse(notificationFrame(record())) as Record<string, unknown>
    expect(frame.jsonrpc).toBe('2.0')
    expect(frame.method).toBe('direct.incoming')
    // Byte-for-byte the stored payload: the push path and `sync.delta` must hand the client
    // the same object, so nothing here may normalize or re-derive it.
    expect(JSON.stringify(frame.params)).toBe(
      '{"meta":{"method":"direct.incoming"},"body":{"text":"hi"}}',
    )
  })
})

describe('the backfill window', () => {
  it('holds what arrives before the backfill is answered, then releases it in order', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    const subscription = registry.subscribe(target, 'did:web:example.com:alice', 'dev-1', 7)
    expect(subscription.headSeq).toBe(7)

    registry.publish(record({ seq: 8, messageId: 'm-8' }))
    registry.publish(record({ seq: 9, messageId: 'm-9' }))
    // §5.2: nothing goes out until the replay has been sent, or the client would render a
    // message it is about to receive again from the backfill.
    expect(target.sent).toEqual([])

    subscription.goLive(7)
    expect(target.sent.map((frame) => (JSON.parse(frame) as { params: { body: unknown } }).params)).toEqual([
      { meta: { method: 'direct.incoming' }, body: { text: 'hi' } },
      { meta: { method: 'direct.incoming' }, body: { text: 'hi' } },
    ])
  })

  it('drops the held frames the backfill already answered', () => {
    // The window this covers: the backfill is answered AFTER registration, so a message
    // that commits in between is in both places. Flushing it would render it twice.
    const registry = createSubscriberRegistry()
    const target = recorder()
    const subscription = registry.subscribe(target, record().ownerDid, 'dev-1', 3)
    registry.publish(record({ seq: 4 }))
    registry.publish(record({ seq: 5 }))
    registry.publish(record({ seq: 6 }))
    subscription.goLive(5)
    expect(target.sent).toHaveLength(1)
    expect(JSON.parse(target.sent[0] as string)).toEqual(
      JSON.parse(notificationFrame(record({ seq: 6 }))),
    )
  })

  it('sends straight through once live', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0).goLive(0)
    registry.publish(record({ seq: 1 }))
    expect(target.sent).toHaveLength(1)
  })

  it('does not put a second goLive in the way of anything', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    const subscription = registry.subscribe(target, record().ownerDid, 'dev-1', 0)
    subscription.goLive(0)
    registry.publish(record({ seq: 1 }))
    subscription.goLive(0)
    registry.publish(record({ seq: 2 }))
    expect(target.sent).toHaveLength(2)
  })
})

describe('routing', () => {
  it('delivers only to the owner the sequence belongs to', () => {
    const registry = createSubscriberRegistry()
    const mine = recorder()
    const theirs = recorder()
    registry.subscribe(mine, 'did:web:example.com:alice', 'dev-1', 0).goLive(0)
    registry.subscribe(theirs, 'did:web:example.com:bob', 'dev-1', 0).goLive(0)

    registry.publish(record({ ownerDid: 'did:web:example.com:bob' }))
    expect(mine.sent).toEqual([])
    expect(theirs.sent).toHaveLength(1)
  })

  it('gives every device watching an account the same sequence (§5.1)', () => {
    // 一份没有设备的消息（P3）是**发给账号**的：账号下的每条连接都拿到它，序号也只有一个。
    const registry = createSubscriberRegistry()
    const phone = recorder()
    const laptop = recorder()
    registry.subscribe(phone, record().ownerDid, 'phone', 0).goLive(0)
    registry.subscribe(laptop, record().ownerDid, 'laptop', 0).goLive(0)

    registry.publish(record({ seq: 3 }))
    expect(phone.sent).toHaveLength(1)
    expect(laptop.sent).toHaveLength(1)
    expect(registry.size()).toBe(2)
  })

  it('sends a device-addressed delivery to that device alone (§10.7.1 L1407)', () => {
    // P5 的密文只属于一台设备，同账号的兄弟设备解不开它——推过去就是规范禁止的 fan-out。
    // 序号仍按账号递增（下面那两条都拿到了 7），变的只是这一帧推给谁。
    const registry = createSubscriberRegistry()
    const phone = recorder()
    const laptop = recorder()
    registry.subscribe(phone, record().ownerDid, 'phone', 0).goLive(0)
    registry.subscribe(laptop, record().ownerDid, 'laptop', 0).goLive(0)

    registry.publish(record({ seq: 7, recipientDeviceId: 'phone' }))
    expect(phone.sent).toHaveLength(1)
    expect(laptop.sent).toEqual([])
  })

  it('does not hand a device-addressed delivery to a connection that named no device', () => {
    // 一条没说"我代表哪台设备"的连接不是任何设备的信箱：它只收账号级的消息。这比让它
    // 跟着收更诚实——P5 的选择器不是广播名单的一半。
    const registry = createSubscriberRegistry()
    const anonymous = recorder()
    registry.subscribe(anonymous, record().ownerDid, '', 0).goLive(0)

    registry.publish(record({ seq: 7, recipientDeviceId: 'phone' }))
    expect(anonymous.sent).toEqual([])

    registry.publish(record({ seq: 8 }))
    expect(anonymous.sent).toHaveLength(1)
  })

  it('forgets a detached subscription, and detaching twice is harmless', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    const subscription = registry.subscribe(target, record().ownerDid, 'dev-1', 0)
    subscription.goLive(0)
    subscription.detach()
    subscription.detach()
    registry.publish(record())
    expect(target.sent).toEqual([])
    expect(registry.size()).toBe(0)
  })
})

describe('a subscription that falls behind', () => {
  it('is dropped rather than skipped ahead, by frame count', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0)
    for (let i = 0; i <= MAX_PENDING; i++) registry.publish(record({ seq: i + 1 }))

    // §5.3: 宁可断，不可悄悄丢. The messages are still in storage, so the disconnect is
    // recoverable and a silently skipped frame is not.
    expect(target.closes).toHaveLength(1)
    expect(target.closes[0]).toContain('cursor')
    expect(target.sent).toEqual([])
    expect(registry.size()).toBe(0)
  })

  it('is dropped by bytes as well, when few frames are large', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0)
    const big = record({ paramsJson: `{"body":{"text":"${'x'.repeat(64 * 1024)}"}}` })
    for (let i = 0; i < MAX_PENDING_BYTES / (64 * 1024) + 2; i++) registry.publish(big)
    expect(target.closes).toHaveLength(1)
    expect(registry.size()).toBe(0)
  })

  it('does not keep pushing after being dropped', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0)
    for (let i = 0; i <= MAX_PENDING; i++) registry.publish(record({ seq: i + 1 }))
    registry.publish(record({ seq: 999 }))
    expect(target.closes).toHaveLength(1)
  })

  it('is dropped while live when the socket stops draining', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0).goLive(0)
    target.queue = 8 * 1024 * 1024
    registry.publish(record({ seq: 1 }))
    expect(target.closes).toHaveLength(1)
    expect(registry.size()).toBe(0)
  })

  it('survives a peer dropping out of the registry mid-publish', () => {
    // `deliver` can forget an entry while `publish` is iterating the same set.
    const registry = createSubscriberRegistry()
    const doomed = recorder()
    const other = recorder()
    registry.subscribe(doomed, record().ownerDid, 'a', 0)
    registry.subscribe(other, record().ownerDid, 'b', 0).goLive(0)
    for (let i = 0; i <= MAX_PENDING; i++) registry.publish(record({ seq: i + 1 }))
    expect(doomed.closes).toHaveLength(1)
    expect(other.sent.length).toBeGreaterThan(0)
    expect(registry.size()).toBe(1)
  })
})

describe('clear', () => {
  it('drops everyone without closing them, so a shutdown can close in its own order', () => {
    const registry = createSubscriberRegistry()
    const target = recorder()
    registry.subscribe(target, record().ownerDid, 'dev-1', 0).goLive(0)
    registry.clear()
    expect(registry.size()).toBe(0)
    expect(target.closes).toEqual([])
    registry.publish(record())
    expect(target.sent).toEqual([])
  })
})
