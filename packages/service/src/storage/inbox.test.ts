// C6 —— 取件面在存储层的那一半（message-service.md §9.3）。
//
// 这里只管行的形状与筛选：`inboxPage` / `inboxSize` / `inboxRows` / `markRead`。RPC 那一层
// （参数、错误码、Profile）在 `rpc/dispatch.test.ts` 的取件面那一节里跑。

import { describe, expect, it } from 'vitest'
import { openStorage } from './sqlite'
import type { Storage } from './types'

const ALICE = 'did:wba:a.example:user:alice:e1_aaa'
const BOB = 'did:wba:b.example:user:bob:e1_bbb'

/** 一条投递行，`params_json` 是 `direct.incoming` 通知的形状——`toIncomingRow` 读的就是
 *  它的 `meta.sender_did` / `meta.content_type` 与 `body`。 */
function receive(
  store: Storage,
  owner: string,
  from: string,
  messageId: string,
  at: string,
  body: Record<string, unknown> = { text: messageId },
): void {
  store.appendDelivery({
    ownerDid: owner,
    messageId,
    method: 'direct.incoming',
    paramsJson: JSON.stringify({
      meta: {
        profile: 'anp.direct.base.v1',
        security_profile: 'transport-protected',
        sender_did: from,
        target: { kind: 'agent', did: owner },
        operation_id: `op-${messageId}`,
        message_id: messageId,
        content_type: 'text/plain',
      },
      body,
    }),
    acceptedAt: at,
  })
}

function send(store: Storage, from: string, to: string, messageId: string, at: string): void {
  store.insertMessage({
    messageId,
    senderDid: from,
    targetDid: to,
    profile: 'anp.direct.base.v1',
    securityProfile: 'transport-protected',
    contentType: 'text/plain',
    bodyJson: JSON.stringify({ text: messageId }),
    acceptedAt: at,
  })
}

/** One instant per message, so the merged order is a literal. */
function at(minute: number): string {
  return new Date(Date.UTC(2026, 9, 1, 12, minute)).toISOString()
}

function ids(rows: { messageId: string }[]): string[] {
  return rows.map((row) => row.messageId)
}

describe('the two tables the inbox merges', () => {
  it('lists both directions newest first', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'from-alice', at(1))
    send(store, BOB, ALICE, 'to-alice', at(2))

    const page = store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: true })

    expect(ids(page)).toEqual(['to-alice', 'from-alice'])
    expect(page[0]?.direction).toBe('outgoing')
    expect(page[0]?.recipientDid).toBe(ALICE)
    expect(page[1]?.direction).toBe('incoming')
    expect(page[1]?.senderDid).toBe(ALICE)
    expect(page[1]?.recipientDid).toBe(BOB)
    store.close()
  })

  it('keeps a message the owner sent out of the other mailbox', () => {
    const store = openStorage({ path: ':memory:' })
    send(store, BOB, ALICE, 'one-way', at(1))
    expect(ids(store.inboxPage(ALICE, { limit: 20, skip: 0, includeRead: true }))).toEqual([])
    store.close()
  })

  it('carries the delivery body through to the row', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'm1', at(1), { payload: { kind: 'ping' } })
    const [row] = store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: true })
    expect(JSON.parse(row?.bodyJson ?? '{}')).toEqual({ payload: { kind: 'ping' } })
    expect(row?.contentType).toBe('text/plain')
    store.close()
  })
})

describe('paging', () => {
  it('does not repeat or drop a message across pages', () => {
    const store = openStorage({ path: ':memory:' })
    for (let i = 0; i < 5; i++) receive(store, BOB, ALICE, `in-${i}`, at(i))
    for (let i = 0; i < 5; i++) send(store, BOB, ALICE, `out-${i}`, at(5 + i))

    const all = ids(store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: true }))
    const paged: string[] = []
    for (let skip = 0; skip < all.length; skip += 3) {
      paged.push(...ids(store.inboxPage(BOB, { limit: 3, skip, includeRead: true })))
    }
    // `skip` is an offset over a merged, time-ordered list, so an unstable order would
    // show up here as a duplicate plus a hole rather than as a failure.
    expect(paged).toEqual(all)
    expect(new Set(paged).size).toBe(10)
    store.close()
  })

  it('counts what the same filter would return', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'in-0', at(0))
    receive(store, BOB, ALICE, 'in-1', at(1))
    send(store, BOB, ALICE, 'out-0', at(2))

    expect(store.inboxSize(BOB, true)).toBe(3)
    store.markRead(BOB, ['in-0'], at(9))
    expect(store.inboxSize(BOB, false)).toBe(2)
    expect(store.inboxSize(BOB, true)).toBe(3)
    expect(store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: false })).toHaveLength(2)
    store.close()
  })
})

describe('reading by id', () => {
  it('returns only ids in this mailbox, in the order asked', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'mine', at(1))
    send(store, ALICE, BOB, 'hers', at(2))

    // `hers` belongs to Alice's mailbox, so Bob asking for it gets nothing back — a
    // message id is not a capability.
    const rows = store.inboxRows(BOB, ['mine', 'hers'])
    expect(ids(rows)).toEqual(['mine'])
    expect(ids(store.inboxRows(BOB, ['mine', 'mine']))).toEqual(['mine'])
    store.close()
  })
})

describe('marking read', () => {
  it('marks the owner messages and reports only what changed', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'in-0', at(0))
    receive(store, BOB, ALICE, 'in-1', at(1))

    expect(store.markRead(BOB, ['in-0', 'in-1'], at(9))).toEqual(['in-0', 'in-1'])
    // Already read: the FIRST read is when it was read, so a second call changes nothing.
    expect(store.markRead(BOB, ['in-0'], at(10))).toEqual([])

    const rows = store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: true })
    expect(rows[0]?.readAt).toBe(at(9))
    store.close()
  })

  it('skips an id it does not hold instead of recording it', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'in-0', at(0))

    expect(store.markRead(BOB, ['in-0', 'someone-elses'], at(9))).toEqual(['in-0'])
    store.close()
  })

  it('leaves an outgoing message with no read time until it is asked for', () => {
    const store = openStorage({ path: ':memory:' })
    receive(store, BOB, ALICE, 'in-0', at(0))
    send(store, BOB, ALICE, 'out-0', at(1))

    const before = store.inboxPage(BOB, { limit: 20, skip: 0, includeRead: true })
    // A message the owner sent was never unread for the owner; nothing marked it, so
    // the honest answer is null rather than a timestamp nobody produced.
    expect(before.find((row) => row.messageId === 'out-0')?.readAt).toBeNull()
    store.close()
  })
})
