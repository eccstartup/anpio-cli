// Who is watching which mailbox, and what happens to a message that arrives while they
// are still catching up.
//
// The whole of realtime.md §5 lives in this file:
//
//   * §5.2 — a subscription latches the head sequence at the moment it is registered and
//     holds every later frame until its backfill is done. That is what makes the
//     backfill-then-live handover gapless: the server owns the order, so there is no
//     window in which a message is neither in the replay nor on the wire.
//   * §5.3 — the hold has a bound. A client that never finishes its backfill is dropped
//     rather than silently skipped ahead: a gap the client cannot see is worse than a
//     disconnect it can (it reconnects with a cursor and gets the replay).
//
// One thing §5.2 states more loosely than it can be implemented: it says the handover is
// `(C, H]` for the backfill and `> H` for the push. H is read at registration and the
// backfill is answered later, so the backfill can already contain messages newer than H —
// a message that commits in between. Flushing "everything held" would then deliver it
// twice. So the release is filtered by the sequence the backfill ACTUALLY ended at, which
// the caller passes to `goLive`: at or below it was answered, above it is pushed. No gap
// either way, because every frame published after registration is held until then.
//
// The bound is also applied to a LIVE connection, through the socket's own write queue.
// A client that stops reading is the same problem as one that never finishes catching up,
// and the same answer applies, for the same reason.

import type { DeliveryRecord } from '../storage/types'

/** Frames held for one subscriber before it finishes its backfill. Beyond this the
 *  subscriber is lagging, not slow, and gets dropped (§5.3). The number is this
 *  implementation's choice: large enough that a burst during a normal backfill is
 *  absorbed, small enough that a client which never completes one costs bounded memory. */
export const MAX_PENDING = 256

/** Bytes held for a subscriber, counted the same way and checked in the same places.
 *  Both bounds exist because they fail differently: many tiny frames and one huge frame
 *  are the same problem measured two ways. */
export const MAX_PENDING_BYTES = 1024 * 1024

/** Write-queue depth at which a live connection counts as too slow to keep. */
export const MAX_BUFFERED = 4 * 1024 * 1024

/** The transport side of one subscription. The registry knows nothing about WebSockets —
 *  it is handed these three things and a test can hand it a recorder. */
export interface SubscriberTarget {
  /** Push one frame. Called only after the target said it was ready. */
  send(frame: string): void
  /** End the connection. `reason` is for the operator's log and the client's eyes. */
  close(reason: string): void
  /** Bytes written but not yet flushed. A client that stopped reading shows up here. */
  bufferedAmount(): number
}

export interface Subscription {
  /** The sequence this subscription starts from: the owner's head at registration.
   *  Everything after it is either in the caller's backfill or about to be pushed. */
  readonly headSeq: number
  /** The backfill has been answered, and its last sequence was `resumeAfter`. Held frames
   *  up to and including that one were part of the answer and are dropped; the rest go out
   *  now, in order. */
  goLive(resumeAfter: number): void
  /** Stop watching. Idempotent, and called by the registry itself when it drops one. */
  detach(): void
}

export interface SubscriberRegistry {
  /** Watch `target.ownerDid`'s queue as `target.deviceId`, starting from `headSeq`.
   *  Frames published before `goLive()` are held (§5.2). */
  subscribe(target: SubscriberTarget, ownerDid: string, deviceId: string, headSeq: number): Subscription
  /** One delivered message, to every connection watching its owner. Ordering follows the
   *  delivery sequence, which is the order the caller publishes in. */
  publish(record: DeliveryRecord): void
  /**
   * One frame to exactly one device, with no delivery row behind it.
   *
   * The P6 Device Delivery Queue (§12.6) is not group history and the Profile defines no
   * P6 pull method, so a P6 envelope has no `deliveries` row to hang a push off — this is
   * the push half on its own. Device-addressed by construction: a connection that declared
   * another device ID never sees it (the same rule {@link reaches} applies, and §12.6 item 4
   * is the reason for it).
   *
   * Returns whether a live connection took it. `false` is not an error and does not mean the
   * frame is lost: for a device with no live socket the caller keeps the envelope queued and
   * retries, which is what §12.6's bounded retention is for.
   */
  publishDevice(ownerDid: string, deviceId: string, frame: string): boolean
  /** Connected subscriptions, for a shutdown line and for tests. */
  size(): number
  /** Drop every subscription without closing the targets. For shutdown only. */
  clear(): void
}

interface Entry {
  target: SubscriberTarget
  deviceId: string
  headSeq: number
  /** Held frames with the sequence each belongs to, so the release can drop the ones the
   *  backfill already answered. */
  pending: { seq: number; frame: string }[]
  pendingBytes: number
  live: boolean
  gone: boolean
}

/** P3 §7.2.3's notification envelope, which is what the stream pushes. The payload is the
 *  delivery row's `params` verbatim — the same object `buildMessageNotification` put in the
 *  outbox, so the push path and the subscription path cannot drift apart. */
export function notificationFrame(record: DeliveryRecord): string {
  return JSON.stringify({ jsonrpc: '2.0', method: record.method, params: JSON.parse(record.paramsJson) })
}

/**
 * Does this delivery reach this connection?
 *
 * A delivery with no device is a P3 message: it is addressed to the account, and every
 * connection watching it gets the frame — the behaviour C7 shipped with. One with a
 * device is a P5 ciphertext, which §10.7.1 L1407 says **MUST** go to
 * `meta.recipient_device_id` and nowhere else; a sibling device cannot decrypt it, so
 * pushing it there would be a fan-out the spec forbids.
 *
 * A connection that declared no device therefore receives only the account-addressed
 * traffic. That is the honest reading: it has not said it stands for a device, so it is
 * not the mailbox of one.
 */
function reaches(entry: Entry, record: DeliveryRecord): boolean {
  return record.recipientDeviceId === undefined || entry.deviceId === record.recipientDeviceId
}

export function createSubscriberRegistry(): SubscriberRegistry {
  /** Keyed by owner DID: a delivery sequence belongs to the ACCOUNT (§5.1), so the map
   *  that finds candidates is the account. Which of them a frame reaches is decided by
   *  {@link reaches}, not by the key — P5 §10.7.1 L1407 forbids handing one device's
   *  ciphertext to a sibling. */
  const watching = new Map<string, Set<Entry>>()

  function forget(ownerDid: string, entry: Entry): void {
    if (entry.gone) return
    entry.gone = true
    entry.pending = []
    entry.pendingBytes = 0
    const set = watching.get(ownerDid)
    if (set === undefined) return
    set.delete(entry)
    if (set.size === 0) watching.delete(ownerDid)
  }

  function deliver(ownerDid: string, entry: Entry, frame: string, seq: number): void {
    if (entry.gone) return
    if (!entry.live) {
      entry.pending.push({ seq, frame })
      entry.pendingBytes += frame.length
      // §5.3: over the bound, the subscription is dropped rather than allowed to fall
      // further behind. `close` is what the client sees, and its own reconnect plus
      // cursor is what recovers the messages.
      if (entry.pending.length > MAX_PENDING || entry.pendingBytes > MAX_PENDING_BYTES) {
        entry.target.close('backfill fell too far behind; reconnect with your cursor')
        forget(ownerDid, entry)
      }
      return
    }
    entry.target.send(frame)
    // The socket is queuing faster than the peer reads. Same reasoning as above: the
    // messages stay in storage, so the connection is what gives way.
    if (entry.target.bufferedAmount() > MAX_BUFFERED) {
      entry.target.close('write queue is over its bound; reconnect with your cursor')
      forget(ownerDid, entry)
    }
  }

  return {
    subscribe(target, ownerDid, deviceId, headSeq) {
      const entry: Entry = { target, deviceId, headSeq, pending: [], pendingBytes: 0, live: false, gone: false }
      let set = watching.get(ownerDid)
      if (set === undefined) {
        set = new Set()
        watching.set(ownerDid, set)
      }
      set.add(entry)

      return {
        headSeq,
        goLive(resumeAfter: number): void {
          if (entry.gone || entry.live) return
          entry.live = true
          const held = entry.pending
          entry.pending = []
          entry.pendingBytes = 0
          // Held frames first, in the order they were published, skipping the ones the
          // backfill already carried. What is left is strictly newer than `resumeAfter`,
          // and every one of them arrived after registration, so nothing is missing
          // between the replay and the push.
          for (const item of held) {
            if (entry.gone) return
            if (item.seq <= resumeAfter) continue
            deliver(ownerDid, entry, item.frame, item.seq)
          }
        },
        detach(): void {
          forget(ownerDid, entry)
        },
      }
    },

    publish(record) {
      const set = watching.get(record.ownerDid)
      if (set === undefined) return
      const frame = notificationFrame(record)
      // A copy: `deliver` may drop an entry, which mutates the set being iterated.
      for (const entry of [...set]) {
        if (!reaches(entry, record)) continue
        deliver(record.ownerDid, entry, frame, record.seq)
      }
    },

    publishDevice(ownerDid, deviceId, frame) {
      const set = watching.get(ownerDid)
      if (set === undefined) return false
      let served = false
      // Only live connections, and only this device. A connection still backfilling has not
      // yet said where its cursor is, so there is no honest place to park a frame that has
      // no position in the delivery sequence — the caller retries instead.
      for (const entry of [...set]) {
        if (entry.gone || !entry.live || entry.deviceId !== deviceId) continue
        entry.target.send(frame)
        served = true
        if (entry.target.bufferedAmount() > MAX_BUFFERED) {
          entry.target.close('write queue is over its bound; reconnect with your cursor')
          forget(ownerDid, entry)
        }
      }
      return served
    },

    size() {
      let total = 0
      for (const set of watching.values()) total += set.size
      return total
    },

    clear() {
      for (const set of watching.values()) {
        for (const entry of set) {
          entry.gone = true
          entry.pending = []
          entry.pendingBytes = 0
        }
        set.clear()
      }
      watching.clear()
    },
  }
}
