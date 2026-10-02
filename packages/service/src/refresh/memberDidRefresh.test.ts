// A3c-4 —— §8.12 的定时刷新。网络那一层与别处一样是注入的，所以"这一轮看了几行、看了谁、
// 名册动没动"全部可观测。

import { describe, expect, it } from 'vitest'
import {
  stableSubjectId,
  subjectOf,
  type DidChain,
  type DidChainAssurance,
} from '@agentx/core'
import { loadConfig } from '../config'
import type { DidChainResolver } from '../rpc/memberDidUpdate'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import { createMemberDidRefreshWorker } from './memberDidRefresh'

const GROUP = 'did:wba:host.example:group:g1:e1_grp'
const ALICE = 'did:wba:peer.example:user:alice:e1_aaa'
const ALICE_SUCCESSOR = 'did:wba:peer.example:user:alice:e2_ccc'
const BOB = 'did:wba:peer.example:user:bob:e1_bbb'
const CAROL = 'did:wba:peer.example:user:carol:e1_ddd'
const CRYPTO_GROUP_ID = 'Z3JvdXAtb25l'
const HOUR = 60 * 60_000
const NOW = new Date('2026-10-01T12:00:00Z')

/** §8.12 刷新读的那条转移链。`currentDid === did` 就是"没换"。 */
function chainResolverTo(currentDid: string, assurance: DidChainAssurance = 'verified'): DidChainResolver {
  return async (did: string): Promise<DidChain> => ({
    did,
    subject: subjectOf(currentDid),
    stableSubjectId: stableSubjectId(currentDid),
    currentDid,
    superseded: currentDid !== did,
    assurance,
    document: {},
    docUrl: `https://peer.example/${currentDid}`,
    hops: [],
  })
}

/** 按 DID 给一个答案；没列出的 DID 就是"没换"。这让一个用例里几个成员的答案各不相同。 */
function chainResolverBy(dids: Record<string, { to: string; assurance?: DidChainAssurance }>): DidChainResolver {
  return async (did: string): Promise<DidChain> => {
    const answer = dids[did]
    if (answer === undefined) return chainResolverTo(did)(did)
    return chainResolverTo(answer.to, answer.assurance ?? 'verified')(did)
  }
}

function seedGroup(storage: Storage): void {
  if (storage.group(GROUP) !== undefined) return
  storage.insertGroup({
    groupDid: GROUP,
    hostServiceDid: 'did:wba:host.example',
    groupStateVersion: 1,
    groupEventSeq: 1,
    groupProfileJson: JSON.stringify({ group_name: 'g1', discoverability: 'private' }),
    groupPolicyJson: JSON.stringify({}),
    createdAt: NOW.toISOString(),
    creatorDid: ALICE,
  })
}

function seedMember(
  storage: Storage,
  memberDid: string,
  withLeaf = false,
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
  if (!withLeaf) return
  storage.upsertGroupLeaf({
    groupDid: GROUP,
    memberDid,
    memberDeviceId: 'dev-1',
    cryptoGroupId: CRYPTO_GROUP_ID,
    epoch: '1',
    state: 'active',
    addedByRefJson: '{}',
    updatedAt: NOW.toISOString(),
  })
}

interface Harness {
  storage: Storage
  logs: string[]
  /** 跑一轮，返回看过的行数。 */
  run(): Promise<number>
  /** 把钟往前拨，让刚盖过戳的行重新到期。 */
  advance(ms: number): void
}

function harness(overrides: {
  chainResolver?: DidChainResolver
  batch?: number
  intervalMs?: number
} = {}): Harness {
  const storage = openStorage({ path: ':memory:' })
  const logs: string[] = []
  let clock = NOW.getTime()
  const worker = createMemberDidRefreshWorker({
    config: loadConfig({}),
    storage,
    chainResolver: overrides.chainResolver ?? chainResolverBy({}),
    log: (line) => logs.push(line),
    now: () => new Date(clock),
    // 缺省把间隔设小，让"同一个 tick 里两次 runOnce"这点差别不至于干扰用例——真正管这件事的
    // `staleAfterMs` 由 worker 传成同一个数，所以拨钟与不拨钟的语义不变。
    intervalMs: overrides.intervalMs ?? HOUR,
    batch: overrides.batch ?? 20,
  })
  return {
    storage,
    logs,
    run: () => worker.runOnce(),
    advance(ms: number): void { clock += ms },
  }
}

describe('the periodic DID refresh (§8.12, A3c-4)', () => {
  it('adopts a verified successor of a quiet member, and opens §10.5 orchestration', async () => {
    const h = harness({
      chainResolver: chainResolverBy({ [ALICE]: { to: ALICE_SUCCESSOR } }),
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE, /* withLeaf */ true)
    seedMember(h.storage, BOB, /* withLeaf */ true)

    expect(await h.run()).toBe(2)

    // 名册搬了：旧 DID 那一行没了，新 DID 那一行在，且只有 DID 变了。
    expect(h.storage.groupMember(GROUP, ALICE)).toBeUndefined()
    const renamed = h.storage.groupMember(GROUP, ALICE_SUCCESSOR)
    expect(renamed?.membershipStatus).toBe('active')
    expect(renamed?.role).toBe('member')
    expect(renamed?.joinedAt).toBe(NOW.toISOString())
    expect(h.storage.countActiveMembers(GROUP)).toBe(2)

    // 改名推了两个计数器（§8.12 "after acceptance"）。
    expect(h.storage.group(GROUP)?.groupStateVersion).toBeGreaterThan(1)
    expect(h.storage.group(GROUP)?.groupEventSeq).toBeGreaterThan(1)

    // 旧 DID 的 leaf 一行都没动，所以 §10.5 的暂停成立、编排行也开了——刷新与另外两条触发路
    // 的后果完全一样。
    expect(h.storage.groupLeaf(GROUP, ALICE, 'dev-1')?.state).toBe('active')
    const orchestration = h.storage.groupDidUpdate(GROUP)
    expect(orchestration?.progress).toBe('add-pending')
    expect(JSON.parse(orchestration?.expectedJson ?? '[]')).toEqual([[ALICE, 'dev-1']])

    expect(h.logs.some((line) => line.includes('via refresh'))).toBe(true)
  })

  it('renames a member that has no leaf at all — the case only this trigger can reach', async () => {
    const h = harness({
      chainResolver: chainResolverBy({ [ALICE]: { to: ALICE_SUCCESSOR } }),
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)

    expect(await h.run()).toBe(1)

    expect(h.storage.groupMember(GROUP, ALICE_SUCCESSOR)?.membershipStatus).toBe('active')
    // 没有旧 leaf 要退役，所以没有要编排的事：不开编排行，群也不会被暂停。
    expect(h.storage.groupDidUpdate(GROUP)).toBeUndefined()
  })

  it('stamps a member whose DID has not moved, so it drops out of the next batch', async () => {
    const h = harness({ batch: 1 })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)

    expect(await h.run()).toBe(1)
    expect(h.storage.groupMember(GROUP, ALICE)?.lastDidCheckedAt).toBe(NOW.toISOString())
    // 同一个时刻再跑一轮：刚看过的行还没到复查周期，一行都不取。
    expect(await h.run()).toBe(0)
    // 拨过间隔就重新到期。
    h.advance(HOUR + 1)
    expect(await h.run()).toBe(1)
  })

  it('rotates through the roster: each tick takes the least recently checked', async () => {
    const h = harness({ batch: 1 })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)
    seedMember(h.storage, BOB)

    // 两行都没看过时按 `(group_did, member_did)` 定序，所以第一个是 alice。
    expect(await h.run()).toBe(1)
    expect(h.storage.groupMember(GROUP, ALICE)?.lastDidCheckedAt).toBe(NOW.toISOString())
    expect(h.storage.groupMember(GROUP, BOB)?.lastDidCheckedAt).toBeUndefined()

    h.advance(HOUR + 1)
    const second = NOW.getTime() + HOUR + 1
    expect(await h.run()).toBe(1)
    expect(h.storage.groupMember(GROUP, BOB)?.lastDidCheckedAt).toBe(new Date(second).toISOString())
  })

  it('refuses a successor below policy, and still stamps the row', async () => {
    const h = harness({
      chainResolver: chainResolverBy({ [ALICE]: { to: ALICE_SUCCESSOR, assurance: 'provider_asserted' } }),
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE, /* withLeaf */ true)

    await h.run()

    expect(h.storage.groupMember(GROUP, ALICE)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(GROUP, ALICE_SUCCESSOR)).toBeUndefined()
    expect(h.storage.groupDidUpdate(GROUP)).toBeUndefined()
    expect(h.logs.some((line) => line.includes('assurance provider_asserted is below policy'))).toBe(true)
    expect(h.storage.groupMember(GROUP, ALICE)?.lastDidCheckedAt).toBe(NOW.toISOString())
  })

  it('stamps a row whose chain could not be resolved, so one unreachable peer cannot block the batch', async () => {
    const h = harness({
      batch: 1,
      chainResolver: async () => {
        throw new Error('did server unreachable')
      },
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)
    seedMember(h.storage, BOB)

    expect(await h.run()).toBe(1)
    expect(h.logs.some((line) => line.includes('could not resolve the DID chain'))).toBe(true)
    // 关键：alice 虽然解析失败，但已经被盖了戳——下一轮取的是 bob，而不是她再来一次。
    expect(h.storage.groupMember(GROUP, ALICE)?.lastDidCheckedAt).toBe(NOW.toISOString())
    h.advance(HOUR + 1)
    expect(await h.run()).toBe(1)
    expect(h.storage.groupMember(GROUP, BOB)?.lastDidCheckedAt).toBeDefined()
  })

  it('skips the successor when it is already an active member (§8.12 item 4)', async () => {
    const h = harness({
      chainResolver: chainResolverBy({ [ALICE]: { to: BOB } }),
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)
    seedMember(h.storage, BOB)

    await h.run()

    // 两个人都还在，没有谁被并成谁。
    expect(h.storage.groupMember(GROUP, ALICE)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(GROUP, BOB)?.membershipStatus).toBe('active')
    expect(h.logs.some((line) => line.includes('already an active member'))).toBe(true)
  })

  it('leaves members who are no longer active out of the batch', async () => {
    const h = harness({
      chainResolver: chainResolverBy({ [ALICE]: { to: ALICE_SUCCESSOR } }),
    })
    seedGroup(h.storage)
    seedMember(h.storage, ALICE)
    seedMember(h.storage, CAROL, false, 'removed')

    // 只有 alice 那一行是 active 的。
    expect(await h.run()).toBe(1)
    expect(h.storage.groupMember(GROUP, ALICE_SUCCESSOR)?.membershipStatus).toBe('active')
    expect(h.storage.groupMember(GROUP, CAROL)?.membershipStatus).toBe('removed')
    expect(h.storage.groupMember(GROUP, CAROL)?.lastDidCheckedAt).toBeUndefined()
  })
})
