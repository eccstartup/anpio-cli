// 信箱迁移那一步的链解析**绕过文档缓存**（TODO7 §5，用户 2026-10-03 裁定走"乙"）。
//
// 这一条盯的是 `chainResolverFor(config, { fresh: true })` 与不带该档的区别，别处没有覆盖：
// `dispatch.test.ts` 里那六条换钥用例注入的是 `resolveChain`，量的是"采信之后搬了什么"，
// 一次也没碰过"这份文档是从缓存读的还是刚抓的"。
//
// 为什么这件事值得一条测试：缓存里那份文档是换钥**之前**抓的，它自己不写 `successorDid`。
// core 的两条缓存规则（带 `successorDid` 的文档不写进缓存、缓存里那份变了也不再读出）挡的
// 是"**已经**换过"，挡不住"抓的时候还没换、抓完之后才换"——那正是这里的情形。于是整个
// "换钥之后把投递搬回新 DID"的发现时刻，会被 `AGENTX_DID_CACHE_TTL_MS`（出厂 5 分钟）推后。
// 迁移这一步要的是"**现在**谁是这个主体的当前 DID"，晚五分钟没有理由，所以它自己带 `fresh`。
//
// **量的就是"我们递了什么选项给 core"**，而不是跑一遍真的解析：服务那份 `DidResolution`
// 配置面**故意**没有 `fetch` / `allowUncontrolledFetch` 这类接缝（放开它等于在生产配置里
// 开一条不设防的出站路），所以这里把 `resolveDidChain` 换成一个记录的桩，直接看调用参数。
// 缓存本身的行为是 core 的，`packages/core/src/did/chain.test.ts` 已经逐条测过。

import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as core from '@agentx/core'
import { loadConfig } from '../config'
import { chainResolverFor } from './memberDidUpdate'

vi.mock('@agentx/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@agentx/core')>()
  return { ...actual, resolveDidChain: vi.fn() }
})

const resolveDidChainMock = vi.mocked(core.resolveDidChain)

/** 一个 `did:wba` 身份——这里只当字符串用，解析被上面那个桩接住了。 */
const ALICE = 'did:wba:example.com:user:alice:e1_AAAA'

beforeEach(() => {
  resolveDidChainMock.mockReset()
  resolveDidChainMock.mockResolvedValue({} as never)
})

describe('chainResolverFor — the mailbox migration reads past the document cache (fresh)', () => {
  it('passes the shared document store by default', async () => {
    const config = loadConfig({})
    await chainResolverFor(config)(ALICE)

    const options = resolveDidChainMock.mock.calls[0]?.[1]
    expect(options?.documentStore).toBe(config.didResolution.documentStore)
  })

  it('fresh sends no documentStore, so every hop is a live fetch — while keeping trustedDocuments', async () => {
    const config = loadConfig({})
    await chainResolverFor(config, { fresh: true })(ALICE)

    const options = resolveDidChainMock.mock.calls[0]?.[1]
    // 没有 documentStore 就是"完全不缓存"（`ResolveDidOptions` 的原话），这一跳才会实时抓取。
    expect(options?.documentStore).toBeUndefined()
    // 恢复钥的凭据仍取自那份缓存：停用之前的那份文档只有它才有。
    expect(options?.trustedDocuments).toBe(config.didResolution.documentStore)
    // 档位口径与缓存档一致——两档问的是同一条链。
    expect(options?.reportLowAssurance).toBe(true)
  })
})
