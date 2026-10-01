import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { DidChain } from '@agentx/core'
import { DID_EXIT, runDid } from './did'
import type { Values } from './auth'

// `--chain` is a thin shell over `resolveDidChain`: what belongs to the CLI is the
// flag→option mapping, the printed shape, and the exit code. The SDK's walk itself has
// its own tests, so the SDK is mocked here and driven directly — a real chain would
// mean re-building update fixtures that `src/core/did/chain.test.ts` already owns.

vi.mock('@agentx/core', () => ({
  ConnectxError: class ConnectxError extends Error {
    code: string
    constructor(code: string, message: string) {
      super(message)
      this.code = code
    }
  },
  isSuperseded: () => false,
  resolveDidDocument: vi.fn(),
  resolveDidChain: vi.fn(),
}))

const { resolveDidChain } = await import('@agentx/core')
const chain = vi.mocked(resolveDidChain)

const ASKED = 'did:wba:example.com:user:alice:e1_old'
const CURRENT = 'did:wba:example.com:user:alice:e1_new'

function chainResult(over: Partial<DidChain> = {}): DidChain {
  return {
    did: ASKED,
    subject: 'did:wba:example.com:user:alice',
    stableSubjectId: 'example.com:user:alice',
    currentDid: CURRENT,
    superseded: true,
    assurance: 'recovery_verified',
    document: { id: CURRENT },
    docUrl: `https://example.com/user/alice/e1_new/did.json`,
    hops: [
      {
        did: ASKED,
        successorDid: CURRENT,
        document: { id: ASKED },
        docUrl: 'https://example.com/user/alice/e1_old/did.json',
        source: 'network',
        assurance: 'verified',
        proofKeyId: `${ASKED}#key-1`,
      },
      {
        did: CURRENT,
        successorDid: 'did:wba:example.com:user:alice:e1_newer',
        document: { id: CURRENT },
        docUrl: 'https://example.com/user/alice/e1_new/did.json',
        source: 'network',
        assurance: 'recovery_verified',
      },
    ],
    ...over,
  }
}

function flags(over: Record<string, unknown> = {}): Values {
  return { chain: true, 'allow-host': ['example.com'], ...over } as unknown as Values
}

async function run(values: Values) {
  const out: string[] = []
  const err: string[] = []
  const log = vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')))
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')))
  try {
    return { code: await runDid(values, 'resolve', ASKED), out: out.join('\n'), err: err.join('\n') }
  } finally {
    log.mockRestore()
    errSpy.mockRestore()
  }
}

beforeEach(() => {
  chain.mockReset()
})

describe('did resolve --chain', () => {
  it('walks a superseded chain, prints every hop, and exits 2', async () => {
    chain.mockResolvedValue(chainResult())
    const { code, out } = await run(flags())
    expect(code).toBe(DID_EXIT.superseded)
    expect(out).toContain(`currentDid:  ${CURRENT}`)
    expect(out).toContain('superseded:  yes')
    expect(out).toContain('assurance:   recovery_verified')
    expect(out).toContain(`[1] ${ASKED} → ${CURRENT}`)
    expect(out).toContain('assurance=verified source=network proofKeyId=')
    expect(out).toContain(`[2] ${CURRENT} →`)
    expect(out).toContain('assurance=recovery_verified source=network')
  })

  it('exits 0 when nothing superseded', async () => {
    chain.mockResolvedValue(chainResult({ superseded: false, currentDid: ASKED, assurance: 'verified', hops: [] }))
    const { code, out } = await run(flags())
    expect(code).toBe(DID_EXIT.current)
    expect(out).toContain('superseded:  no')
    expect(out).toContain('hops:        0')
  })

  it('gives a broken chain its own exit code (3), not a generic failure', async () => {
    const { ConnectxError } = await import('@agentx/core')
    chain.mockRejectedValue(new ConnectxError('did_chain_broken', 'Chain from "x" does not verify: cycle'))
    const { code, err } = await run(flags())
    expect(code).toBe(DID_EXIT.chainBroken)
    expect(err).toContain('does not verify')
  })

  it('reports a broken chain as JSON on stderr under --json', async () => {
    const { ConnectxError } = await import('@agentx/core')
    chain.mockRejectedValue(new ConnectxError('did_chain_broken', 'nope'))
    const { code, err } = await run(flags({ json: true }))
    expect(code).toBe(DID_EXIT.chainBroken)
    expect(JSON.parse(err)).toMatchObject({ ok: false, code: 'did_chain_broken' })
  })

  it('passes the acceptance policy through and nothing else', async () => {
    chain.mockResolvedValue(chainResult())
    await run(flags({ 'accept-provider-asserted': true, 'report-low-assurance': true }))
    expect(chain).toHaveBeenCalledWith(ASKED, {
      allowedHosts: ['example.com'],
      acceptProviderAsserted: true,
      reportLowAssurance: true,
    })
  })

  it('emits the chain verbatim under --json', async () => {
    const result = chainResult()
    chain.mockResolvedValue(result)
    const { out } = await run(flags({ json: true }))
    expect(JSON.parse(out)).toEqual(result)
  })
})
