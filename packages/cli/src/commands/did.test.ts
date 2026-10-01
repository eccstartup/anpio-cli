import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { anpCli } from '@agentx/core'
import { DID_EXIT, registerCommandHint, runDid } from './did'
import { storeLocation } from '../identity/paths'
import { generateSuccessorKey, initIdentity, loadStoredKey, readDidDocumentCopy, recordRegistration, stageSuccessorKey, writeDidDocumentCopy } from '../identity/store'
import type { Values } from './auth'

// The command is driven end to end against a real loopback http server, through the
// allowlist an operator would have to pass — so this file also pins the fact that
// `did resolve` has no shortcut around the SDK's network policy.

const DOC = { verificationMethod: [], authentication: [] }

let server: ReturnType<typeof createServer>
let port = 0
let did = ''
let served: () => Record<string, unknown> = () => ({ id: did, ...DOC })
/** The status the next GET of a document answers with — 404 is how a host that publishes
 *  nothing is simulated. */
let docStatus = 200
/** How many times a document was FETCHED (a POST delivery is not a fetch). */
let docFetches = 0
/** Every POST body the server received, in order — the delivery half of `did update`. */
let received: Record<string, unknown>[] = []

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.method === 'POST') {
      let raw = ''
      req.on('data', (chunk) => {
        raw += chunk
      })
      req.on('end', () => {
        received.push(JSON.parse(raw) as Record<string, unknown>)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true }))
      })
      return
    }
    docFetches += 1
    res.writeHead(docStatus, { 'content-type': 'application/json' })
    res.end(docStatus === 200 ? JSON.stringify(served()) : JSON.stringify({ error: 'not_found' }))
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
  did = `did:web:127.0.0.1%3A${port}`
})

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()))
})

// `served` is mutable so a test can decide what the host publishes; reset it so one
// test's document cannot leak into the next.
beforeEach(() => {
  served = () => ({ id: did, ...DOC })
  docStatus = 200
  docFetches = 0
  received = []
})

/** The flags that make a loopback http DID reachable, as an operator would type them.
 *  One flag: a loopback name is admitted on its own, private and plain http included. */
function localFlags(over: Record<string, unknown> = {}): Values {
  return { 'allow-host': ['127.0.0.1'], ...over } as unknown as Values
}

/** Run the command and capture what it printed on each stream. */
async function run(flags: Values, sub?: string, arg?: string) {
  const out: string[] = []
  const err: string[] = []
  const log = vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')))
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')))
  try {
    const code = await runDid(flags, sub ?? 'resolve', arg ?? did)
    return { code, out: out.join('\n'), err: err.join('\n') }
  } finally {
    log.mockRestore()
    errSpy.mockRestore()
  }
}

describe('did resolve — one document', () => {
  it('resolves and reports the DID as current (exit 0)', async () => {
    served = () => ({ id: did, ...DOC })
    const { code, out } = await run(localFlags())
    expect(code).toBe(DID_EXIT.current)
    expect(out).toContain(`docUrl:   http://127.0.0.1:${port}/.well-known/did.json`)
    expect(out).toContain('source:   network')
    expect(out).toContain('status:   current')
  })

  it('reports a retirement as "not current" instead of hiding it (exit 2)', async () => {
    // `resolveDidDocument` returns a superseded document on purpose, so the CLI is the
    // layer that has to say so — and its exit code is the machine-readable half.
    served = () => ({ id: did, ...DOC, deactivated: true, successorDid: 'did:web:127.0.0.1%3A9:user:alice' })
    const { code, out } = await run(localFlags())
    expect(code).toBe(DID_EXIT.superseded)
    expect(out).toContain('SUPERSEDED')
  })

  it('carries the same conclusion in --json', async () => {
    served = () => ({ id: did, ...DOC, deactivated: true })
    const { code, out } = await run(localFlags({ json: true }))
    expect(code).toBe(DID_EXIT.superseded)
    const payload = JSON.parse(out)
    expect(payload.superseded).toBe(true)
    expect(payload.docUrl).toBe(`http://127.0.0.1:${port}/.well-known/did.json`)
  })
})

/** The two steps an operator runs, minus the network: `did create` seals a key, then
 *  `did register` records the host the DID server confirmed. The DID is composed the
 *  same way the connector composes it at request time, so `lastDid` is exactly what the
 *  CLI re-derives later — which is what the update path checks it against. */
async function createAndRegister(location: ReturnType<typeof storeLocation>, host: string) {
  await initIdentity({ location, curve: 'ed25519', password: '', force: false })
  const parsed = await loadStoredKey(location, '')
  const identity = await anpCli(parsed, { host, path: ['user', location.agent] }).getIdentity()
  recordRegistration({ location, host, did: identity.did })
  return identity
}

describe('did resolve — arguments', () => {
  it('refuses to resolve without an explicit allowlist (exit 1)', async () => {
    const { code, err } = await run({})
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('--allow-host')
  })

  it('rejects an allowlist entry carrying a port', async () => {
    // It would never match (the SDK compares hostnames), and "not in the allowed hosts
    // list" would send the operator looking in the wrong place.
    const { code, err } = await run(localFlags({ 'allow-host': [`127.0.0.1:${port}`] }))
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('WITHOUT a port')
  })

  it('accepts a comma-separated list as well as a repeated flag', async () => {
    const { code } = await run(localFlags({ 'allow-host': ['localhost,127.0.0.1'] }))
    expect(code).toBe(DID_EXIT.current)
  })

  it('rejects a host that is not the one allowlisted', async () => {
    const { code, err } = await run(localFlags({ 'allow-host': ['example.com'] }))
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('not in the allowed hosts list')
  })

  // A host that is local WITHOUT being spelled that way: it resolves inward, so the
  // address gate refuses it and `--allow-private-host` is the one remedy. Loopback names
  // never reach this gate — `--allow-host localhost` admits those on its own, which is
  // what the two tests below this pair pin down.
  const privateDid = 'did:web:192.168.1.5%3A8080'

  it('names the flag that lifts a private-address refusal', async () => {
    const { code, err } = await run({ 'allow-host': ['192.168.1.5'] } as unknown as Values, 'resolve', privateDid)
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('private/loopback')
    // The operator's own host, not a placeholder: they must be able to paste it.
    expect(err).toContain('--allow-private-host 192.168.1.5')
  })

  it('offers no private-host hint when the host is merely not allowlisted', async () => {
    // That message already names the host, and `--allow-host` is the flag they found.
    // Pointing at the other gate would send them to fix the wrong thing.
    const { err } = await run({ 'allow-host': ['example.com'] } as unknown as Values)
    expect(err).not.toContain('--allow-private-host')
  })

  it('keeps the hint off the --json stream, which must stay parseable', async () => {
    const { code, out, err } = await run(
      { 'allow-host': ['192.168.1.5'], json: true } as unknown as Values,
      'resolve',
      privateDid,
    )
    expect(code).toBe(DID_EXIT.error)
    expect(out).toBe('')
    expect(JSON.parse(err)).toMatchObject({ ok: false, code: 'did_resolve_blocked' })
  })

  it('rejects the chain-only acceptance flags without --chain', async () => {
    const { code, err } = await run(localFlags({ 'report-low-assurance': true }))
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('only apply to --chain')
  })

  it('rejects a missing DID and an unknown subcommand', async () => {
    expect((await run(localFlags(), 'resolve', '')).code).toBe(DID_EXIT.error)
    expect((await run(localFlags(), 'publish')).err).toContain('Unknown "did" subcommand')
  })

  it('emits a machine-readable failure on stderr under --json', async () => {
    const { code, out, err } = await run({ json: true })
    expect(code).toBe(DID_EXIT.error)
    expect(out).toBe('')
    expect(JSON.parse(err)).toMatchObject({ ok: false, code: 'did_resolve_blocked' })
  })
})

// The delivery half of `did update` is verified end to end in
// `scripts/did-cli-e2e.mjs`, where a peer can check the hop and the store can be
// inspected afterwards. What is worth pinning HERE is the set of refusals that must
// happen before anything is sent — they are the reason a mistyped invocation cannot
// update the wrong identity or half-perform an update.
describe('did update — refusals with no delivery', () => {
  let home = ''
  let savedHome: string | undefined
  let savedAgent: string | undefined

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'connectx-update-unit-'))
    savedHome = process.env.CONNECTX_HOME
    savedAgent = process.env.CONNECTX_AGENT
    process.env.CONNECTX_HOME = home
    // Declared rather than detected: the ambient environment may carry another agent's
    // markers, which would put the identity somewhere other than where the test looks.
    process.env.CONNECTX_AGENT = 'default'
  })

  afterEach(() => {
    if (savedHome === undefined) delete process.env.CONNECTX_HOME
    else process.env.CONNECTX_HOME = savedHome
    if (savedAgent === undefined) delete process.env.CONNECTX_AGENT
    else process.env.CONNECTX_AGENT = savedAgent
    rmSync(home, { recursive: true, force: true })
  })

  const location = () => storeLocation('default', 'default')

  it('requires --target — nothing else can name an update endpoint (ANP-03 §2.5.3)', async () => {
    const { code, err } = await run({}, 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('--target')
  })

  it('refuses when there is no identity on file to update', async () => {
    const { code, err } = await run({ target: 'http://127.0.0.1:1/update' }, 'update')
    expect(code).toBe(DID_EXIT.error)
    // Text mode prints the message, not the code (the code is carried by --json), so the
    // assertion is on what the operator actually reads.
    expect(err).toContain('No identity for agent')
    expect(err).toContain('connectx did create')
  })

  it('refuses an identity that has only been created: there is no DID to retire yet', async () => {
    // `did create` leaves an unregistered key, and an unregistered key has no host — so
    // there is no DID, and an update has nothing to replace. Caught here rather than by
    // the server, which would have been sent a hop about an identifier it never hosted.
    await initIdentity({ location: location(), curve: 'ed25519', password: '', force: false })

    const { code, err } = await run({ target: 'http://127.0.0.1:1/update' }, 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('not registered on a DID server')
    expect(err).toContain('connectx did register')
    // The hint has to be runnable as printed: it names the identity the operator is
    // looking at, and the contract a DID server's own register endpoint serves.
    expect(err).toContain('--agent default')
    expect(err).toContain('--rpc')
    expect(existsSync(join(location().dir, 'key.next'))).toBe(false)
  })

  /** The hint is the one place a failed command says where to go next, so the copy-paste
   *  it prints must address the SAME identity the reader was looking at. Only the flags
   *  whose value is a fact here are printed: the agent, and a profile that is not the
   *  store's default. */
  describe('registerCommandHint', () => {
    it('names the agent, and omits the default profile', () => {
      expect(registerCommandHint(storeLocation('alice', 'default'))).toContain('--agent alice --target')
      expect(registerCommandHint(storeLocation('alice', 'default'))).not.toContain('--profile')
    })

    it('carries a non-default profile, so the hint cannot address another identity', () => {
      expect(registerCommandHint(storeLocation('alice', 'work'))).toContain('--agent alice --profile work')
    })
  })

  it('refuses a store whose convention would move the subject, before signing anything', async () => {
    // A sidecar whose recorded host disagrees with the one it was registered on. Re-deriving
    // the retiring DID here would name an identity this key never had, so the hop must not
    // be attempted at all — the point is that this is caught locally rather than by the
    // server refusing it.
    await createAndRegister(location(), 'did.example.com')
    const sidecar = JSON.parse(readFileSync(location().identityFile, 'utf8'))
    const drifted = { ...sidecar, host: 'elsewhere.example.com' }
    writeFileSync(location().identityFile, JSON.stringify(drifted, null, 2) + '\n')

    const { code, err } = await run({ target: 'http://127.0.0.1:1/update' }, 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('does not follow this CLI')
    // Nothing was staged either: a refusal that leaves a key behind would be a half-run.
    expect(existsSync(join(location().dir, 'key.next'))).toBe(false)
  })
})

// `--resume` settles a delivery whose outcome nobody could observe. Its ONE job is to ask
// the DID server rather than guess, so the branches that matter here are the ones where
// the answer says "do not promote". The branch that DOES promote (the server serves the
// staged successor) needs a hop the server accepted, so it lives in
// `scripts/did-cli-e2e.mjs`, alongside the third-DID branch — both need a peer that
// published a real transition.
describe('did update --resume — settling a staged successor', () => {
  let home = ''
  let savedHome: string | undefined
  let savedAgent: string | undefined

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'connectx-resume-unit-'))
    savedHome = process.env.CONNECTX_HOME
    savedAgent = process.env.CONNECTX_AGENT
    process.env.CONNECTX_HOME = home
    process.env.CONNECTX_AGENT = 'default'
  })

  afterEach(() => {
    if (savedHome === undefined) delete process.env.CONNECTX_HOME
    else process.env.CONNECTX_HOME = savedHome
    if (savedAgent === undefined) delete process.env.CONNECTX_AGENT
    else process.env.CONNECTX_AGENT = savedAgent
    rmSync(home, { recursive: true, force: true })
  })

  const location = () => storeLocation('default', 'default')

  /** An identity whose host IS the loopback server, so its own DID is what gets fetched.
   *  Registered, because `--resume` reads the host the DID server recorded — the two steps
   *  `did create` and `did register` drive the same store calls an operator's commands do. */
  async function localIdentity() {
    return await createAndRegister(location(), `127.0.0.1%3A${port}`)
  }

  const stage = (curve: 'ed25519' | 'secp256k1' = 'ed25519') =>
    stageSuccessorKey({ location: location(), password: '', privateKey: generateSuccessorKey(curve).privateKey })

  // No host flags: the identity is registered on the loopback server, and `--resume`
  // derives that host from the store, so the loopback rule admits it unaided.
  const resumeFlags = (over: Record<string, unknown> = {}): Values =>
    ({ resume: true, ...over }) as unknown as Values

  it('refuses --target: settling a delivery is not making one', async () => {
    const { code, err } = await run(resumeFlags({ target: 'http://127.0.0.1:1/update' }), 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('takes no --target')
  })

  it('refuses when nothing was ever staged', async () => {
    await localIdentity()
    const { code, err } = await run(resumeFlags(), 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('Nothing to resume')
  })

  it('refuses when there is no identity on file', async () => {
    await stage()
    const { code, err } = await run(resumeFlags(), 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('No identity for agent')
  })

  it('drops the staged key when the server still serves the old DID as current', async () => {
    // The question --resume exists to answer, answered by the server's own document: it
    // still publishes this identity's DID, so the hop was never accepted. The staged key
    // then belongs to no identity, and keeping it would only make the next --resume ask
    // the same settled question again.
    const identity = await localIdentity()
    served = () => identity.didDocument as unknown as Record<string, unknown>
    await stage()

    const { code, err } = await run(resumeFlags(), 'update')
    expect(code).toBe(DID_EXIT.error)
    expect(err).toContain('NOT accepted')
    expect(err).toContain('has been dropped')
    expect(existsSync(join(location().dir, 'key.next'))).toBe(false)
  })
})

// The copy of the document the DID server has on file. Its whole reason to exist is the
// retirement half of an update: ANP-03 §2.5.3 L417 retires THE document on file (plus
// `deactivated` + `successorDid`), and L411 lets that document carry content this CLI
// cannot compose — so a composed base would retire a document the server never published.
// Everything here is driven through `runDid`, against the loopback host.
describe('the DID document as the server has it on file', () => {
  let home = ''
  let savedHome: string | undefined
  let savedAgent: string | undefined

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'connectx-copy-unit-'))
    savedHome = process.env.CONNECTX_HOME
    savedAgent = process.env.CONNECTX_AGENT
    process.env.CONNECTX_HOME = home
    process.env.CONNECTX_AGENT = 'default'
  })

  afterEach(() => {
    if (savedHome === undefined) delete process.env.CONNECTX_HOME
    else process.env.CONNECTX_HOME = savedHome
    if (savedAgent === undefined) delete process.env.CONNECTX_AGENT
    else process.env.CONNECTX_AGENT = savedAgent
    rmSync(home, { recursive: true, force: true })
  })

  const location = () => storeLocation('default', 'default')

  /** An identity whose host IS the loopback server, so its own DID is what gets fetched.
   *  Registered, because everything here runs past the point where a host exists. */
  async function localIdentity() {
    return await createAndRegister(location(), `127.0.0.1%3A${port}`)
  }

  /** What a DID server that also hosts an agent description would have on file for this
   *  identity: the SAME key, with a `service` entry the CLI has no way to compose on its
   *  own — and a proof that covers it, because a document's proof covers all of it
   *  (§2.5.3 L419). Built through the store's own key, so it is a document this identity
   *  really could have published. */
  async function documentOnFile() {
    const key = await loadStoredKey(location(), '')
    const at = { host: `127.0.0.1%3A${port}`, path: ['user', 'default'] }
    const composed = await anpCli(key, at).getIdentity()
    const image = await anpCli(key, {
      ...at,
      service: [
        { id: `${composed.did}#ad`, type: 'AgentDescription', serviceEndpoint: `http://127.0.0.1:${port}/ad.json` },
      ],
    }).getIdentity()
    return image.didDocument as unknown as Record<string, unknown>
  }

  const flags = (over: Record<string, unknown> = {}): Values =>
    ({ 'allow-host': ['127.0.0.1'], ...over }) as unknown as Values

  it('records what the host served, for this identity\'s own DID', async () => {
    const identity = await localIdentity()
    const onFile = await documentOnFile()
    served = () => onFile

    const { code } = await run(flags(), 'resolve', identity.did)
    expect(code).toBe(DID_EXIT.current)
    const copy = readDidDocumentCopy(location())
    expect(copy?.did).toBe(identity.did)
    expect(copy?.document).toEqual(onFile)
    expect(statSync(location().documentFile).mode & 0o777).toBe(0o600)
  })

  it('records nothing for a DID that is not this store\'s own', async () => {
    // One copy slot per identity, and it is reserved for the DID this store can actually
    // retire — recording every DID ever resolved would let an unrelated query evict it.
    await localIdentity()
    const { code } = await run(flags())
    expect(code).toBe(DID_EXIT.current)
    expect(existsSync(location().documentFile)).toBe(false)
  })

  it('reports drift and refreshes the copy when the host now serves something else', async () => {
    const identity = await localIdentity()
    const onFile = await documentOnFile()
    // A copy of an earlier state of the SAME DID — what a server-side edit looks like.
    writeDidDocumentCopy(location(), {
      did: identity.did,
      document: { ...onFile, service: [{ id: `${identity.did}#old`, type: 'AgentDescription' }] },
      fetchedAt: 1,
    })
    served = () => onFile

    const { err } = await run(flags(), 'resolve', identity.did)
    // On stderr, so a --json caller parsing stdout still sees only the document.
    expect(err).toContain('differs from what this DID now serves')
    expect(readDidDocumentCopy(location())?.document).toEqual(onFile)
  })

  it('stays quiet when the copy already matches', async () => {
    const identity = await localIdentity()
    const onFile = await documentOnFile()
    served = () => onFile
    writeDidDocumentCopy(location(), { did: identity.did, document: onFile, fetchedAt: 1 })

    const { err } = await run(flags(), 'resolve', identity.did)
    expect(err).toBe('')
  })

  it('bases the retirement hop on the copy — the field the builder cannot produce survives', async () => {
    // The hole this batch closes: a retirement document composed here dropped `service`,
    // so what the server was asked to retire was not what it had on file.
    const identity = await localIdentity()
    const onFile = await documentOnFile()
    writeDidDocumentCopy(location(), { did: identity.did, document: onFile, fetchedAt: Date.now() })

    const { code, err } = await run(flags({ target: `http://127.0.0.1:${port}/update` }), 'update')
    expect(code).toBe(DID_EXIT.current)
    expect(err).toBe('')
    // Not re-fetched: the copy is the point of keeping one.
    expect(docFetches).toBe(0)
    const delivered = received[0].didDocument as Record<string, unknown>
    expect(delivered.service).toEqual(onFile.service)
    expect(delivered.deactivated).toBe(true)
    expect(delivered.successorDid).toBe(received[0].successorDid)
    expect(delivered.id).toBe(identity.did)
    // Not the composed document, and not the copy untouched either: the SAME document,
    // marked retired. §2.5.3 L417.
    expect(delivered.verificationMethod).toEqual(onFile.verificationMethod)
  })

  it('resolves the document once when there is no copy, records it, and uses it', async () => {
    const identity = await localIdentity()
    const onFile = await documentOnFile()
    served = () => onFile

    const { code, err } = await run(flags({ target: `http://127.0.0.1:${port}/update` }), 'update')
    expect(code).toBe(DID_EXIT.current)
    expect(err).toBe('')
    expect(docFetches).toBe(1)
    expect((received[0].didDocument as Record<string, unknown>).service).toEqual(onFile.service)
    // The fetch it had to make anyway is left behind for the next one.
    expect(readDidDocumentCopy(location())?.document).toMatchObject({ service: onFile.service })
  })

  it('falls back to a composed document — visibly — when the host serves none', async () => {
    const identity = await localIdentity()
    docStatus = 404

    const { code, err } = await run(flags({ target: `http://127.0.0.1:${port}/update` }), 'update')
    expect(code).toBe(DID_EXIT.current)
    // The hop still happens (ANP-03 §2.5.3 L411 leaves the document's other content to
    // us), but the operator is told it may not be the one on file.
    expect(err).toContain('FALLING BACK')
    const delivered = received[0].didDocument as Record<string, unknown>
    expect(delivered.service).toBeUndefined()
    expect(delivered.verificationMethod).toEqual(identity.didDocument.verificationMethod)
    expect(delivered.deactivated).toBe(true)
    expect(existsSync(location().documentFile)).toBe(false)
  })
})
