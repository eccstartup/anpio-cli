import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { runDidStore } from './auth'
import { initIdentity } from '../identity/store'
import { storeLocation } from '../identity/paths'
import type { Values } from './auth'

// `did register --rpc` composes the identity under the domain the DID server publishes
// for ITSELF, which is a fact that server can state and this side must not invent. The
// PORT is the one part of it that document does not have to repeat: a server reached at
// `127.0.0.1:8765` publishes as `did:wba:localhost`, because the port it is reached
// through is a deployment detail no self-description can see — while `did:wba` spells a
// non-default port inside the host segment (ANP-03 §2.1), making
// `did:wba:localhost%3A8765:users:alice:e1_x` and `did:wba:localhost:users:alice:e1_x`
// two DIFFERENT identities. So `--target`'s port is merged in, and what goes on the wire
// is the DID the server can actually host. The regression pinned here is that port being
// dropped — the registration then names an identity the server never stored, and its
// own resolution of that DID answers 404.

let server: ReturnType<typeof createServer>
let port = 0
/** The DID the server publishes for itself. A bare domain by default — the shape a
 *  deployment has when the port it is reached through is not in its own identity. */
let publishedId = ''
/** Every JSON-RPC body the register endpoint received, in order. */
let received: Record<string, unknown>[] = []
/** Whether the server also serves the document it holds for the registered DID. Off by
 *  default: most of this file is about what goes ON THE WIRE, and a served document would
 *  add a second call to those runs. */
let serveOwnDocument = false

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.method === 'POST') {
      let raw = ''
      req.on('data', (chunk) => {
        raw += chunk
      })
      req.on('end', () => {
        const body = JSON.parse(raw) as Record<string, unknown>
        received.push(body)
        const params = (body.params ?? {}) as { handle?: string; did_document?: { id?: string } }
        // The server confirms the DID it was sent — a stub that answered with a DID of
        // its own choosing would hide exactly the composition this file is about.
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: body.id,
            result: { did: params.did_document?.id, handle: params.handle },
          }),
        )
      })
      return
    }
    if (req.url?.startsWith('/.well-known/did.json')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(
        JSON.stringify({
          id: publishedId,
          service: [
            {
              id: `${publishedId}#anp`,
              type: 'ANPMessageService',
              serviceEndpoint: `http://127.0.0.1:${port}/anp-im/rpc`,
              serviceDid: publishedId,
            },
          ],
        }),
      )
      return
    }
    // The document on file, for the runs that need a server that holds one: what the
    // server stores is what was submitted to it, which is also how the far side can
    // serve a document that proves itself under the DID it was registered as.
    if (serveOwnDocument && req.url?.endsWith('/did.json') === true) {
      const onFile = (received[0]?.params as { did_document?: unknown } | undefined)?.did_document
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(onFile ?? {}))
      return
    }
    // Anything else (the document copy the command tries to keep) is simply not served.
    res.writeHead(404, { 'content-type': 'application/json' })
    res.end('{"error":"not_found"}')
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()))
})

let home = ''
let savedHome: string | undefined
let savedAgent: string | undefined

beforeEach(async () => {
  received = []
  serveOwnDocument = false
  publishedId = 'did:wba:127.0.0.1'
  home = mkdtempSync(join(tmpdir(), 'connectx-register-unit-'))
  savedHome = process.env.CONNECTX_HOME
  savedAgent = process.env.CONNECTX_AGENT
  process.env.CONNECTX_HOME = home
  // Declared rather than detected: the ambient environment may carry another agent's
  // markers, which would put the identity somewhere other than where the test looks.
  process.env.CONNECTX_AGENT = 'default'
  await initIdentity({
    location: storeLocation('default', 'default'),
    curve: 'ed25519',
    password: '',
    force: false,
  })
})

afterEach(() => {
  if (savedHome === undefined) delete process.env.CONNECTX_HOME
  else process.env.CONNECTX_HOME = savedHome
  if (savedAgent === undefined) delete process.env.CONNECTX_AGENT
  else process.env.CONNECTX_AGENT = savedAgent
  rmSync(home, { recursive: true, force: true })
})

function flags(over: Record<string, unknown> = {}): Values {
  return {
    target: `http://127.0.0.1:${port}/user-service/v1/did-auth/rpc`,
    handle: 'alice',
    rpc: true,
    ...over,
  } as unknown as Values
}

async function run(values: Values) {
  const out: string[] = []
  const err: string[] = []
  const log = vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')))
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')))
  try {
    await runDidStore(values, 'register')
    return { out: out.join('\n'), err: err.join('\n') }
  } finally {
    log.mockRestore()
    errSpy.mockRestore()
  }
}

/** The document that was sent for registration — the only place the composed DID is
 *  visible as the server will read it. */
function sentDocument(): { id: string; service: { serviceEndpoint?: string }[] } {
  const body = received[0] as { params?: { did_document?: unknown } }
  return body.params?.did_document as { id: string; service: { serviceEndpoint?: string }[] }
}

describe('did register --rpc — the DID carries the port it is registered at', () => {
  it('merges the port --target names into the domain the server publishes', async () => {
    const { out } = await run(flags())
    const document = sentDocument()
    // `%3A<port>` in the host segment, then this agent's path and the key fingerprint.
    expect(document.id).toMatch(new RegExp(`^did:wba:127\\.0\\.0\\.1%3A${port}:user:default:e1_`))
    // The service entry the server published rides along: it is what the server checks
    // the submitted document against, so dropping it would be refused on the far side.
    expect(document.service[0]?.serviceEndpoint).toBe(`http://127.0.0.1:${port}/anp-im/rpc`)
    // Printed is what was registered — a DID the operator can paste into `did resolve`.
    expect(out).toContain(`did:      ${document.id}`)
  })

  it('does not append a port the published domain already spells', async () => {
    // A server that DOES name its own port publishes the same host segment this side
    // would compose, and appending again would read as a second `%3A<port>` — a DID the
    // server never published, from a domain it did.
    publishedId = `did:wba:127.0.0.1%3A${port}`
    await run(flags())
    expect(received).toHaveLength(1)
    const id = sentDocument().id
    expect(id.startsWith(`did:wba:127.0.0.1%3A${port}:user:default:e1_`)).toBe(true)
    // One encoded port, not two: a second `%3A` is the doubling this pins.
    expect(id.match(/%3A/g)).toHaveLength(1)
  })

  it('refuses a --host that contradicts the published domain, before sending anything', async () => {
    // Naming a host the server does not serve would compose a DID under a domain it
    // would reject as foreign — and the refusal has to come from here, because the
    // request it would otherwise send is a registration this side cannot take back.
    await expect(run(flags({ host: 'other.test' }))).rejects.toThrow(/contradicts/)
    expect(received).toHaveLength(0)
  })
})

describe('did register — the document on file is kept for a loopback host', () => {
  it('records a copy with no relaxation flag, because a loopback name is the whole confirmation', async () => {
    // This is the deployment ADR-0003 left open, reproduced: the server publishes
    // `did:wba:127.0.0.1` with NO port of its own (the default `publishedId`) while the
    // instance is reached at `127.0.0.1:<port>`. The composed DID therefore carries a
    // port its own self-description never mentions, and the document that DID points at
    // is served at `http://127.0.0.1:<port>/…/did.json` — which is only reachable because
    // a loopback spelling unlocks the private-address and plain-http gates by itself.
    // This command takes no host flag, and needs none.
    //
    // The copy it keeps is the base the NEXT `did update` retires (§2.5.3 L417), so a
    // registration that could not fetch it would start that update from a composed
    // document.
    serveOwnDocument = true
    const { out } = await run(flags({ json: true }))
    const payload = JSON.parse(out) as { local: { documentOnFile: boolean } }
    expect(payload.local.documentOnFile).toBe(true)
  })
})
