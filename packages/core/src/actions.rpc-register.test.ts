// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createConfig } from './config'
import { registerViaJsonRpc } from './actions'
import { anpCli } from './connectors/anpCli'
import { ConnectxError } from './errors'
import { verifyDidDocumentProof } from './crypto/dataIntegrity'
import type { AnpConnector } from './types'
import type { ParsedKey } from './keys/parse'
import type { DidServerService } from './did/discovery'

// The second registration contract: the DID server's OWN JSON-RPC `register`, where the
// proof is the submitted document's own DataIntegrityProof (§2.5.5) and the response may
// carry a failure at HTTP 200. Both of those are why `register` cannot serve this path:
// there is no RFC 9421 header for the server to check, and a 200 is not a success.

const host = 'localhost'
const path = ['user', 'tom']
const targetUri = 'http://127.0.0.1:8765/user-service/v1/did-auth/rpc'

/** The entry a server publishes for itself — carried verbatim, unknown members included. */
const service: DidServerService = {
  id: 'did:wba:localhost#anp-message',
  type: 'ANPMessageService',
  serviceEndpoint: 'http://127.0.0.1:8765/anp-im/rpc',
  serviceDid: 'did:wba:localhost',
  profiles: ['anp.direct.base.v1'],
  securityProfiles: ['transport-protected'],
  authSchemes: ['bearer', 'didwba'],
}

function ed25519Connector(opts: { service?: DidServerService[] } = {}): AnpConnector {
  const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
  return anpCli(key, { host, path, ...(opts.service ? { service: opts.service } : {}) })
}

interface Captured {
  url: string
  init: RequestInit
}

/** A transport that answers once and records the request it was given. */
function answering(status: number, body: string, contentType = 'application/json') {
  let captured: Captured | undefined
  const transport = async (url: string, init: RequestInit): Promise<Response> => {
    captured = { url, init }
    return new Response(body, { status, headers: { 'content-type': contentType } })
  }
  return { transport, captured: () => captured }
}

function jsonRpcResult(result: Record<string, unknown>): string {
  return JSON.stringify({ jsonrpc: '2.0', result, id: 'test' })
}

function jsonRpcError(code: number, message: string): string {
  return JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: 'test' })
}

describe('registerViaJsonRpc — posts the server its own contract', () => {
  it('POSTs a JSON-RPC register carrying this key’s signed document', async () => {
    const connector = ed25519Connector({ service: [service] })
    const config = createConfig([connector], connector.id)
    const identity = await connector.getIdentity()
    const { transport, captured } = answering(
      200,
      jsonRpcResult({ did: identity.did, handle: 'tom', token: 'tok', token_type: 'Bearer' }),
    )

    const outcome = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport })

    const c = captured()!
    expect(c.url).toBe(targetUri)
    expect(c.init.method).toBe('POST')
    expect((c.init.headers as Record<string, string>)['content-type']).toBe('application/json')
    const body = JSON.parse(c.init.body as string) as Record<string, unknown>
    expect(body.jsonrpc).toBe('2.0')
    expect(body.method).toBe('register')
    expect(body.params).toEqual({ handle: 'tom', did_document: identity.didDocument })
    // The document is the proof here: the server verifies it, not a signature header.
    expect(identity.didDocument.proof).toBeDefined()
    expect(verifyDidDocumentProof(identity.didDocument, { did: identity.did })).toBe(true)

    expect(outcome).toEqual({ did: identity.did, handle: 'tom', token: 'tok', tokenType: 'Bearer' })
  })

  it('signs over the injected service entry, so it cannot be added after the fact', async () => {
    const connector = ed25519Connector({ service: [service] })
    const config = createConfig([connector], connector.id)
    const identity = await connector.getIdentity()
    const { transport, captured } = answering(
      200,
      jsonRpcResult({ did: identity.did, handle: 'tom' }),
    )

    await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport })

    const sent = JSON.parse(captured()!.init.body as string) as {
      params: { did_document: Record<string, unknown> }
    }
    expect(sent.params.did_document.service).toEqual([service])
    // The document the server receives proves itself, and is bound to this DID's own
    // fingerprint — which is the check the server runs.
    expect(verifyDidDocumentProof(sent.params.did_document, { did: identity.did })).toBe(true)

    // An entry changed after signing is not covered by the proof, so it fails that same
    // check instead of reaching the server's own comparison.
    const tampered = {
      ...sent.params.did_document,
      service: [{ ...service, serviceEndpoint: 'http://attacker.test/anp-im/rpc' }],
    }
    expect(verifyDidDocumentProof(tampered, { did: identity.did })).toBe(false)
  })

  it('reports the server’s own handle when it confirms one', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(200, jsonRpcResult({ did: 'x', handle: 'Tom' }))
    const outcome = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport })
    expect(outcome.handle).toBe('Tom')
  })

  it('falls back to the requested handle only when the server confirms none', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(200, jsonRpcResult({ did: 'x' }))
    const outcome = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport })
    expect(outcome.handle).toBe('tom')
  })
})

describe('registerViaJsonRpc — a failure at HTTP 200 is a failure', () => {
  it('turns a JSON-RPC error body into register_failed with the server code', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(200, jsonRpcError(-32000, 'handle_already_registered'))

    const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
      (e: unknown) => e,
    )
    expect(err).toBeInstanceOf(ConnectxError)
    expect((err as ConnectxError).code).toBe('register_failed')
    expect((err as ConnectxError).status).toBe(200)
    expect((err as ConnectxError).serverCode).toBe('handle_already_registered')
  })

  it('reads error before result when a malformed body carries both', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(
      200,
      JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'did_document_proof_invalid' },
        result: { did: 'did:wba:localhost:user:tom:e1_nope', handle: 'tom' },
      }),
    )
    const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
      (e: unknown) => e,
    )
    expect((err as ConnectxError).serverCode).toBe('did_document_proof_invalid')
  })

  it('keeps a non-2xx without a JSON-RPC error a failed registration', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(500, JSON.stringify({ detail: 'boom' }))
    const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
      (e: unknown) => e,
    )
    expect((err as ConnectxError).code).toBe('register_failed')
    expect((err as ConnectxError).status).toBe(500)
    expect((err as ConnectxError).serverCode).toBeUndefined()
  })
})

describe('registerViaJsonRpc — a 2xx that is not an answer must not read as one', () => {
  // The mistake `--target` names: a site origin, or the application's login endpoint.
  // Every field of a registration outcome is optional, so without these checks a page
  // would be reported as a successful registration.
  const cases: { name: string; status: number; body: string; contentType: string }[] = [
    { name: 'a web page', status: 200, body: '<html></html>', contentType: 'text/html' },
    { name: 'plain text', status: 200, body: 'OK', contentType: 'text/plain' },
    { name: 'a JSON array', status: 200, body: '[]', contentType: 'application/json' },
    { name: 'a JSON null', status: 200, body: 'null', contentType: 'application/json' },
    { name: 'JSON without a result', status: 200, body: '{"jsonrpc":"2.0"}', contentType: 'application/json' },
  ]

  for (const c of cases) {
    it(`refuses ${c.name} with the status, so the CLI can name --target`, async () => {
      const connector = ed25519Connector()
      const config = createConfig([connector], connector.id)
      const { transport } = answering(c.status, c.body, c.contentType)
      const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
        (e: unknown) => e,
      )
      expect(err).toBeInstanceOf(ConnectxError)
      expect((err as ConnectxError).code).toBe('invalid_argument')
      expect((err as ConnectxError).status).toBe(200)
    })
  }

  it('refuses a result that names no DID', async () => {
    const connector = ed25519Connector()
    const config = createConfig([connector], connector.id)
    const { transport } = answering(200, jsonRpcResult({ handle: 'tom' }))
    const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
      (e: unknown) => e,
    )
    expect((err as ConnectxError).code).toBe('invalid_argument')
  })
})

describe('registerViaJsonRpc — Ed25519 only', () => {
  it('refuses a secp256k1 identity before sending anything', async () => {
    const key: ParsedKey = {
      privateKey: new Uint8Array(Array.from({ length: 32 }, () => 0x22)),
      curve: 'secp256k1',
    }
    const connector = anpCli(key, { host, path })
    const config = createConfig([connector], connector.id)
    let sent = false
    const transport = async (): Promise<Response> => {
      sent = true
      return new Response('{}', { status: 200 })
    }

    const err = await registerViaJsonRpc(config, { handle: 'tom', targetUri, transport }).catch(
      (e: unknown) => e,
    )
    expect((err as ConnectxError).code).toBe('invalid_argument')
    expect((err as ConnectxError).message).toContain('Ed25519')
    expect(sent).toBe(false)
  })
})
