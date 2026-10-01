// @vitest-environment node
import { describe, it, expect, vi } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createConfig } from './config'
import { update } from './actions'
import { anpCli } from './connectors/anpCli'
import { ConnectxError } from './errors'
import { resolveVerificationKey } from './crypto/resolveDid'
import { verifyHttpMessageSignature } from './crypto/verify'
import { verifyDidDocumentProof } from './crypto/dataIntegrity'
import { verifyDidDocumentProofWithKey } from './advanced'
import type { AnpConnector, SignRequest, SignResult } from './types'
import type { ParsedKey } from './keys/parse'

// A update hop is TWO documents in ONE signed request, and each half has to be
// provable on its own terms:
//   - the retirement document by the key the RETIRING DID binds (§2.5.5 — the proof
//     covers the whole document, so `deactivated` / `successorDid` cannot be added or
//     rewritten by whoever forwards it),
//   - the successor document by its OWN key, which this SDK never holds.
// Plus the invariants that make it a hop rather than a hand-off: same stable subject
// path, and a successor that actually proves itself.

const host = 'did.example.com'
const targetUri = `https://${host}/api/did/update`
const path = ['user', 'alice']

async function retiredKey(): Promise<{ key: ParsedKey; connector: AnpConnector }> {
  const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
  return { key, connector: anpCli(key, { host, path }) }
}

/** A successor: a fresh key under the SAME host + path, so only the fingerprint moves. */
async function successor(opts: { host?: string; path?: string[] } = {}) {
  const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
  const connector = anpCli(key, { host: opts.host ?? host, path: opts.path ?? path })
  return { key, connector, identity: await connector.getIdentity() }
}

function capturedTransport(status = 200) {
  let captured: { url: string; init: RequestInit } | undefined
  const transport = async (url: string, init: RequestInit): Promise<Response> => {
    captured = { url, init }
    return new Response(JSON.stringify({ ok: true }), { status })
  }
  return { transport, captured: () => captured }
}

function bodyOf(captured: { init: RequestInit }): Record<string, unknown> {
  return JSON.parse(captured.init.body as string) as Record<string, unknown>
}

function signedRequestInput(captured: { url: string; init: RequestInit }) {
  const url = new URL(captured.url)
  return {
    method: 'POST',
    path: url.pathname,
    authority: url.host,
    targetUri: captured.url,
    headers: (captured.init.headers ?? {}) as Record<string, string>,
    body: captured.init.body as string,
  }
}

describe('update — one hop, delivered as a signed ANP-02 request', () => {
  it('retires the old DID and carries the successor in the same body', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()

    const older = await connector.getIdentity()
    const outcome = await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    expect(outcome).toEqual({ did: older.did, successorDid: next.did })
    const body = bodyOf(captured()!)
    expect(body.did).toBe(older.did)
    expect(body.successorDid).toBe(next.did)
    expect(body.successorDocument).toEqual(next.didDocument)
    expect(body.nonce).toBe('n1')
  })

  it('sends the OLD document marked deactivated and pointing at the successor', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()
    const older = await connector.getIdentity()

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    const document = bodyOf(captured()!).didDocument as Record<string, unknown>
    expect(document.id).toBe(older.did)
    expect(document.deactivated).toBe(true)
    expect(document.successorDid).toBe(next.did)
    // Not a new document — the SAME one, still keyed and controlled by the retired DID.
    expect(document.verificationMethod).toEqual(older.didDocument.verificationMethod)
    expect(document.authentication).toEqual(older.didDocument.authentication)
  })

  it('bases the retirement document on the document ON FILE, keeping what the builder cannot produce', async () => {
    // The fix this covers: composing a fresh base means every field the builder has no
    // flag for (here a `service` endpoint — what a site publishes `ad.json` through) is
    // silently dropped, so the retirement document differs from the one on file. §2.5.3
    // L417 says the OLD DOCUMENT gets `deactivated` + `successorDid`; L419 says the
    // re-made proof covers the properties it carries.
    const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
    const composed = await anpCli(key, { host, path }).getIdentity()
    const onFile = {
      ...composed.didDocument,
      service: [
        { id: `${composed.did}#ad`, type: 'AgentDescription', serviceEndpoint: `https://${host}/ad.json` },
      ],
    }
    const connector = anpCli(key, { host, path, baseDocument: onFile })
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    const document = bodyOf(captured()!).didDocument as Record<string, unknown>
    expect(document.service).toEqual(onFile.service)
    expect(document.deactivated).toBe(true)
    expect(document.successorDid).toBe(next.did)
    // The re-made proof covers the whole document, `service` included — a hop whose
    // retirement half no verifier can check would be worse than one that dropped a field.
    expect(verifyDidDocumentProof(document, { did: composed.did })).toBe(true)
  })

  it('re-signs the retirement document: the proof covers deactivated/successorDid', async () => {
    const { connector } = await retiredKey()
    const { key: nextKey, identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()
    const older = await connector.getIdentity()

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    const document = bodyOf(captured()!).didDocument as Record<string, unknown>
    // Verified against the identifier too: the last path segment commits to the key, so
    // this rejects a retirement document signed by anyone else.
    expect(verifyDidDocumentProof(document, { did: older.did })).toBe(true)
    // The successor's key does NOT verify the retirement document — the hop is
    // authorised by the key being retired, not by the key that takes over.
    expect(verifyDidDocumentProofWithKey(document, ed25519.getPublicKey(nextKey.privateKey))).toBe(false)
    // The carried-over proof would have been a lie; a fresh one cannot equal it.
    expect(document.proof).not.toEqual(older.didDocument.proof)
  })

  it('the request signature verifies over the succession-bearing body', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()
    const older = await connector.getIdentity()

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    const c = captured()!
    const key = await resolveVerificationKey(older.keyid, older.didDocument)
    expect(await verifyHttpMessageSignature({ ...signedRequestInput(c), key })).toBe(true)
  })

  it('rejects a body whose successor was swapped after signing', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport, captured } = capturedTransport()
    const older = await connector.getIdentity()

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'n1',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    const c = captured()!
    const key = await resolveVerificationKey(older.keyid, older.didDocument)
    const tampered = { ...c, init: { ...c.init, body: JSON.stringify({ ...bodyOf(c), successorDid: 'did:wba:evil.example:user:alice:e1_zzz' }) } }
    expect(await verifyHttpMessageSignature({ ...signedRequestInput(tampered), key })).toBe(false)
  })

  it('re-signs on a 401 challenge WITHOUT dropping the successor', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    let call = 0
    const bodies: Record<string, unknown>[] = []
    const transport = async (_url: string, init: RequestInit): Promise<Response> => {
      call += 1
      bodies.push(JSON.parse(init.body as string) as Record<string, unknown>)
      if (call === 1) {
        return new Response(JSON.stringify({}), {
          status: 401,
          headers: { 'www-authenticate': 'didwba nonce="fresh"' },
        })
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    }

    await update(config, {
      connectorId: connector.id,
      targetUri,
      nonce: 'stale',
      successorDid: next.did,
      successorDocument: next.didDocument,
      transport,
    })

    expect(call).toBe(2)
    expect(bodies[0].successorDid).toBe(next.did)
    expect(bodies[1].successorDid).toBe(next.did)
    expect(bodies[1].nonce).toBe('fresh')
  })

  it('maps a non-2xx to update_failed, keeping the server’s own code', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const transport = async (): Promise<Response> =>
      new Response(JSON.stringify({ code: 'not_supported', error: 'not_supported' }), { status: 501 })

    await expect(
      update(config, {
        connectorId: connector.id,
        targetUri,
        nonce: 'n1',
        successorDid: next.did,
        successorDocument: next.didDocument,
        transport,
      }),
    ).rejects.toMatchObject({ code: 'update_failed', status: 501, serverCode: 'not_supported' })
  })
})

describe('update — refuses a hop that is not one', () => {
  const base = { targetUri, nonce: 'n1' }

  it('refuses a successor on a different stable subject path (2.5.3)', async () => {
    const { connector } = await retiredKey()
    const { identity: elsewhere } = await successor({ path: ['user', 'bob'] })
    const config = createConfig([connector], connector.id)
    const { transport } = capturedTransport()

    await expect(
      update(config, { ...base, connectorId: connector.id, successorDid: elsewhere.did, successorDocument: elsewhere.didDocument, transport }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('refuses a successor on a different host', async () => {
    const { connector } = await retiredKey()
    const { identity: elsewhere } = await successor({ host: 'other.example.com' })
    const config = createConfig([connector], connector.id)
    const { transport } = capturedTransport()

    await expect(
      update(config, { ...base, connectorId: connector.id, successorDid: elsewhere.did, successorDocument: elsewhere.didDocument, transport }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('refuses a successor whose active document carries no proof (2.5.3)', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport } = capturedTransport()
    const { proof: _drop, ...unsigned } = next.didDocument

    await expect(
      update(config, { ...base, connectorId: connector.id, successorDid: next.did, successorDocument: unsigned, transport }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('refuses to retire an unsigned document (a k1_ identity)', async () => {
    const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'secp256k1' }
    const connector = anpCli(key, { host, path })
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport } = capturedTransport()
    const identity = await connector.getIdentity()
    expect(identity.did).toContain(':k1_')
    expect(identity.didDocument.proof).toBeUndefined()

    await expect(
      update(config, { ...base, connectorId: connector.id, successorDid: next.did, successorDocument: next.didDocument, transport }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('refuses a CAIP-10 identity, which has no stable subject path to keep', async () => {
    const key: ParsedKey = { privateKey: ed25519.utils.randomSecretKey(), curve: 'ed25519' }
    const connector = anpCli(key, { host, chainId: 'eip155:1', address: '0x0000000000000000000000000000000000000001' })
    const { identity: next } = await successor()
    const config = createConfig([connector], connector.id)
    const { transport } = capturedTransport()
    const identity = await connector.getIdentity()
    expect(identity.did).toBe('eip155:1:0x0000000000000000000000000000000000000001')
    // The document IS signed (ed25519), so this exits through the subject-path branch.
    expect(identity.didDocument.proof).toBeDefined()

    await expect(
      update(config, { ...base, connectorId: connector.id, successorDid: next.did, successorDocument: next.didDocument, transport }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })
  })

  it('refuses to deliver at all when the connector drops the successor', async () => {
    const { connector } = await retiredKey()
    const { identity: next } = await successor()
    const older = await connector.getIdentity()
    // A connector that builds its own body and ignores what it does not understand —
    // the browser-extension shape. Sending this as a "update" would deliver a bare
    // login body, so the pipeline must refuse BEFORE the POST.
    const deaf: AnpConnector = {
      id: 'deaf',
      name: 'deaf',
      type: 'anp-extension',
      isAvailable: () => Promise.resolve(true),
      getIdentity: () => Promise.resolve(older),
      signRequest: async (req: SignRequest): Promise<SignResult> => ({
        did: older.did,
        keyid: older.keyid,
        didDocument: older.didDocument,
        body: JSON.stringify({ nonce: req.nonce, did: older.did }),
        headers: { 'content-type': 'application/json', signature: 'sig1=::' },
      }),
    }
    const transport = vi.fn(async () => new Response('{}', { status: 200 }))

    await expect(
      update(createConfig([deaf]), {
        ...base,
        connectorId: 'deaf',
        successorDid: next.did,
        successorDocument: next.didDocument,
        transport,
      }),
    ).rejects.toBeInstanceOf(ConnectxError)
    expect(transport).not.toHaveBeenCalled()
  })
})

describe('the successor is a different credential for the SAME subject', () => {
  it('moves the fingerprint and nothing else', async () => {
    const { connector } = await retiredKey()
    const older = await connector.getIdentity()
    const { identity: next } = await successor()

    expect(next.did).not.toBe(older.did)
    // Only the fingerprint segment moved — the DID stays on the same host + path, which
    // is what §2.5.3 requires and what lets the server treat it as the same account.
    expect(older.did.startsWith('did:wba:did.example.com:user:alice:e1_')).toBe(true)
    expect(next.did.startsWith('did:wba:did.example.com:user:alice:e1_')).toBe(true)
    expect(next.subject).toBe(older.subject)
    expect(next.keyid).not.toBe(older.keyid)
  })
})
