import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createDidChainEdgeStore, resolveDidChain, type DidChainOptions } from './chain'
import { buildBaseDidDocument } from '../crypto/didDocument'
import { encodeMultibaseEd25519 } from '../crypto/multicodec'
import { didFingerprint } from '../crypto/fingerprint'
import { signDidDocumentProofSync } from '../crypto/dataIntegrity'
import { createDidDocumentStore, didToUrl } from '../crypto/resolveDid'

// A `did:wba` update is a chain of SAME-HOST, SAME-PATH DIDs: §2.5.3 rule 1
// requires the successor's stable subject path to be identical, and that path
// carries the domain (§2.2.3). So every fixture below puts the whole chain on
// `example.com` under one path, and changing only the KEY — which is what makes the
// DID change. The one test that crosses a host is the negative one.

interface Signer {
  priv: Uint8Array
  pub: Uint8Array
}

function newKey(): Signer {
  const priv = ed25519.utils.randomSecretKey()
  return { priv, pub: ed25519.getPublicKey(priv) }
}

function didFor(path: string, key: Signer, host = 'example.com'): string {
  return `did:wba:${host}:${path}:${didFingerprint('ed25519', key.pub)}`
}

/** How a fixture writes a DID URL: as the document spells it, or as the DID-spec
 *  relative `#fragment` that names the same method from inside that document. */
type Spell = (didUrl: string) => string

const absolute: Spell = (didUrl) => didUrl
const relative: Spell = (didUrl) => `#${didUrl.slice(didUrl.indexOf('#') + 1)}`

/** An ACTIVE `e1_` document, carrying the binding proof §2.5.5 makes mandatory. */
function activeDoc(did: string, key: Signer, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const keyid = `${did}#key-1`
  const doc: Record<string, unknown> = {
    ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(key.pub) }),
    ...extra,
  }
  doc.proof = signDidDocumentProofSync(doc, keyid, key.priv)
  return doc
}

/** A DEACTIVATED transition document pointing at its direct successor. `sign: false`
 *  leaves the proof off entirely, which §2.5.5 permits for this case. */
function transitionDoc(
  did: string,
  key: Signer,
  successorDid: string,
  opts: { sign?: boolean } = {},
): Record<string, unknown> {
  const keyid = `${did}#key-1`
  const doc: Record<string, unknown> = {
    ...buildBaseDidDocument({ did, keyid, publicKeyMultibase: encodeMultibaseEd25519(key.pub) }),
    deactivated: true,
    successorDid,
  }
  if (opts.sign !== false) doc.proof = signDidDocumentProofSync(doc, keyid, key.priv)
  return doc
}

/** Serve exactly these documents; anything else is a 404. */
function serve(docs: Map<string, Record<string, unknown>>) {
  return async (url: string): Promise<Response> => {
    const doc = docs.get(url)
    if (!doc) return new Response('not found', { status: 404 })
    return new Response(JSON.stringify(doc), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
}

const docUrl = didToUrl

function options(
  docs: Map<string, Record<string, unknown>>,
  extra: Omit<DidChainOptions, 'allowedHosts' | 'fetch' | 'allowUncontrolledFetch'> = {},
): DidChainOptions {
  return {
    allowedHosts: ['example.com'],
    resolveAddresses: async () => ['93.184.216.34'],
    allowUncontrolledFetch: true,
    fetch: serve(docs),
    ...extra,
  }
}

/** A 2-generation chain: `did1` (active, no) — one hop to `did2` (active). */
function oneHop(sign = true) {
  const k1 = newKey()
  const k2 = newKey()
  const did1 = didFor('user:alice', k1)
  const did2 = didFor('user:alice', k2)
  const docs = new Map<string, Record<string, unknown>>([
    [docUrl(did1), transitionDoc(did1, k1, did2, { sign })],
    [docUrl(did2), activeDoc(did2, k2)],
  ])
  return { k1, k2, did1, did2, docs }
}

describe('resolveDidChain — the happy paths', () => {
  it('reports a DID that has not superseded without inventing a chain', async () => {
    const k1 = newKey()
    const did1 = didFor('user:alice', k1)
    const docs = new Map([[docUrl(did1), activeDoc(did1, k1)]])

    const chain = await resolveDidChain(did1, options(docs))
    expect(chain.did).toBe(did1)
    expect(chain.currentDid).toBe(did1)
    expect(chain.superseded).toBe(false)
    expect(chain.hops).toEqual([])
    // No migration claim was made, so there is nothing to weaken. The document's own
    // integrity was the resolver's business — and for an ACTIVE e1_ DID it is mandatory.
    expect(chain.assurance).toBe('verified')
    expect(chain.stableSubjectId).toBe('example.com:user:alice')
    expect(chain.subject).toBe('did:wba:example.com:user:alice')
  })

  it('walks one update and returns the DID that is current now', async () => {
    const { did1, did2, k1, docs } = oneHop()
    const chain = await resolveDidChain(did1, options(docs))

    expect(chain.currentDid).toBe(did2)
    expect(chain.superseded).toBe(true)
    expect(chain.assurance).toBe('verified')
    expect(chain.hops).toHaveLength(1)
    expect(chain.hops[0]).toMatchObject({
      did: did1,
      successorDid: did2,
      source: 'network',
      assurance: 'verified',
      proofKeyId: `${did1}#key-1`,
    })
    // The subject is unchanged by the update — that is the whole point of it.
    expect(chain.subject).toBe('did:wba:example.com:user:alice')
    // The terminal document is the CURRENT DID's, not the one we asked about.
    expect(chain.document.id).toBe(did2)
    expect(chain.docUrl).toContain(did2.slice(did2.lastIndexOf(':') + 1))
    // The old key signed the transition; the walk used it, and the fingerprint it
    // commits to is the old DID's, not the new one.
    expect(k1.pub).toHaveLength(32)
  })

  it('walks a multi-generation chain to the terminal active DID', async () => {
    const k = [newKey(), newKey(), newKey()]
    const did = k.map((key) => didFor('user:alice', key))
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did[0]!), transitionDoc(did[0]!, k[0]!, did[1]!)],
      [docUrl(did[1]!), transitionDoc(did[1]!, k[1]!, did[2]!)],
      [docUrl(did[2]!), activeDoc(did[2]!, k[2]!)],
    ])

    const chain = await resolveDidChain(did[0]!, options(docs))
    expect(chain.currentDid).toBe(did[2])
    expect(chain.hops.map((h) => h.did)).toEqual([did[0], did[1]])
    expect(chain.assurance).toBe('verified')
  })

  it('reports the chain for a diagnostic query even below the acceptance policy', async () => {
    const { did1, docs } = oneHop(false) // an unsigned transition
    const chain = await resolveDidChain(
      did1,
      options(docs, { acceptProviderAsserted: true, reportLowAssurance: true }),
    )
    expect(chain.assurance).toBe('provider_asserted')
    expect(chain.currentDid).not.toBe(did1)
  })
})

describe('resolveDidChain — assurance is per edge and is never promoted', () => {
  it('does not accept a signature-less chain by default', async () => {
    const { did1, docs } = oneHop(false)
    await expect(resolveDidChain(did1, options(docs))).rejects.toMatchObject({
      code: 'did_chain_assurance_too_low',
    })
  })

  it('accepts a signature-less chain only when the caller opts in', async () => {
    const { did1, did2, docs } = oneHop(false)
    const chain = await resolveDidChain(did1, options(docs, { acceptProviderAsserted: true }))
    expect(chain.currentDid).toBe(did2)
    // §2.5.5: a provider assertion is NOT a DID Document property and may never be
    // promoted to verified / recovery_verified.
    expect(chain.assurance).toBe('provider_asserted')
    expect(chain.hops[0]!.assurance).toBe('provider_asserted')
    expect(chain.hops[0]!.proofKeyId).toBeUndefined()
  })

  it('will not report provider_asserted without reaching an active e1_ binding path', async () => {
    // The successor is a did:wba WITHOUT a fingerprint segment, so there is no
    // binding proof at the end of the walk to anchor the claim. §2.5.5 allows
    // `provider_asserted` only after reaching an active `e1_` DID, so this
    // structurally complete chain is `unverified` — and unverified is never accepted.
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const bare = 'did:wba:example.com:user:alice'
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, bare, { sign: false })],
      ['https://example.com/user/alice/did.json', activeDoc(bare, k2)],
    ])

    const chain = await resolveDidChain(
      did1,
      options(docs, { acceptProviderAsserted: true, reportLowAssurance: true }),
    )
    expect(chain.assurance).toBe('unverified')
    await expect(resolveDidChain(did1, options(docs, { acceptProviderAsserted: true }))).rejects.toMatchObject(
      { code: 'did_chain_assurance_too_low' },
    )
  })

  it('verifies a recovery proof against the PRE-deactivation document', async () => {
    // §2.5.5 rule 2: a recovery key is validated against the key material and
    // `assertionMethod` authorization of the document trusted BEFORE deactivation —
    // and it need not match the DID path's e1_ fingerprint.
    const k1 = newKey()
    const recovery = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const trusted = createDidDocumentStore()

    // The PRE-deactivation state: the recovery key exists and is authorized.
    const trustedDoc = activeDoc(did1, k1)
    ;(trustedDoc.verificationMethod as unknown[]).push({
      id: `${did1}#recovery-1`,
      type: 'Multikey',
      controller: did1,
      publicKeyMultibase: encodeMultibaseEd25519(recovery.pub),
    })
    ;(trustedDoc.assertionMethod as string[]).push(`${did1}#recovery-1`)
    await trusted.set({ did: did1, document: trustedDoc, docUrl: docUrl(did1), source: 'store', fetchedAt: Date.now() })

    // The deactivation, signed by the recovery key instead of the binding key.
    const doc = transitionDoc(did1, k1, did2)
    doc.verificationMethod = [
      ...(trustedDoc.verificationMethod as unknown[]),
    ]
    doc.proof = signDidDocumentProofSync(doc, `${did1}#recovery-1`, recovery.priv)

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), doc],
      [docUrl(did2), activeDoc(did2, k2)],
    ])

    const chain = await resolveDidChain(did1, options(docs, { trustedDocuments: trusted }))
    expect(chain.assurance).toBe('recovery_verified')
    expect(chain.hops[0]).toMatchObject({
      assurance: 'recovery_verified',
      proofKeyId: `${did1}#recovery-1`,
    })
  })

  it('refuses a recovery proof whose key was never authorized before deactivation', async () => {
    const k1 = newKey()
    const recovery = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)

    // The recovery key is added INSIDE the transition document only. §2.5.5 rule 1
    // forbids exactly this: a key introduced at deactivation time must not be able to
    // claim continuity, so without the pre-deactivation document there is nothing to
    // authorize against.
    const doc = transitionDoc(did1, k1, did2)
    ;(doc.verificationMethod as unknown[]).push({
      id: `${did1}#recovery-1`,
      type: 'Multikey',
      controller: did1,
      publicKeyMultibase: encodeMultibaseEd25519(recovery.pub),
    })
    doc.proof = signDidDocumentProofSync(doc, `${did1}#recovery-1`, recovery.priv)

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), doc],
      [docUrl(did2), activeDoc(did2, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toMatchObject({ code: 'did_chain_broken' })
  })

  it('refuses a transition proof signed by an unrelated key', async () => {
    // Present, structurally valid, and cryptographically sound in isolation — but
    // neither the binding key nor an authorized recovery key. §2.5.5: it MUST NOT be
    // downgraded to a provider assertion or an unverified hint.
    const k1 = newKey()
    const stranger = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const doc = transitionDoc(did1, k1, did2)
    ;(doc.verificationMethod as unknown[]).push({
      id: `${did1}#key-9`,
      type: 'Multikey',
      controller: did1,
      publicKeyMultibase: encodeMultibaseEd25519(stranger.pub),
    })
    doc.proof = signDidDocumentProofSync(doc, `${did1}#key-9`, stranger.priv)

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), doc],
      [docUrl(did2), activeDoc(did2, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toMatchObject({ code: 'did_chain_broken' })
  })

  /** The PRE-deactivation trusted document for `did1`: its binding key plus a recovery
   *  key authorized in `assertionMethod`. `spell` decides how that method's id is
   *  written, which is what the recovery branch must resolve rather than compare
   *  literally. */
  async function trustedWithRecovery(did1: string, k1: Signer, recovery: Signer, spell: Spell) {
    const store = createDidDocumentStore()
    const document = activeDoc(did1, k1)
    const id = spell(`${did1}#recovery-1`)
    ;(document.verificationMethod as unknown[]).push({
      id,
      type: 'Multikey',
      controller: did1,
      publicKeyMultibase: encodeMultibaseEd25519(recovery.pub),
    })
    ;(document.assertionMethod as string[]).push(id)
    await store.set({ did: did1, document, docUrl: docUrl(did1), source: 'store', fetchedAt: Date.now() })
    return { store, document }
  }

  it('refuses a recovery keyid that names ANOTHER DID with the same fragment', async () => {
    // The trusted document pre-authorized its OWN `#recovery-1`; the transition names
    // `did:wba:evil.example:user:mallory#recovery-1`. Comparing fragments alone would
    // call those one identifier, and the chain would report `recovery_verified` with an
    // outsider's DID URL recorded as its proof key (ANP-2026-09-17-R01). The signature
    // IS made by the authorized recovery key, so only the namespace rule can refuse it.
    const k1 = newKey()
    const recovery = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const { store, document } = await trustedWithRecovery(did1, k1, recovery, relative)

    const doc = transitionDoc(did1, k1, did2)
    doc.verificationMethod = [...(document.verificationMethod as unknown[])]
    doc.proof = signDidDocumentProofSync(doc, 'did:wba:evil.example:user:mallory#recovery-1', recovery.priv)

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), doc],
      [docUrl(did2), activeDoc(did2, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs, { trustedDocuments: store }))).rejects.toMatchObject({
      code: 'did_chain_broken',
    })
  })

  it('accepts every spelling pairing of one recovery DID URL', async () => {
    // `#recovery-1` and `${did1}#recovery-1` are the SAME identifier for a document
    // whose id is did1, so which spelling each side happens to use must not decide
    // whether the recovery proof is authorized.
    const spellings: [string, Spell][] = [
      ['absolute', absolute],
      ['relative', relative],
    ]
    for (const [trustedName, trustedSpelling] of spellings) {
      for (const [proofName, proofSpelling] of spellings) {
        const k1 = newKey()
        const recovery = newKey()
        const k2 = newKey()
        const did1 = didFor('user:alice', k1)
        const did2 = didFor('user:alice', k2)
        const { store, document } = await trustedWithRecovery(did1, k1, recovery, trustedSpelling)

        const doc = transitionDoc(did1, k1, did2)
        doc.verificationMethod = [...(document.verificationMethod as unknown[])]
        doc.proof = signDidDocumentProofSync(doc, proofSpelling(`${did1}#recovery-1`), recovery.priv)

        const docs = new Map<string, Record<string, unknown>>([
          [docUrl(did1), doc],
          [docUrl(did2), activeDoc(did2, k2)],
        ])
        const chain = await resolveDidChain(did1, options(docs, { trustedDocuments: store }))
        expect(chain.assurance, `${trustedName} method / ${proofName} proof`).toBe('recovery_verified')
        expect(chain.hops[0]!.proofKeyId).toBe(`${did1}#recovery-1`)
      }
    }
  })
})

describe('resolveDidChain — the migration rules it must reject', () => {
  it('rejects a successor that does not share the stable subject path', async () => {
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const other = didFor('user:bob', k2)
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, other)],
      [docUrl(other), activeDoc(other, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toThrow(/stable subject path/)
  })

  it('rejects a successor on another host — so a chain needs no new fetch authority', async () => {
    // §2.2.3 puts the DOMAIN inside the stable subject path and §2.5.3 rule 1
    // requires the paths to be identical, so a cross-host successor is a path
    // mismatch by construction. Nothing here resolves across hosts: the caller's
    // existing allowedHosts covers every hop.
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const elsewhere = didFor('user:alice', k2, 'other.example')
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, elsewhere)],
      [`https://other.example/user/alice/did.json`, activeDoc(elsewhere, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toThrow(/stable subject path/)
  })

  it('rejects a document that names a successor but is not deactivated', async () => {
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const doc = activeDoc(did1, k1, { successorDid: did2 }) // deactivated is absent
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), doc],
      [docUrl(did2), activeDoc(did2, k2)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toThrow(/deactivated/)
  })

  it('rejects a chain that cycles', async () => {
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, did2)],
      [docUrl(did2), transitionDoc(did2, k2, did1)],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toThrow(/cycles/)
  })

  it('rejects a chain longer than maxChainLength', async () => {
    const k = [newKey(), newKey(), newKey()]
    const did = k.map((key) => didFor('user:alice', key))
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did[0]!), transitionDoc(did[0]!, k[0]!, did[1]!)],
      [docUrl(did[1]!), transitionDoc(did[1]!, k[1]!, did[2]!)],
      [docUrl(did[2]!), activeDoc(did[2]!, k[2]!)],
    ])
    await expect(resolveDidChain(did[0]!, options(docs, { maxChainLength: 1 }))).rejects.toThrow(/maxChainLength/)
  })

  it('rejects a successor that names a different predecessor', async () => {
    // §2.5.5 requires the DIRECT-successor relation to be checked. `alsoKnownAs` is
    // the only evidence a document offers, and naming the wrong generation
    // contradicts the hop.
    const k = [newKey(), newKey(), newKey()]
    const did = k.map((key) => didFor('user:alice', key))
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did[0]!), transitionDoc(did[0]!, k[0]!, did[1]!)],
      [docUrl(did[1]!), transitionDoc(did[1]!, k[1]!, did[2]!)],
      [docUrl(did[2]!), activeDoc(did[2]!, k[2]!, { alsoKnownAs: [did[0]] })],
    ])
    await expect(resolveDidChain(did[0]!, options(docs))).rejects.toThrow(/skipped a generation/)
  })

  it('accepts a successor that names its predecessor in alsoKnownAs', async () => {
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, did2)],
      // `alsoKnownAs` is signed over, like every other field, so it is set before the
      // proof rather than patched in afterwards.
      [docUrl(did2), activeDoc(did2, k2, { alsoKnownAs: [did1] })],
    ])
    const chain = await resolveDidChain(did1, options(docs))
    expect(chain.currentDid).toBe(did2)
  })

  it('rejects a terminal DID that is deactivated and names no successor', async () => {
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const keyid2 = `${did2}#key-1`
    const dead: Record<string, unknown> = {
      ...buildBaseDidDocument({ did: did2, keyid: keyid2, publicKeyMultibase: encodeMultibaseEd25519(k2.pub) }),
      deactivated: true,
    }
    dead.proof = signDidDocumentProofSync(dead, keyid2, k2.priv)
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, did2)],
      [docUrl(did2), dead],
    ])
    await expect(resolveDidChain(did1, options(docs))).rejects.toThrow(/deactivated and names no successor/)
  })
})

describe('resolveDidChain — the verified-edge store (ANP-03 §2.6)', () => {
  it('keeps only the cryptographic edges, and only once the whole chain succeeded', async () => {
    const { did1, did2, docs } = oneHop()
    const store = createDidChainEdgeStore()
    await resolveDidChain(did1, options(docs, { edgeStore: store }))

    expect(await store.get(did1)).toMatchObject({
      did: did1,
      successorDid: did2,
      assurance: 'verified',
      stableSubjectId: 'example.com:user:alice',
    })
    // The terminal DID has no successor, so it has no edge.
    expect(await store.get(did2)).toBeUndefined()
  })

  it('does not keep a provider-asserted edge', async () => {
    const { did1, docs } = oneHop(false)
    const store = createDidChainEdgeStore()
    await resolveDidChain(did1, options(docs, { acceptProviderAsserted: true, edgeStore: store }))
    expect(await store.get(did1)).toBeUndefined()
  })

  it('leaves no prefix edge behind when a later hop fails', async () => {
    // §2.6: a failure before the cache-commit step must not leave the failed chain's
    // prefix edges. Here the FIRST hop is sound and the second is signed by a key
    // nobody authorized, so the walk fails with the first hop already verified.
    const k = [newKey(), newKey(), newKey()]
    const stranger = newKey()
    const did = k.map((key) => didFor('user:alice', key))
    const badSecond = transitionDoc(did[1]!, k[1]!, did[2]!)
    ;(badSecond.verificationMethod as unknown[]).push({
      id: `${did[1]}#key-9`,
      type: 'Multikey',
      controller: did[1],
      publicKeyMultibase: encodeMultibaseEd25519(stranger.pub),
    })
    badSecond.proof = signDidDocumentProofSync(badSecond, `${did[1]}#key-9`, stranger.priv)

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did[0]!), transitionDoc(did[0]!, k[0]!, did[1]!)],
      [docUrl(did[1]!), badSecond],
      [docUrl(did[2]!), activeDoc(did[2]!, k[2]!)],
    ])

    const store = createDidChainEdgeStore()
    await expect(resolveDidChain(did[0]!, options(docs, { edgeStore: store }))).rejects.toMatchObject({
      code: 'did_chain_broken',
    })
    expect(await store.get(did[0]!)).toBeUndefined()
    expect(await store.get(did[1]!)).toBeUndefined()
  })

  it('rejects a second, different successor for a DID already verified', async () => {
    // §2.6/§7: one old DID may have only ONE direct successor. Only the store can
    // see this across resolutions — a single walk cannot.
    const k1 = newKey()
    const k2 = newKey()
    const k3 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const did3 = didFor('user:alice', k3)
    const store = createDidChainEdgeStore()
    await store.set({
      did: did1,
      successorDid: did2,
      assurance: 'verified',
      stableSubjectId: 'example.com:user:alice',
      verifiedAt: Date.now(),
    })

    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, did3)],
      [docUrl(did3), activeDoc(did3, k3)],
    ])
    await expect(resolveDidChain(did1, options(docs, { edgeStore: store }))).rejects.toThrow(
      /only one direct successor/,
    )
  })
})

describe('resolveDidChain — provider_asserted needs a LIVE terminal (ANP-2026-09-17-01)', () => {
  /** A store already holding `did`'s active document, and an observable marker so a
   *  test can tell the cached copy apart from the one the transport serves. */
  async function storeHolding(did: string, key: Signer, marker: string) {
    const store = createDidDocumentStore()
    await store.set({
      did,
      document: activeDoc(did, key, { alsoKnownAs: [marker] }),
      docUrl: docUrl(did),
      source: 'network',
      fetchedAt: Date.now(),
    })
    return store
  }

  it('will not promote a signature-less hop whose terminal came from the store', async () => {
    // The predecessor is fetched live, but the ACTIVE successor is answered from the
    // caller's store. §2.5.5's provider assertion is a claim about what the provider
    // says NOW, and a stored copy cannot show an update made after it was written —
    // so this chain is `unverified`, and an explicit opt-in does not change that.
    const k1 = newKey()
    const k2 = newKey()
    const did1 = didFor('user:alice', k1)
    const did2 = didFor('user:alice', k2)
    const store = await storeHolding(did2, k2, 'from-the-store')
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, did2, { sign: false })],
      [docUrl(did2), activeDoc(did2, k2, { alsoKnownAs: ['from-the-network'] })],
    ])

    const chain = await resolveDidChain(
      did1,
      options(docs, { documentStore: store, acceptProviderAsserted: true, reportLowAssurance: true }),
    )

    // The store copy is what the walk ended on — the terminal was never re-fetched.
    expect((chain.document.alsoKnownAs as string[])[0]).toBe('from-the-store')
    expect(chain.assurance).toBe('unverified')
    await expect(
      resolveDidChain(did1, options(docs, { documentStore: store, acceptProviderAsserted: true })),
    ).rejects.toMatchObject({ code: 'did_chain_assurance_too_low' })
  })

  it('still promotes a signature-less chain when every document was fetched live', async () => {
    // The whole walk — both predecessors AND the terminal — came from the transport, so
    // the provider assertion is about this resolution and is allowed. A configured
    // store must not disturb that: nothing in this chain was in it.
    const k = [newKey(), newKey(), newKey()]
    const did = k.map((key) => didFor('user:alice', key))
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did[0]!), transitionDoc(did[0]!, k[0]!, did[1]!, { sign: false })],
      [docUrl(did[1]!), transitionDoc(did[1]!, k[1]!, did[2]!, { sign: false })],
      [docUrl(did[2]!), activeDoc(did[2]!, k[2]!)],
    ])

    const chain = await resolveDidChain(
      did[0]!,
      options(docs, { documentStore: createDidDocumentStore(), acceptProviderAsserted: true }),
    )
    expect(chain.currentDid).toBe(did[2])
    expect(chain.hops.map((hop) => hop.source)).toEqual(['network', 'network'])
    expect(chain.assurance).toBe('provider_asserted')
  })

  it('never lets a stored, superseded predecessor stand in for a live fetch', async () => {
    // A transition document names a successor, so it IS superseded and the resolver
    // refuses to serve it from a store. That is what keeps an intermediate hop a
    // network fetch — a stale stored copy must not decide where the chain goes.
    const k1 = newKey()
    const k2 = newKey()
    const k3 = newKey()
    const did1 = didFor('user:alice', k1)
    const stale = didFor('user:alice', k2)
    const live = didFor('user:alice', k3)

    const store = createDidDocumentStore()
    await store.set({
      did: did1,
      document: transitionDoc(did1, k1, stale),
      docUrl: docUrl(did1),
      source: 'network',
      fetchedAt: Date.now(),
    })
    const docs = new Map<string, Record<string, unknown>>([
      [docUrl(did1), transitionDoc(did1, k1, live)],
      [docUrl(stale), activeDoc(stale, k2)],
      [docUrl(live), activeDoc(live, k3)],
    ])

    const chain = await resolveDidChain(did1, options(docs, { documentStore: store }))
    expect(chain.currentDid).toBe(live)
    expect(chain.hops[0]!.source).toBe('network')
  })
})

describe('resolveDidChain — input and transport policy', () => {
  it('refuses a DID whose method defines no stable subject path', async () => {
    // The update chain is a `did:wba` rule; there is nothing to walk for another
    // method, and inventing one would be a protocol concept upstream has not defined.
    await expect(resolveDidChain('did:web:example.com:alice', options(new Map()))).rejects.toMatchObject({
      code: 'invalid_did',
    })
  })

  it('refuses to fetch a host outside the allowlist', async () => {
    const k1 = newKey()
    const did1 = didFor('user:alice', k1)
    const docs = new Map([[docUrl(did1), activeDoc(did1, k1)]])
    await expect(
      resolveDidChain(did1, { ...options(docs), allowedHosts: ['other.example'] }),
    ).rejects.toMatchObject({ code: 'did_resolve_blocked' })
  })
})
