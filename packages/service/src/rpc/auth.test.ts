import { describe, expect, it } from 'vitest'
import {
  DidKeyResolver,
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  ed25519OriginProofSigner,
  type AnpMeta,
  type AnpRequest,
  type AnpSigningIdentity,
} from '@agentx/core'
import { DIRECT_AUTH_CODES, P1_AUTH_CODES, authenticate, callerAnchor } from './auth'

const sender = createAnpIdentity('sender.example')
const other = createAnpIdentity('other.example')
const group = createAnpIdentity('group.example')

/** 服务端将来就是这么解析的：`DidKeyResolver` 加上一份内联文档。
 *  内联是为了不起网络——生产里这个选项不存在，文档来自 DID 自己的域。 */
const resolver = new DidKeyResolver()

function identityOptions(identity: AnpSigningIdentity) {
  return { didDocument: identity.didDocument }
}

/** 一个什么都解析不出来的 resolver，用来跑"钥不在这个身份下"这一支。 */
const unresolvable = {
  async resolve(identity: string): Promise<never> {
    throw new Error(`no DID document for ${identity}`)
  },
}

function meta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: sender.did,
    target: { kind: 'agent', did: other.did },
    ...overrides,
  }
}

const BODY = { content_type: 'text/plain', content: 'hello' }

/** 一份真的签过名的请求——成功路径要跑真签名，桩只负责把钥交出来。 */
async function signed(
  options: {
    method?: string
    meta?: AnpMeta
    body?: Record<string, unknown>
    signer?: AnpSigningIdentity
    created?: number
    expires?: number
  } = {},
): Promise<AnpRequest> {
  const method = options.method ?? 'direct.send'
  const under = options.meta ?? meta()
  const body = options.body ?? BODY
  const signer = options.signer ?? sender
  const auth = await buildOriginProofAuth({
    method,
    meta: under,
    body,
    signer: ed25519OriginProofSigner(signer.priv, signer.keyid),
    ...(options.created !== undefined ? { created: options.created } : {}),
    ...(options.expires !== undefined ? { expires: options.expires } : {}),
  })
  return buildMessageRequest({ id: 'req-1', method, meta: under, body, auth })
}

describe('callerAnchor', () => {
  it('takes meta.sender_did for an ordinary request', () => {
    expect(callerAnchor('direct.send', { meta: meta(), body: BODY })).toBe(sender.did)
  })

  it.each(['group.incoming', 'group.state_changed', 'group.e2ee.notice'])(
    'takes body.group_did for %s',
    (method) => {
      const params = { meta: meta({ sender_did: group.did }), body: { group_did: group.did } }
      expect(callerAnchor(method, params)).toBe(group.did)
    },
  )

  it('does not fall back to meta.sender_did when a group notification has no group_did', () => {
    // The whole point of the group column. An attacker running their own domain can set
    // `meta.sender_did` to a DID they control and sign a perfect proof with that key; if
    // the anchor fell back to that field, the forged notification would authenticate. So a
    // missing `body.group_did` yields "no anchor" — never the attacker's DID.
    const params = { meta: meta({ sender_did: other.did }), body: { event: 'member-removed' } }
    expect(callerAnchor('group.state_changed', params)).toBeUndefined()
  })

  it('is undefined when an ordinary request names no sender', () => {
    const anonymous = { profile: 'p', security_profile: 's' } as unknown as AnpMeta
    expect(callerAnchor('direct.send', { meta: anonymous })).toBeUndefined()
  })

  it('is undefined for an empty sender_did rather than an empty anchor', () => {
    expect(callerAnchor('direct.send', { meta: meta({ sender_did: '' }), body: BODY })).toBeUndefined()
  })
})

describe('authenticate', () => {
  it('accepts a request whose proof verifies against the caller', async () => {
    const envelope = await signed()
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(sender),
    })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.key.identity).toBe(sender.did)
  })

  it('rejects a proof whose keyid does not resolve under the caller', async () => {
    const envelope = await signed({ signer: other })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      // The caller's own document is what we hold. The keyid names `other`, and a document
      // may only satisfy a keyid for the DID it describes (resolveDid.ts:905), so the
      // lookup fails before any signature is checked.
      resolverOptions: identityOptions(sender),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('key_unresolved')
    expect(result.error.anpCode).toBe('anp.unauthorized')
    expect(result.error.code).toBe(1005)
  })

  it('gives anchor mismatch its own code when the profile defines one', async () => {
    // Here the keyid's DID *is* resolvable — it is just not the identity the method says
    // should be calling. P3 §11 L599-600 gives that its own code; P1 has a single one.
    const envelope = await signed({ signer: other })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(other),
      codes: DIRECT_AUTH_CODES,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('anchor_mismatch')
    expect(result.error.anpCode).toBe('direct.origin_did_mismatch')
    expect(result.error.code).toBe(2006)
  })

  it("folds other verification failures into the profile's invalid-proof code", async () => {
    const envelope = await signed()
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver: unresolvable,
      codes: DIRECT_AUTH_CODES,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.anpCode).toBe('direct.invalid_origin_proof')
    expect(result.error.code).toBe(2005)
  })

  it('rejects a request that carries no auth at all', async () => {
    const envelope = buildMessageRequest({ id: 'r', method: 'direct.send', meta: meta(), body: BODY })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(sender),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('scheme_unsupported')
  })

  it('rejects when the method names no originator to authenticate', async () => {
    const under = meta({ profile: 'anp.group.base.v2', sender_did: group.did })
    const body = { group_did: group.did, event: 'member-removed' }
    const envelope = await signed({ method: 'group.state_changed', meta: under, body, signer: group })
    const result = await authenticate({
      envelope,
      expectedAnchor: undefined,
      resolver,
      resolverOptions: identityOptions(group),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('no_anchor')
    expect(result.error.anpCode).toBe('anp.unauthorized')
  })

  it('accepts a group notification anchored on the group DID', async () => {
    const body = { group_did: group.did, event: 'member-removed' }
    const under = meta({
      profile: 'anp.group.base.v2',
      sender_did: group.did,
      target: { kind: 'agent', did: sender.did },
    })
    const envelope = await signed({ method: 'group.state_changed', meta: under, body, signer: group })
    const anchor = callerAnchor('group.state_changed', { meta: under, body })
    const result = await authenticate({
      envelope,
      expectedAnchor: anchor,
      resolver,
      resolverOptions: identityOptions(group),
    })
    expect(result.ok).toBe(true)
  })

  it('authenticates against the group DID even when meta.sender_did disagrees', async () => {
    // P4 §8.11 L922 requires the two fields to be equal; that MUST is the P4 handler's to
    // enforce (C9). This layer anchors on the body, so a request that lies in
    // `meta.sender_did` still has to prove the *group* signed it, and cannot be accepted
    // by proving an identity the attacker controls.
    const body = { group_did: group.did, event: 'member-removed' }
    const under = meta({
      profile: 'anp.group.base.v2',
      sender_did: other.did,
      target: { kind: 'agent', did: sender.did },
    })
    const envelope = await signed({ method: 'group.state_changed', meta: under, body, signer: group })
    expect(callerAnchor('group.state_changed', { meta: under, body })).toBe(group.did)

    const asGroup = await authenticate({
      envelope,
      expectedAnchor: group.did,
      resolver,
      resolverOptions: identityOptions(group),
    })
    expect(asGroup.ok).toBe(true)

    // The same envelope judged as its own claimed sender is refused: nothing `other` holds
    // could have produced this signature.
    const asClaimed = await authenticate({
      envelope,
      expectedAnchor: other.did,
      resolver,
      resolverOptions: identityOptions(other),
    })
    expect(asClaimed.ok).toBe(false)
  })

  it('rejects a proof whose expires has passed', async () => {
    const now = Math.floor(Date.now() / 1000)
    const envelope = await signed({ created: now - 10, expires: now - 1 })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(sender),
      now,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('expired')
    expect(result.error.anpCode).toBe('anp.unauthorized')
  })

  it('rejects a proof timestamped well in the future', async () => {
    const now = Math.floor(Date.now() / 1000)
    const envelope = await signed({ created: now + 600 })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(sender),
      now,
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('stale')
  })

  it('imposes no age limit of its own, because the spec leaves that to the profile', async () => {
    // P1 附录 A says how the digest and the signature are computed and nothing about how
    // old a proof may be; §13.2 L816 refuses outright to make a timestamp the anti-replay
    // mechanism. A service that invented an age cap here would be answering a question the
    // profile owns.
    const now = Math.floor(Date.now() / 1000)
    const envelope = await signed({ created: now - 86_400 })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(sender),
      now,
    })
    expect(result.ok).toBe(true)
  })

  it('does not put the failure category on the wire', async () => {
    // core's `verify.ts` warns that answering "was this keyid authorized?" once per failure
    // is an oracle. The category goes back to the service for its logs and stays out of the
    // rejection the caller receives.
    const envelope = await signed({ signer: other })
    const result = await authenticate({
      envelope,
      expectedAnchor: sender.did,
      resolver,
      resolverOptions: identityOptions(other),
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('anchor_mismatch')
    const wire = JSON.stringify(result.error)
    for (const reason of ['anchor_mismatch', 'key_unresolved', 'signature_invalid', 'digest_mismatch']) {
      expect(wire).not.toContain(reason)
    }
  })

  it('defaults to the P1 code pair when the caller does not name one', () => {
    expect(P1_AUTH_CODES.invalidProof.code).toBe(1005)
    expect(P1_AUTH_CODES.anchorMismatch.code).toBe(1005)
  })
})
