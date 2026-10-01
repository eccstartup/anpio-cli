import { describe, it, expect } from 'vitest'
import {
  ANP_COMPONENTS,
  parseSignatureInput,
  buildSignatureBase,
  serializeSignatureParams,
  buildSignatureInputHeader,
  buildContentDigestValue,
} from './signatureBase'
import { utf8, base64ToBytes } from './encoding'

describe('ANP_COMPONENTS', () => {
  it('is the single source of truth for the official ANP-02 covered components', () => {
    expect(ANP_COMPONENTS).toEqual(['@method', '@target-uri', '@authority', 'content-digest'])
  })
})

describe('parseSignatureInput', () => {
  it('parses components and params, coercing numeric timestamps to numbers', () => {
    const input =
      '("@method" "@target-uri" "@authority" "content-digest");created=1700000000;expires=1700000300;nonce="abc";keyid="did:web:example.com#key-1"'
    const { components, params } = parseSignatureInput(input)
    expect(components).toEqual(['@method', '@target-uri', '@authority', 'content-digest'])
    expect(params.created).toBe(1700000000)
    expect(params.expires).toBe(1700000300)
    expect(params.nonce).toBe('abc')
    expect(params.keyid).toBe('did:web:example.com#key-1')
  })

  it('keeps non-numeric param values as strings', () => {
    const { params } = parseSignatureInput('("content-digest");keyid="k1";alg="ed25519"')
    expect(params.keyid).toBe('k1')
    expect(params.alg).toBe('ed25519')
  })

  it('round-trips a serialized params string', () => {
    const sigParams = serializeSignatureParams(ANP_COMPONENTS, {
      created: 1700000000,
      nonce: 'n-1',
      keyid: 'did:web:example.com#key-1',
    })
    const { components, params } = parseSignatureInput(`sig1=${sigParams}`)
    expect(components).toEqual(ANP_COMPONENTS)
    expect(params.keyid).toBe('did:web:example.com#key-1')
    expect(params.nonce).toBe('n-1')
    expect(params.created).toBe(1700000000)
  })

  it('throws on input without a parenthesised component list', () => {
    expect(() => parseSignatureInput('no-parens-here')).toThrow()
  })
})

describe('buildSignatureBase', () => {
  const headers = { 'content-digest': 'sha-256=:abc:' }
  const input = {
    method: 'POST',
    path: '/api/login/anp/verify',
    authority: 'localhost:3000',
    targetUri: 'http://localhost:3000/api/login/anp/verify',
    headers,
    components: ANP_COMPONENTS,
  }

  it('builds covered-component lines in their declared order', () => {
    const base = buildSignatureBase(input)
    expect(base).toBe(
      [
        '"@method": POST',
        '"@target-uri": http://localhost:3000/api/login/anp/verify',
        '"@authority": localhost:3000',
        '"content-digest": sha-256=:abc:',
      ].join('\n'),
    )
  })

  it('falls @target-uri back to the path when no targetUri is given (legacy)', () => {
    const base = buildSignatureBase({ ...input, targetUri: undefined })
    expect(base).toContain('"@target-uri": /api/login/anp/verify')
  })

  it('uppercases @method', () => {
    const base = buildSignatureBase({ ...input, method: 'post' })
    expect(base).toContain('"@method": POST')
  })

  it('appends the @signature-params line after the covered components', () => {
    const sigParams = serializeSignatureParams(ANP_COMPONENTS, { nonce: 'n', keyid: 'did:#1' })
    const base = buildSignatureBase({ ...input, signatureParams: sigParams })
    const lines = base.split('\n')
    expect(lines).toHaveLength(5)
    expect(lines[4]).toBe(`"@signature-params": ${sigParams}`)
  })

  it('reads an uncovered header value from the headers map', () => {
    const base = buildSignatureBase({
      ...input,
      headers: { 'x-anp': 'hello' },
      components: ['x-anp'],
    })
    expect(base).toBe('"x-anp": hello')
  })
})

describe('serializeSignatureParams', () => {
  it('formats created/expires unquoted and nonce/keyid/alg quoted', () => {
    const s = serializeSignatureParams(ANP_COMPONENTS, {
      created: 1,
      expires: 2,
      nonce: 'n',
      keyid: 'k',
      alg: 'ed25519',
    })
    expect(s).toBe(
      '("@method" "@target-uri" "@authority" "content-digest");created=1;expires=2;nonce="n";keyid="k";alg="ed25519"',
    )
  })

  it('omits absent optional params', () => {
    const s = serializeSignatureParams(['@method'], { keyid: 'k' })
    expect(s).toBe('("@method");keyid="k"')
  })
})

describe('buildSignatureInputHeader', () => {
  it('produces the Signature-Input header value', () => {
    const s = buildSignatureInputHeader(ANP_COMPONENTS, { keyid: 'k', alg: 'ed25519', created: 5 })
    expect(s).toBe('("@method" "@target-uri" "@authority" "content-digest");created=5;keyid="k";alg="ed25519"')
  })
})

describe('buildContentDigestValue', () => {
  it('produces the labeled RFC 9421 sha-256 value bound to the body', async () => {
    const value = await buildContentDigestValue(utf8('{"nonce":"abc"}'))
    expect(value).toMatch(/^sha-256=:[A-Za-z0-9+/=]+:$/)
    // The embedded digest is the SHA-256 of the body.
    const { sha256 } = await import('./encoding')
    const digest = await sha256(utf8('{"nonce":"abc"}'))
    expect(base64ToBytes(value.slice('sha-256=:'.length, -1))).toEqual(digest)
  })
})
