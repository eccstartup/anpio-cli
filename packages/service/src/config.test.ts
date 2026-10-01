import { describe, expect, it } from 'vitest'
import { didWebFor, loadConfig } from './config'

describe('loadConfig defaults', () => {
  it('binds loopback and derives everything from it', () => {
    const config = loadConfig({})
    expect(config.listen).toEqual({ host: '127.0.0.1', port: 8787 })
    expect(config.publicUrl).toBe('http://127.0.0.1:8787')
    expect(config.serviceDid).toBe('did:web:127.0.0.1%3A8787')
    expect(config.dbPath).toBe('./agentx.db')
    expect(config.maxBody).toBe(1024 * 1024)
    // Optional paths stay out of the object rather than becoming ''.
    expect('keyFile' in config).toBe(false)
    // `objectDir` has no absent state: it is derived from the database path.
    expect(config.objectDir).toBe('objects')
  })
})

describe('AGENTX_OBJECT_DIR', () => {
  it('defaults to a directory beside the database file', () => {
    expect(loadConfig({ AGENTX_DB: '/var/agentx/agentx.db' }).objectDir).toBe('/var/agentx/objects')
    expect(loadConfig({ AGENTX_DB: 'agentx.db' }).objectDir).toBe('objects')
  })

  it('falls back to the working directory for an in-memory database', () => {
    // `:memory:` has no "beside": there is no file to sit next to.
    expect(loadConfig({ AGENTX_DB: ':memory:' }).objectDir).toBe('./objects')
  })
})

describe('AGENTX_LISTEN', () => {
  it('accepts an IPv6 literal in brackets', () => {
    expect(loadConfig({ AGENTX_LISTEN: '[::1]:9000' }).listen).toEqual({ host: '::1', port: 9000 })
  })

  it('accepts port 0, which is how a test asks for any free port', () => {
    expect(loadConfig({ AGENTX_LISTEN: '127.0.0.1:0' }).listen.port).toBe(0)
  })

  it('requires a port rather than inventing one', () => {
    expect(() => loadConfig({ AGENTX_LISTEN: '127.0.0.1' })).toThrow(/must be host:port/)
    expect(() => loadConfig({ AGENTX_LISTEN: 'nonsense' })).toThrow(/must be host:port/)
  })

  it('rejects a port outside the range', () => {
    expect(() => loadConfig({ AGENTX_LISTEN: '127.0.0.1:70000' })).toThrow(/0-65535/)
  })
})

describe('AGENTX_PUBLIC_URL', () => {
  it('refuses to derive one from a non-loopback bind', () => {
    expect(() => loadConfig({ AGENTX_LISTEN: '0.0.0.0:8787' })).toThrow(/AGENTX_PUBLIC_URL is required/)
  })

  it('accepts a non-loopback bind once the public URL is given', () => {
    const config = loadConfig({ AGENTX_LISTEN: '0.0.0.0:8787', AGENTX_PUBLIC_URL: 'https://agentx.example' })
    expect(config.publicUrl).toBe('https://agentx.example')
    expect(config.serviceDid).toBe('did:web:agentx.example')
  })

  it('drops trailing slashes so endpoint paths do not double up', () => {
    expect(loadConfig({ AGENTX_PUBLIC_URL: 'https://agentx.example///' }).publicUrl).toBe('https://agentx.example')
  })

  it('must be an absolute http(s) URL', () => {
    expect(() => loadConfig({ AGENTX_PUBLIC_URL: 'agentx.example' })).toThrow(/absolute URL/)
    expect(() => loadConfig({ AGENTX_PUBLIC_URL: 'ftp://agentx.example' })).toThrow(/http or https/)
  })
})

describe('AGENTX_SERVICE_DID', () => {
  it('wins over the derived value', () => {
    const config = loadConfig({ AGENTX_SERVICE_DID: 'did:web:elsewhere.example' })
    expect(config.serviceDid).toBe('did:web:elsewhere.example')
  })

  it('refuses a DID URL, because the field names the service rather than one of its keys', () => {
    // §8.7 L512. This value is written into the DID document and is the base a cross-domain
    // `keyid` resolves against, so a fragment here would quietly turn "this service" into
    // "some key of this service" at a place that never says so.
    expect(() => loadConfig({ AGENTX_SERVICE_DID: 'did:web:agentx.example#svc' })).toThrow(/not a DID URL/)
    expect(() => loadConfig({ AGENTX_SERVICE_DID: 'did:web:agentx.example?x=1' })).toThrow(/not a DID URL/)
  })

  it('refuses something that is not a DID at all', () => {
    expect(() => loadConfig({ AGENTX_SERVICE_DID: 'https://agentx.example' })).toThrow(/must be a DID string/)
  })

  it('accepts another DID method, which is the deployment choice rather than this module one', () => {
    expect(loadConfig({ AGENTX_SERVICE_DID: 'did:wba:agentx.example' }).serviceDid).toBe('did:wba:agentx.example')
  })
})

describe('didWebFor', () => {
  it('encodes the port and keeps each path segment', () => {
    expect(didWebFor('https://agentx.example')).toBe('did:web:agentx.example')
    expect(didWebFor('http://localhost:8787')).toBe('did:web:localhost%3A8787')
    expect(didWebFor('https://example.com/agentx/inbox')).toBe('did:web:example.com:agentx:inbox')
  })

  it('uses the decoded path, so one document is not two DIDs', () => {
    expect(didWebFor('https://example.com/my%20agent')).toBe('did:web:example.com:my agent')
  })
})

describe('AGENTX_MAX_BODY', () => {
  it('treats an empty value as unset', () => {
    expect(loadConfig({ AGENTX_MAX_BODY: '' }).maxBody).toBe(1024 * 1024)
  })

  it('takes a positive integer and rejects anything else', () => {
    expect(loadConfig({ AGENTX_MAX_BODY: '2048' }).maxBody).toBe(2048)
    expect(() => loadConfig({ AGENTX_MAX_BODY: '0' })).toThrow(/positive integer/)
    expect(() => loadConfig({ AGENTX_MAX_BODY: '-1' })).toThrow(/positive integer/)
    expect(() => loadConfig({ AGENTX_MAX_BODY: '1.5' })).toThrow(/positive integer/)
    expect(() => loadConfig({ AGENTX_MAX_BODY: 'lots' })).toThrow(/positive integer/)
  })
})

describe('optional paths', () => {
  it('are set only when non-empty', () => {
    const set = loadConfig({
      AGENTX_KEY_FILE: '/keys/agentx.pem',
      AGENTX_KEY_ID: `${didWebFor('http://127.0.0.1:8787')}#key-1`,
      AGENTX_OBJECT_DIR: '/var/agentx/objects',
    })
    expect(set.keyFile).toBe('/keys/agentx.pem')
    expect(set.objectDir).toBe('/var/agentx/objects')

    // An empty value is a shell accident, not a path: `objectDir` falls back to the
    // derivation rather than becoming ''.
    const blank = loadConfig({ AGENTX_KEY_FILE: '', AGENTX_KEY_ID: '', AGENTX_OBJECT_DIR: '' })
    expect('keyFile' in blank).toBe(false)
    expect('keyId' in blank).toBe(false)
    expect(blank.objectDir).toBe('objects')
  })
})

describe('AGENTX_KEY_FILE / AGENTX_KEY_ID', () => {
  const SERVICE_DID = didWebFor('http://127.0.0.1:8787')

  it('requires a keyid that names a method of this service own DID', () => {
    // 半个配置没有意义：`keyid` 的 DID 必须等于对端按 §6.2.2 第 6 步读出的 `serviceDid`，
    // 不一致时我们签出去的每一份请求都会被拒成 `forbidden_did`——那个错误看起来像对端的
    // 问题，所以要在启动时挡掉。
    expect(() => loadConfig({ AGENTX_KEY_FILE: '/keys/k' })).toThrow(/AGENTX_KEY_ID is required/)
    expect(() => loadConfig({ AGENTX_KEY_FILE: '/keys/k', AGENTX_KEY_ID: 'key-1' })).toThrow(/full DID URL/)
    expect(() => loadConfig({ AGENTX_KEY_FILE: '/keys/k', AGENTX_KEY_ID: `${SERVICE_DID}#` })).toThrow(/full DID URL/)
    expect(() =>
      loadConfig({ AGENTX_KEY_FILE: '/keys/k', AGENTX_KEY_ID: 'did:web:elsewhere#key-1' }),
    ).toThrow(/verification method of/)
  })

  it('accepts a keyid under this service own DID', () => {
    const config = loadConfig({ AGENTX_KEY_FILE: '/keys/k', AGENTX_KEY_ID: `${SERVICE_DID}#key-1` })
    expect(config.keyId).toBe(`${SERVICE_DID}#key-1`)
  })

  it('rejects a keyid with no key file', () => {
    // 打错一个变量名时说清楚，比等到第一次跨域调用才炸好查。
    expect(() => loadConfig({ AGENTX_KEY_ID: `${SERVICE_DID}#key-1` })).toThrow(/AGENTX_KEY_FILE is not/)
  })
})

describe('AGENTX_ALLOWED_DID_HOSTS / AGENTX_DID_DEV_HOSTS', () => {
  it('defaults to resolving nothing at all', () => {
    // The fail-closed default, and the one worth stating out loud: with no allowlist the
    // resolver refuses every remote document, so only inline documents verify.
    const config = loadConfig({})
    expect(config.didResolution.allowedHosts).toEqual([])
    expect('allowPrivateHosts' in config.didResolution).toBe(false)
    expect('allowInsecureTransport' in config.didResolution).toBe(false)
  })

  it('splits on commas and whitespace, because both get typed at a shell', () => {
    const config = loadConfig({ AGENTX_ALLOWED_DID_HOSTS: 'a.example, b.example  c.example' })
    expect(config.didResolution.allowedHosts).toEqual(['a.example', 'b.example', 'c.example'])
  })

  it('treats an empty value as unset rather than as a host named ""', () => {
    expect(loadConfig({ AGENTX_ALLOWED_DID_HOSTS: '' }).didResolution.allowedHosts).toEqual([])
  })

  it('puts dev hosts in the allowlist as well as in the two relaxations', () => {
    // The relaxations lift a gate; they do not widen the allowlist. A host only named
    // there would be opted in to nothing and would still never be fetched.
    const config = loadConfig({ AGENTX_ALLOWED_DID_HOSTS: 'public.example', AGENTX_DID_DEV_HOSTS: 'localhost' })
    expect(config.didResolution.allowedHosts).toEqual(['public.example', 'localhost'])
    expect(config.didResolution.allowPrivateHosts).toEqual(['localhost'])
    expect(config.didResolution.allowInsecureTransport).toEqual(['localhost'])
  })

  it('does not repeat a host named in both variables', () => {
    const config = loadConfig({ AGENTX_ALLOWED_DID_HOSTS: 'localhost', AGENTX_DID_DEV_HOSTS: 'localhost' })
    expect(config.didResolution.allowedHosts).toEqual(['localhost'])
  })
})
