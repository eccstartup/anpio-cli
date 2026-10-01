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
    expect('objectDir' in config).toBe(false)
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
    const set = loadConfig({ AGENTX_KEY_FILE: '/keys/agentx.pem', AGENTX_OBJECT_DIR: '/var/agentx/objects' })
    expect(set.keyFile).toBe('/keys/agentx.pem')
    expect(set.objectDir).toBe('/var/agentx/objects')

    const blank = loadConfig({ AGENTX_KEY_FILE: '', AGENTX_OBJECT_DIR: '' })
    expect('keyFile' in blank).toBe(false)
    expect('objectDir' in blank).toBe(false)
  })
})
