import { describe, it, expect } from 'vitest'
import { createStore } from './store'
import { createConfig } from './config'
import { createEventEmitter } from './events'
import type { AnpConnector, AnpIdentity } from './types'
import { subjectOf } from './identity'

function identity(did: string): AnpIdentity {
  return {
    subject: subjectOf(did),
    did,
    keyid: `${did}#key-1`,
    publicKey: { publicKeyMultibase: 'zed...' },
    didDocument: { id: did, verificationMethod: [] },
  }
}

// A connector whose isAvailable/getIdentity resolve after a controllable delay.
function connector(id: string, ident: AnpIdentity, delayMs = 0): AnpConnector {
  return {
    id,
    name: id,
    type: 'anp-dev-shim',
    isAvailable: () => new Promise<boolean>((r) => setTimeout(() => r(true), delayMs)),
    getIdentity: () => new Promise<AnpIdentity>((r) => setTimeout(() => r(ident), delayMs)),
    signRequest: async () => {
      throw new Error('signRequest is not used by the store')
    },
  }
}

const tick = () => new Promise<void>((r) => setTimeout(r, 0))

describe('createStore — async race (3.5)', () => {
  it('does not let a slower older connect overwrite a newer connect', async () => {
    const slow = connector('slow', identity('did:slow'), 50)
    const fast = connector('fast', identity('did:fast'), 0)
    const store = createStore()
    const config = createConfig([slow, fast])

    // The slow connect starts first but resolves LAST; the fast one must win.
    await Promise.all([store.connect(config, 'slow'), store.connect(config, 'fast')])

    const s = store.getState()
    expect(s.status).toBe('connected')
    expect(s.connectorId).toBe('fast')
    expect(s.identity?.did).toBe('did:fast')
  })

  it('ignores a connect that resolves after a disconnect', async () => {
    const slow = connector('slow', identity('did:slow'), 30)
    const store = createStore()
    const config = createConfig([slow])

    const pending = store.connect(config, 'slow')
    store.disconnect() // invalidates the in-flight connect
    await pending

    expect(store.getState().status).toBe('idle')
    expect(store.getState().identity).toBeUndefined()
  })

  it('keeps only the newest reconnect when account changes race', async () => {
    const em = createEventEmitter()
    const resolvers: Array<(id: AnpIdentity) => void> = []
    const c: AnpConnector = {
      id: 'c',
      name: 'c',
      type: 'anp-dev-shim',
      isAvailable: () => Promise.resolve(true),
      getIdentity: () => new Promise<AnpIdentity>((resolve) => resolvers.push(resolve)),
      signRequest: async () => {
        throw new Error('signRequest is not used by the store')
      },
      events: em,
    }
    const store = createStore()
    const config = createConfig([c])

    const connectPromise = store.connect(config, 'c')
    await tick() // isAvailable resolves, getIdentity is called → resolvers[0]
    resolvers[0](identity('did:first'))
    await connectPromise
    expect(store.getState().identity?.did).toBe('did:first')

    // Two account changes launch two reconnects; the older one must not win.
    em.emit({ type: 'accountsChanged', payload: ['x'] })
    em.emit({ type: 'accountsChanged', payload: ['y'] })
    await tick() // both reconnects reach getIdentity → resolvers[1], resolvers[2]
    expect(resolvers.length).toBe(3)

    // Resolve the NEWER reconnect first, then the older one.
    resolvers[2](identity('did:newer'))
    await tick()
    resolvers[1](identity('did:older'))
    await tick()

    expect(store.getState().identity?.did).toBe('did:newer')
  })

  it('a disconnect invalidates an in-flight reconnect so the wallet cannot re-commit', async () => {
    const em = createEventEmitter()
    const resolvers: Array<(id: AnpIdentity) => void> = []
    const c: AnpConnector = {
      id: 'c',
      name: 'c',
      type: 'anp-dev-shim',
      isAvailable: () => Promise.resolve(true),
      getIdentity: () => new Promise<AnpIdentity>((resolve) => resolvers.push(resolve)),
      signRequest: async () => {
        throw new Error('signRequest is not used by the store')
      },
      events: em,
    }
    const store = createStore()
    const config = createConfig([c])

    const connectPromise = store.connect(config, 'c')
    await tick() // isAvailable resolves, getIdentity is called → resolvers[0]
    resolvers[0](identity('did:first'))
    await connectPromise
    expect(store.getState().status).toBe('connected')

    // An account change starts a reconnect, then the wallet disconnects before it resolves.
    em.emit({ type: 'accountsChanged', payload: ['x'] })
    await tick() // reconnect reaches getIdentity → resolvers[1]
    em.emit({ type: 'disconnect' })
    expect(store.getState().status).toBe('idle')
    expect(store.getState().identity).toBeUndefined()

    // The reconnect resolves AFTER the disconnect; it must not resurrect an identity.
    resolvers[1](identity('did:second'))
    await tick()
    expect(store.getState().status).toBe('idle')
    expect(store.getState().identity).toBeUndefined()
  })
})
