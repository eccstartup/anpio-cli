import type { AnpConfig, AnpIdentity, AnpStatus } from './types'
import { selectWallet } from './config'
import { ConnectorUnavailableError } from './errors'
import type { WalletEvent } from './events'

// Framework-agnostic connection store: a publish/subscribe state machine that
// tracks which connector is connected and the resolved identity. It is an
// OPTIONAL upper layer — `login()` / `signRequest()` / `register()` remain stateless
// and callable directly. React hooks (phase 3) subscribe to this store.
//
// Lifecycle: idle → connecting → connected → disconnecting → idle.
// `signing` / `error` are set during login and reset by connect/disconnect.
//
// The store also bridges connector wallet events: `accountsChanged` /
// `chainChanged` / `disconnect` update the state, and `reconnect()` re-connects
// the last-used connector (autoReconnect after a page reload).

export interface AnpStoreState {
  status: AnpStatus
  /** The connector that is (or is being) connected. */
  connectorId?: string
  /** The resolved identity once connected. */
  identity?: AnpIdentity
  /** Last error, if any. */
  error?: Error
}

export interface AnpStore {
  getState(): AnpStoreState
  /** Subscribe to state changes. Returns an unsubscribe function. */
  subscribe(listener: (state: AnpStoreState) => void): () => void
  /** Connect a connector: feature-detect, resolve identity, set `connected`. */
  connect(config: AnpConfig, connectorId?: string): Promise<AnpStoreState>
  /** Disconnect: clear identity, return to `idle`. */
  disconnect(): AnpStoreState
  /** Re-connect the last-used connector (for autoReconnect after a reload). */
  reconnect(config: AnpConfig): Promise<AnpStoreState>
}

export function createStore(): AnpStore {
  let state: AnpStoreState = { status: 'idle' }
  let lastConnectorId: string | undefined
  let lastConfig: AnpConfig | undefined
  let unsubscribeEvents: (() => void) | undefined
  // Monotonic token, bumped on every connect/disconnect/reconnect. An async
  // connect/reconnect only commits state if it is still the CURRENT generation, so
  // a slower, older connect — or an account/chain change that launched a newer
  // reconnect — can never overwrite the identity a newer operation just resolved.
  let generation = 0
  const listeners = new Set<(state: AnpStoreState) => void>()

  function setState(next: Partial<AnpStoreState>): AnpStoreState {
    state = { ...state, ...next }
    for (const l of listeners) l(state)
    return state
  }

  async function reconnectFrom(connectorId: string): Promise<AnpStoreState> {
    if (!lastConfig) return state
    const connector = selectWallet(lastConfig, connectorId)
    const gen = ++generation
    setState({ status: 'connecting', connectorId, identity: undefined, error: undefined })
    try {
      if (!(await connector.isAvailable())) {
        throw new ConnectorUnavailableError(connectorId)
      }
      const identity = await connector.getIdentity()
      if (gen !== generation) return state // superseded — leave the newer state alone
      setState({ status: 'connected', identity })
      return state
    } catch (err) {
      if (gen !== generation) return state // superseded — don't clobber a newer result
      const error = err instanceof Error ? err : new Error(String(err))
      setState({ status: 'error', identity: undefined, error })
      return state
    }
  }

  // Bridge a connector's wallet events into store state changes.
  function bindEvents(connectorId: string, emit?: { on(l: (e: WalletEvent) => void): () => void }) {
    unsubscribeEvents?.()
    unsubscribeEvents = undefined
    if (!emit) return
    unsubscribeEvents = emit.on((event) => {
      if (event.type === 'disconnect') {
        // A disconnect must invalidate any in-flight account/chain reconnect, which
        // would otherwise still commit an identity after the wallet went idle. Bump
        // the generation and unbind the events so the disconnected connector can no
        // longer drive the store.
        generation++
        unsubscribeEvents?.()
        unsubscribeEvents = undefined
        setState({ status: 'idle', connectorId: undefined, identity: undefined, error: undefined })
      } else if (event.type === 'accountsChanged' || event.type === 'chainChanged') {
        // Account or chain changed under the same connector — reconnect to refresh
        // the identity. The DID is the CAIP-10 account id `chain:address`, so both
        // a new address and a new chain change the identity and must re-resolve.
        // `reconnectFrom` bumps the generation so an older in-flight connect loses.
        void reconnectFrom(connectorId)
      }
    })
  }

  return {
    getState: () => state,

    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },

    async connect(config, connectorId) {
      const connector = selectWallet(config, connectorId)
      lastConnectorId = connector.id
      lastConfig = config
      const gen = ++generation
      setState({ status: 'connecting', connectorId: connector.id, identity: undefined, error: undefined })
      try {
        if (!(await connector.isAvailable())) {
          throw new ConnectorUnavailableError(connector.id)
        }
        const identity = await connector.getIdentity()
        if (gen !== generation) return state // superseded — leave the newer state alone
        bindEvents(connector.id, connector.events)
        setState({ status: 'connected', identity })
        return state
      } catch (err) {
        if (gen !== generation) return state // superseded — don't clobber a newer result
        const error = err instanceof Error ? err : new Error(String(err))
        setState({ status: 'error', identity: undefined, error })
        return state
      }
    },

    disconnect() {
      generation++ // invalidate any in-flight connect/reconnect
      unsubscribeEvents?.()
      unsubscribeEvents = undefined
      return setState({ status: 'idle', connectorId: undefined, identity: undefined, error: undefined })
    },

    async reconnect(config) {
      if (config) lastConfig = config
      if (!lastConnectorId) return state
      return reconnectFrom(lastConnectorId)
    },
  }
}
