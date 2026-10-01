// Framework-agnostic event bus. Connectors and wallets emit lifecycle events
// (`accountsChanged`, `chainChanged`, `disconnect`); the store and React layer
// subscribe to react to them. No framework imports — works in Node and browsers.

export type WalletEventType = 'accountsChanged' | 'chainChanged' | 'disconnect'

export interface WalletEvent {
  type: WalletEventType
  /** Event payload — new account(s), new chain id, or nothing for disconnect. */
  payload?: unknown
}

export interface EventEmitter {
  /** Register a listener. Returns an unsubscribe function. */
  on(listener: (event: WalletEvent) => void): () => void
  /** Remove a specific listener (or all if omitted). */
  off(listener?: (event: WalletEvent) => void): void
  /** Emit an event to all listeners. */
  emit(event: WalletEvent): void
}

export function createEventEmitter(): EventEmitter {
  const listeners = new Set<(event: WalletEvent) => void>()
  return {
    on(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    off(listener) {
      if (listener) listeners.delete(listener)
      else listeners.clear()
    },
    emit(event) {
      for (const l of listeners) l(event)
    },
  }
}
