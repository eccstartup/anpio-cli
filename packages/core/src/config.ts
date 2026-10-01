import type { AnpConfig, AnpConnector } from './types'
import { ConnectxError } from './errors'

// Configure the SDK with a set of connectors. This is the agent's single "pick a
// wallet configuration" entry point: which wallets are available, and which one
// is the default. Signing / registering / logging in all use the same
// connectors — an agent never branches on ANP vs web3.
export function createConfig(
  connectors: AnpConnector[],
  defaultConnectorId?: string,
): AnpConfig {
  if (defaultConnectorId && !connectors.some((c) => c.id === defaultConnectorId)) {
    throw new ConnectxError(
      'invalid_argument',
      `defaultConnectorId "${defaultConnectorId}" does not match any configured connector`,
    )
  }
  return { connectors, defaultConnectorId }
}

// Select a connector by id, falling back to the config's default. Returns the
// connector's own `signRequest` — the same uniform operation regardless of wallet.
export function selectWallet(
  config: AnpConfig,
  connectorId?: string,
): AnpConnector {
  const id = connectorId ?? config.defaultConnectorId ?? config.connectors[0]?.id
  const connector = config.connectors.find((c) => c.id === id)
  if (!connector) {
    throw new ConnectxError('no_connector_selected', `No connector selected (requested "${connectorId ?? ''}")`)
  }
  return connector
}
