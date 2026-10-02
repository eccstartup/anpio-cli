#!/usr/bin/env node
// The `agentx` executable.
//
// It does four things: read the environment, open the storage, build the dispatcher that
// accepts control-plane calls (C5), and hand the HTTP layer that handler. Everything a
// request can be refused for lives behind `createDispatch`; this file owns the process —
// the socket, the log lines, and the shutdown.
//
// The shebang is what makes `node dist/main.js` work without going through the `bin` shim;
// relative imports stay extensionless (house style, `moduleResolution: Bundler`), which is
// why this file is only runnable after `tsup` rather than straight from `src/`.

import { ConnectxError } from '@agentx/core'
import { loadConfig } from './config'
import { createDataPlane } from './dataplane'
import { createDeviceQueueWorker } from './delivery/deviceQueue'
import { createDeliveryWorker } from './delivery/worker'
import { createEgress } from './federation/egress'
import { createRelay } from './federation/forward'
import { loadHttpSigner } from './federation/signing'
import { createServer } from './http/server'
import { openObjectStore } from './objects'
import { createMemberDidRefreshWorker } from './refresh/memberDidRefresh'
import { createDispatch } from './rpc/dispatch'
import { openStorage } from './storage/sqlite'
import { createSubscriberRegistry } from './stream/registry'
import { createStreamSession } from './stream/session'
import { buildServiceEntry } from './well-known'
import type { RpcHandler } from './http/server'

async function main(): Promise<void> {
  const config = loadConfig()
  const storage = openStorage({ path: config.dbPath })
  // Opened at startup rather than lazily on the first upload: a directory that cannot be
  // created should fail here, not after a client has already been handed an `upload_uri`.
  const objects = openObjectStore({ directory: config.objectDir, maxBytes: config.maxObjectBytes })

  // The two halves of one accepted message: the dispatcher writes it and commits, then
  // hands the delivery here, and the registry writes it to whichever connections are
  // watching that mailbox (realtime.md §8.1). Nothing is published from inside the
  // transaction — see `dispatch.ts`'s `publish`.
  const registry = createSubscriberRegistry()
  // Outbound cross-domain requests (P8, C11). The signer is absent unless the deployment
  // configured a key; without it the calls still go out, unsigned (§2.3).
  const signer = await loadHttpSigner(config)
  const egress = createEgress({ config, ...(signer !== undefined ? { signer } : {}) })
  const handleRpc: RpcHandler = createDispatch({
    config,
    storage,
    objects,
    relay: createRelay({ config, egress }),
    onDelivered: (record) => {
      registry.publish(record)
    },
  })
  // The two byte routes of P7 §11. They are the only place in this process that puts a
  // non-string body on a socket.
  const dataPlane = createDataPlane({ storage, objects, publicUrl: config.publicUrl })
  const session = createStreamSession({
    serverDid: config.serviceDid,
    storage,
    registry,
    handleRpc,
    resolverOptions: config.didResolution,
  })
  const server = createServer({
    config,
    handleRpc,
    handleStream: (connection, request) => session.handlersFor(connection, request),
    handleUpload: dataPlane.handleUpload,
    handleObject: dataPlane.handleObject,
    // A pure function of the configuration and the method table, so it is built once. The
    // DID Service fetches this to embed as the agent's `ANPMessageService` entry
    // (message-service.md §13) — this service never writes a DID document itself.
    wellKnown: JSON.stringify(buildServiceEntry(config), null, 2),
  })
  // Outbound `direct.incoming` pushes. Started only after the socket is up: a startup
  // that fails should exit without a background timer having already spent attempts.
  const delivery = createDeliveryWorker({ config, storage })
  // P6's device-addressed envelopes (§12.6). A separate queue and a separate worker by
  // design: this one is keyed by `(recipient_did, recipient_device_id)` and must not fan
  // out to a sibling device, so it cannot ride the DID-keyed outbox above. It does need the
  // registry, because a P6 envelope has no `deliveries` row to push off when the recipient
  // is one of this service's own devices.
  const deviceQueue = createDeviceQueueWorker({ config, storage, registry })
  // §8.12's third trigger (§8.12 L946): the periodic sweep that notices a member's DID moved
  // on even when that member is quiet — no request, no envelope to deliver. Slow by design
  // (`Config.memberDidRefresh`), and separate from the two queues above because its period is
  // four orders of magnitude longer.
  const memberDidRefresh = createMemberDidRefreshWorker({ config, storage })

  try {
    await server.listen()
  } catch (err) {
    // The socket never opened, so nothing was written and nothing needs closing.
    storage.close()
    throw err
  }
  delivery.start()
  deviceQueue.start()
  memberDidRefresh.start()

  process.stdout.write(`AgentXAgent listening on http://${server.address.host}:${server.address.port}\n`)
  process.stdout.write(`  service did   ${config.serviceDid}\n`)
  process.stdout.write(`  rpc           ${config.publicUrl}/anp-im/rpc\n`)
  process.stdout.write(`  database      ${config.dbPath}\n`)
  process.stdout.write(`  objects       ${config.objectDir}\n`)
  // The deployment coupling federation.md §4 names: the keyid's fragment is decided by
  // whoever publishes this service's DID document, so an operator needs to see which one
  // this process is signing with — every outgoing request fails at the peer's step 6 if
  // it does not match.
  process.stdout.write(
    signer === undefined
      ? '  outbound      unsigned (no AGENTX_KEY_FILE)\n'
      : `  outbound      signed as ${signer.keyid}\n`,
  )
  // Outbound DID resolution is the one setting whose default is a closed door, so say so
  // at startup rather than let the first 2005 be the operator's introduction to it.
  process.stdout.write(
    config.didResolution.allowedHosts.length === 0
      ? '  did hosts     none (only inline DID documents will verify)\n'
      : `  did hosts     ${config.didResolution.allowedHosts.join(', ')}\n`,
  )

  let closing = false
  const shutdown = (signal: string): void => {
    if (closing) return
    closing = true
    process.stdout.write(`\n${signal}: shutting down\n`)
    delivery.stop()
    deviceQueue.stop()
    memberDidRefresh.stop()
    // Before `server.close()`: an upgraded socket is detached from the HTTP server, so its
    // `close()` waits for connections it cannot reach. Nowhere else can end these.
    session.closeAll('server shutting down')
    void server.close().then(() => {
      storage.close()
      process.exit(0)
    })
  }
  process.on('SIGINT', () => shutdown('SIGINT'))
  process.on('SIGTERM', () => shutdown('SIGTERM'))
}

main().catch((err: unknown) => {
  // A configuration mistake is the operator's to fix and its message names the variable;
  // anything else is a bug and gets the stack.
  if (err instanceof ConnectxError) {
    process.stderr.write(`${err.code}: ${err.message}\n`)
    process.exit(2)
  }
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`)
  process.exit(1)
})
