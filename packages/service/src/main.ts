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
import { createDeliveryWorker } from './delivery/worker'
import { createServer } from './http/server'
import { createDispatch } from './rpc/dispatch'
import { openStorage } from './storage/sqlite'
import type { RpcHandler } from './http/server'

async function main(): Promise<void> {
  const config = loadConfig()
  const storage = openStorage({ path: config.dbPath })

  const handleRpc: RpcHandler = createDispatch({ config, storage })
  const server = createServer({ config, handleRpc })
  // Outbound `direct.incoming` pushes. Started only after the socket is up: a startup
  // that fails should exit without a background timer having already spent attempts.
  const delivery = createDeliveryWorker({ config, storage })

  try {
    await server.listen()
  } catch (err) {
    // The socket never opened, so nothing was written and nothing needs closing.
    storage.close()
    throw err
  }
  delivery.start()

  process.stdout.write(`AgentXAgent listening on http://${server.address.host}:${server.address.port}\n`)
  process.stdout.write(`  service did   ${config.serviceDid}\n`)
  process.stdout.write(`  rpc           ${config.publicUrl}/anp-im/rpc\n`)
  process.stdout.write(`  database      ${config.dbPath}\n`)
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
