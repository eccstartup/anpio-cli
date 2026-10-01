#!/usr/bin/env node
// The `agentx` executable.
//
// It does three things: read the environment, open the storage, and hand the HTTP layer a
// handler. The handler validates the envelope (C2) and then finds no dispatcher behind it,
// so a well-formed request gets `-32601` — an incomplete service rather than a wrong one.
// C5 replaces the last step and nothing else here changes.
//
// The shebang is what makes `node dist/main.js` work without going through the `bin` shim;
// relative imports stay extensionless (house style, `moduleResolution: Bundler`), which is
// why this file is only runnable after `tsup` rather than straight from `src/`.

import { ConnectxError, JSON_RPC_ERROR, rpcRejection } from '@agentx/core'
import { loadConfig } from './config'
import { createServer } from './http/server'
import { errorResponse, failureId, noResponse, parseRequestText } from './rpc/envelope'
import { openStorage } from './storage/sqlite'
import type { RpcRequest, RpcResponse } from './http/server'

/**
 * Validate the envelope, then look for a method to run.
 *
 * There is nothing to dispatch to yet, so every method that survives validation is
 * `-32601`. That is the spec's own answer for a method this service does not have, and the
 * service really does not have it — C5 is where the methods arrive.
 */
function handleRpc(request: RpcRequest): RpcResponse {
  const text = request.body
  const parsed = parseRequestText(text)
  if (!parsed.ok) return errorResponse(failureId(text, parsed.error), parsed.error)

  // `'id' in` rather than core's `isNotification` guard: `AnpRequest` is structurally a
  // subtype of `AnpNotification`, so a type guard over the union narrows the else branch
  // to `never` instead of to `AnpRequest`.
  const envelope = parsed.value
  if (!('id' in envelope)) return noResponse()

  return errorResponse(
    envelope.id,
    rpcRejection(JSON_RPC_ERROR.METHOD_NOT_FOUND, `Method not found: ${envelope.method}`),
  )
}

async function main(): Promise<void> {
  const config = loadConfig()
  const storage = openStorage({ path: config.dbPath })
  const server = createServer({ config, handleRpc })

  try {
    await server.listen()
  } catch (err) {
    // The socket never opened, so nothing was written and nothing needs closing.
    storage.close()
    throw err
  }

  process.stdout.write(`AgentXAgent listening on http://${server.address.host}:${server.address.port}\n`)
  process.stdout.write(`  service did   ${config.serviceDid}\n`)
  process.stdout.write(`  rpc           ${config.publicUrl}/anp-im/rpc\n`)
  process.stdout.write(`  database      ${config.dbPath}\n`)

  let closing = false
  const shutdown = (signal: string): void => {
    if (closing) return
    closing = true
    process.stdout.write(`\n${signal}: shutting down\n`)
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
