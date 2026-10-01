#!/usr/bin/env node
// The `agentx` executable.
//
// It does three things: read the environment, open the storage, and hand the HTTP layer a
// handler. Right now that handler has no dispatcher behind it, so a well-formed request
// gets `-32601` — an incomplete service rather than a wrong one. C2 replaces the body of
// `handleRpc` and nothing else here changes.
//
// The shebang is what makes `node dist/main.js` work without going through the `bin` shim;
// relative imports stay extensionless (house style, `moduleResolution: Bundler`), which is
// why this file is only runnable after `tsup` rather than straight from `src/`.

import { ConnectxError, JSONRPC_VERSION } from '@agentx/core'
import { loadConfig, type Config } from './config'
import { createServer } from './http/server'
import { openStorage } from './storage/sqlite'
import type { RpcRequest, RpcResponse } from './http/server'

function respond(value: unknown): RpcResponse {
  return { status: 200, contentType: 'application/json', body: JSON.stringify(value) }
}

/** A standard JSON-RPC error. No `data.anp_code`: §10.2 L695 requires it only for a code
 *  in the ANP range (1000+), and these are the standard negative ones. */
function rpcError(id: unknown, code: number, message: string): RpcResponse {
  return respond({ jsonrpc: JSONRPC_VERSION, id, error: { code, message } })
}

/** An ANP error, which carries `error.data.anp_code` (§10.2 L695) — that field is the only
 *  thing a client branches on, so it is never omitted. */
function anpError(id: unknown, code: number, anpCode: string, message: string): RpcResponse {
  return respond({
    jsonrpc: JSONRPC_VERSION,
    id,
    error: { code, message, data: { anp_code: anpCode, retryable: false, details: {} } },
  })
}

/**
 * Answer a request that no method implements yet.
 *
 * The cheap envelope rules are applied here because they decide whether there is a
 * response at all; the rest of §3 waits for C2. `id` is echoed back when it is valid,
 * because §5.6 L203 requires a response's `id` to equal the request's.
 */
function handleRpc(request: RpcRequest): RpcResponse {
  let parsed: unknown
  try {
    parsed = JSON.parse(request.body)
  } catch {
    return rpcError(null, -32700, 'Parse error')
  }
  // §5.4 L179: a batch MUST be rejected, and the answer is an `anp_code` rather than the
  // standard `-32600`. A batch has no single `id` to echo, so this one goes out as null.
  if (Array.isArray(parsed)) return anpError(null, 1004, 'anp.batch_not_supported', 'Batch requests are not supported')
  if (typeof parsed !== 'object' || parsed === null) return rpcError(null, -32600, 'Invalid Request')

  const envelope = parsed as Record<string, unknown>
  const id = envelope.id
  // §5.3 L162 + §5.6 L201: a Notification is a request with no `id`, and it gets no
  // response — not even an error.
  if (id === undefined) return { status: 200, body: '' }
  // §5.2 L157–159: `id` MUST be a non-empty string; a number or null is a violation. Both
  // of those are answered with a null id, since echoing the invalid one would break §5.2
  // in the response as well.
  if (typeof id !== 'string' || id === '') {
    return anpError(null, 1000, 'anp.invalid_request_id', 'id must be a non-empty string')
  }

  const method = typeof envelope.method === 'string' ? envelope.method : '(none)'
  return rpcError(id, -32601, `Method not found: ${method}`)
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
