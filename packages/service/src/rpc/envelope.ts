// The inbound half of the control plane: request text in, JSON-RPC response text out.
//
// The validation itself is core's `parseEnvelope` — it is shared with the CLI, which
// builds the same envelopes, and having two readings of P1 §4–§6 is how a service ends up
// accepting what its own client would refuse. What lives here is the part the CLI has no
// use for: a TEXT arrives rather than an object, and every failure has to leave as a
// response with the right `id`.
//
// Two rows of message-service.md §3 are NOT here, both because they need the method's own
// declaration rather than the envelope alone: the target modelling mode (§6.2.5.1 L382) and
// the decimal-string counters of §7.3 L491–499. They arrive with the method table in C5.

import {
  JSON_RPC_ERROR,
  parseEnvelope,
  rpcRejection,
  toErrorObject,
  type AnpNotification,
  type AnpRejection,
  type AnpRequest,
} from '@anpio-cli/core'
import type { RpcResponse } from '../http/server'

// `AnpRequest` is structurally an `AnpNotification` plus an `id`, so this union is NOT
// narrowed by a type guard (`isNotification` in the negative leaves `never`); discriminate
// with `'id' in value` instead. Same reason the two members are written out rather than
// aliased to core's own union.
export type ParsedRequest = AnpRequest | AnpNotification

export type ParseResult = { ok: true; value: ParsedRequest } | { ok: false; error: AnpRejection }

function responds(value: unknown): RpcResponse {
  return { status: 200, contentType: 'application/json', body: JSON.stringify(value) }
}

/**
 * Parse the request body.
 *
 * A body that is not JSON is answered with `-32700` before anything else is looked at:
 * there is no envelope to read a field from, which is also why that one response carries a
 * null `id` (§5.6 L203 can only be honoured for a request that was understood).
 */
export function parseRequestText(text: string): ParseResult {
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    return { ok: false, error: rpcRejection(JSON_RPC_ERROR.PARSE_ERROR, 'Parse error') }
  }
  return parseEnvelope(raw)
}

/**
 * The `id` to put on a failure response, taken from the request text.
 *
 * §5.6 L203 requires a response to carry the request's `id`, so a request that failed on
 * anything but its `id` still gets its own back. The exceptions are the two cases where
 * there is no usable id: a body that never parsed, and an `id` that was itself the
 * violation — echoing a number or null there would break §5.2 L157–159 in the response too.
 */
export function failureId(text: string, error: AnpRejection): string | null {
  if (error.anpCode === 'anp.invalid_request_id') return null
  try {
    const raw: unknown = JSON.parse(text)
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
    const id = (raw as Record<string, unknown>).id
    return typeof id === 'string' && id !== '' ? id : null
  } catch {
    return null
  }
}

/** A JSON-RPC error response carrying an ANP rejection (§10.2 L681–693). */
export function errorResponse(id: string | null, error: AnpRejection): RpcResponse {
  return responds({ jsonrpc: '2.0', id, error: toErrorObject(error) })
}

export function successResponse(id: string, result: unknown): RpcResponse {
  return responds({ jsonrpc: '2.0', id, result })
}

/**
 * §5.3 L162 + §5.6 L201: a Notification (a request with no `id`) is answered with nothing
 * at all — not even an error. The HTTP status is still 200, because the exchange happened;
 * there is just no JSON-RPC response object in it.
 */
export function noResponse(): RpcResponse {
  return { status: 200, body: '' }
}
