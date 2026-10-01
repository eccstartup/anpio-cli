// The library surface of `packages/service`.
//
// `@agentx/service` is mostly a binary (`agentx`), so this file exists for the two callers
// that are not a shell: a test that wants the service in-process, and a deployment that
// embeds it. Every name is listed explicitly rather than re-exported wholesale, so a new
// export inside a module does not silently become public contract.

export { loadConfig, didWebFor } from './config'
export type { Config, DidResolution, ListenAddress } from './config'

export { createServer, RPC_PATH, STREAM_PATH, WELL_KNOWN_PATH } from './http/server'
export type { RpcHandler, RpcRequest, RpcResponse, RunningServer, ServerOptions } from './http/server'

export { parseRequestText, failureId, errorResponse, successResponse, noResponse } from './rpc/envelope'
export type { ParseResult, ParsedRequest } from './rpc/envelope'

export { authenticate, callerAnchor, DIRECT_AUTH_CODES, P1_AUTH_CODES } from './rpc/auth'
export type { AuthErrorCodes, AuthResult, AuthenticateInput, ProfileCode } from './rpc/auth'

export { acceptOperation } from './rpc/accept'
export type { Acceptance, AcceptInput } from './rpc/accept'

export { createDispatch } from './rpc/dispatch'
export type { DispatchDeps } from './rpc/dispatch'

export { checkMethod, lookupMethod, targetBindingHolds, DIRECT_SEND } from './rpc/methods'
export type { MetaField, MethodSpec, TargetMode } from './rpc/methods'

export { storeDirectMessage, incomingParams, validateDirectBody } from './rpc/direct'
export type { StoreDirectInput } from './rpc/direct'

export { openStorage } from './storage/sqlite'
export type { OpenStorageOptions } from './storage/sqlite'
export { SCHEMA, SCHEMA_VERSION } from './storage/schema'
export type {
  DeliveryRecord,
  IdempotencyRow,
  OutboxEntry,
  Storage,
  StoredMessage,
} from './storage/types'
