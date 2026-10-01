// The library surface of `packages/service`.
//
// `@agentx/service` is mostly a binary (`agentx`), so this file exists for the two callers
// that are not a shell: a test that wants the service in-process, and a deployment that
// embeds it. Every name is listed explicitly rather than re-exported wholesale, so a new
// export inside a module does not silently become public contract.

export { loadConfig, didWebFor } from './config'
export type { Config, DidResolution, ListenAddress } from './config'

export { createServer, RPC_PATH, STREAM_PATH, WELL_KNOWN_PATH } from './http/server'
export type {
  RpcHandler,
  RpcRequest,
  RpcResponse,
  RunningServer,
  ServerOptions,
  StreamHandler,
} from './http/server'

export { createSubscriberRegistry, notificationFrame } from './stream/registry'
export type { SubscriberRegistry, SubscriberTarget, Subscription } from './stream/registry'
export { CLOSE_GOING_AWAY, CLOSE_TRY_AGAIN_LATER, acceptKey, isWebSocketUpgrade, upgrade } from './stream/ws'
export type { WebSocketConnection, WebSocketHandlers } from './stream/ws'
export { createStreamSession, STREAM_PROFILES } from './stream/session'
export type { StreamSession, StreamSessionDeps } from './stream/session'

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

export { storeDirectMessage, incomingParams, validateDirectBody, DIRECT_INCOMING } from './rpc/direct'
export type { IncomingParamsInput, StoreDirectInput } from './rpc/direct'

export {
  EXTENSION_PROFILE,
  INBOX_GET,
  INBOX_MARK_READ,
  MESSAGE_GET_BATCH,
  SYNC_DELTA,
  markRead,
  readBatch,
  readDelta,
  readInbox,
  validateDeltaBody,
  validateGetBatchBody,
  validateInboxGetBody,
  validateMarkReadBody,
} from './rpc/inbox'

export { createDeliveryWorker } from './delivery/worker'
export type { DeliveryOptions, DeliveryWorker } from './delivery/worker'

export { openStorage } from './storage/sqlite'
export type { OpenStorageOptions } from './storage/sqlite'
export { SCHEMA, SCHEMA_VERSION } from './storage/schema'
export type {
  DeliveryRecord,
  IdempotencyRow,
  InboxQuery,
  InboxRow,
  OutboxEntry,
  Storage,
  StoredMessage,
} from './storage/types'
