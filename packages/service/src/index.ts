// The library surface of `packages/service`.
//
// `@agentx/service` is mostly a binary (`agentx`), so this file exists for the two callers
// that are not a shell: a test that wants the service in-process, and a deployment that
// embeds it. Every name is listed explicitly rather than re-exported wholesale, so a new
// export inside a module does not silently become public contract.

export { loadConfig, didWebFor } from './config'
export type { Config, DidResolution, ListenAddress } from './config'

export { buildServiceEntry } from './well-known'
export type { ServiceEntry } from './well-known'
export { serviceCapabilities } from './capabilities'
export type { ServiceCapabilities } from './capabilities'

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

export { checkMethod, lookupMethod, targetBindingHolds, DIRECT_SEND, GET_CAPABILITIES } from './rpc/methods'
export type { MetaField, MethodSpec, TargetMode } from './rpc/methods'

export { storeDirectMessage, incomingParams, DIRECT_INCOMING } from './rpc/direct'
export type { IncomingParamsInput, StoreDirectInput } from './rpc/direct'

export { validatePayloadBody, ACCEPTED_CONTENT_TYPES, PAYLOAD_FIELDS } from './rpc/payload'

export { EXTENSION_PROFILE, SYNC_DELTA, readDelta, validateDeltaBody } from './rpc/inbox'

export {
  GROUP_ADD,
  GROUP_CREATE,
  GROUP_GET_INFO,
  GROUP_HANDLERS,
  GROUP_INCOMING,
  GROUP_JOIN,
  GROUP_LEAVE,
  GROUP_PROFILE,
  GROUP_REMOVE,
  GROUP_SECURITY_PROFILE,
  GROUP_SEND,
  GROUP_STATE_CHANGED,
  GROUP_UPDATE_POLICY,
  GROUP_UPDATE_PROFILE,
} from './rpc/groups'
export type { GroupContext, GroupHandler } from './rpc/groups'
export { AnpRefusal, refusal } from './rpc/refusal'
export { groupMethodNames } from './rpc/methods'

export {
  ATTACHMENT_ABORT_OBJECT,
  ATTACHMENT_COMMIT_OBJECT,
  ATTACHMENT_CREATE_SLOT,
  ATTACHMENT_GET_DOWNLOAD_TICKET,
  ATTACHMENT_HANDLERS,
  ATTACHMENT_MANIFEST_CONTENT_TYPE,
  ATTACHMENT_PROFILE,
  ATTACHMENT_SECURITY_PROFILE,
  OBJECTS_PATH,
  SLOT_TTL_MS,
  TICKET_TTL_MS,
  UPLOAD_PATH,
  attachmentError,
  attachmentGrantsFor,
  insertAttachmentGrants,
  manifestAttachments,
  objectUriFor,
} from './rpc/attachments'
export type { AttachmentContext, AttachmentHandler, GrantInput } from './rpc/attachments'

export { createDataPlane } from './dataplane'
export type { DataPlaneDeps, DataPlaneHandler, DataPlaneRequest, DataPlaneResponse } from './dataplane'

export { openObjectStore, isObjectDigest, ObjectTooLargeError } from './objects'
export type { ObjectStore, OpenObjectStoreOptions, StagedObject } from './objects'

export { createDeliveryWorker } from './delivery/worker'
export type { DeliveryOptions, DeliveryWorker } from './delivery/worker'

export { createMemberDidRefreshWorker } from './refresh/memberDidRefresh'
export type { MemberDidRefreshOptions, MemberDidRefreshWorker } from './refresh/memberDidRefresh'

export { openStorage } from './storage/sqlite'
export type { OpenStorageOptions } from './storage/sqlite'
export { SCHEMA, SCHEMA_VERSION } from './storage/schema'
export type {
  DeliveryRecord,
  IdempotencyRow,
  OutboxEntry,
  Storage,
  StoredAttachmentGrant,
  StoredAttachmentObject,
  StoredAttachmentSlot,
  StoredDownloadTicket,
  StoredGroup,
  StoredGroupEvent,
  StoredGroupMember,
  StoredMessage,
} from './storage/types'
