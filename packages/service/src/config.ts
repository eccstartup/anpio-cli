// AgentXAgent's configuration, read from the environment.
//
// The names and defaults are message-service.md §14 verbatim. Two of them are not
// values but derivations (`AGENTX_SERVICE_DID` from the public URL, the public URL
// itself from the listen address), and both are resolved here so that no other module
// has to know how a deployment gets a service DID.
//
// The rule §14 states in prose is enforced by what this file does NOT have: there is no
// switch that turns `origin_proof` verification off. A local integration test relaxes the
// DID resolution policy instead, which is a policy on the resolver and not a hole in the
// auth path.

import { ConnectxError } from '@agentx/core'

/** 1 MiB, §14. Attachments travel on the data plane and never through this limit. */
const DEFAULT_MAX_BODY = 1024 * 1024

const DEFAULT_LISTEN = '127.0.0.1:8787'
const DEFAULT_DB = './agentx.db'

export interface ListenAddress {
  host: string
  port: number
}

export interface Config {
  /** Where the HTTP server binds. */
  listen: ListenAddress
  /** The externally visible base URL, `https://host[:port][/path]`, with no trailing
   *  slash. `serviceEndpoint` and `object_uri` are built from it. */
  publicUrl: string
  /** This service's own DID: `AGENTX_SERVICE_DID`, else `did:web` of the public URL.
   *  It is what a cross-domain caller authenticates and the `did` of `group.create`'s
   *  target (P4 §8.1.2 L625). */
  serviceDid: string
  /** The key that signs outbound cross-domain requests (P8, C11). Absent means this
   *  deployment does not call other domains. */
  keyFile?: string
  /** SQLite file, or `:memory:`. */
  dbPath: string
  /** Where attachment objects are written (P7, C10). */
  objectDir?: string
  /** Request body cap in bytes. */
  maxBody: number
}

/** `host:port`, with the host allowed to be an IPv6 literal in brackets. The port is
 *  required: a listen address with no port has no default this file can invent, and
 *  guessing 8787 would silently bind somewhere the operator did not name. */
function parseListen(raw: string): ListenAddress {
  const ipv6 = /^\[([^\]]+)\]:(\d+)$/.exec(raw)
  const hostPort = ipv6 ?? /^(.+):(\d+)$/.exec(raw)
  if (hostPort === null) {
    throw new ConnectxError(
      'invalid_argument',
      `AGENTX_LISTEN must be host:port (got ${JSON.stringify(raw)}); for example 127.0.0.1:8787`,
    )
  }
  const port = Number(hostPort[2])
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new ConnectxError('invalid_argument', `AGENTX_LISTEN port must be 0-65535 (got ${hostPort[2]})`)
  }
  return { host: hostPort[1], port }
}

/** A positive integer, or the default when the variable is absent. An empty string is
 *  treated as absent: `AGENTX_MAX_BODY= ` is a shell accident, not a request for 0. */
function parsePositive(raw: string | undefined, name: string, fallback: number): number {
  if (raw === undefined || raw === '') return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConnectxError('invalid_argument', `${name} must be a positive integer (got ${JSON.stringify(raw)})`)
  }
  return value
}

/** The public base URL with any trailing slash removed, so `publicUrl + '/anp-im/rpc'`
 *  is one slash and not two. */
function normalizeUrl(raw: string, name: string): string {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new ConnectxError('invalid_argument', `${name} must be an absolute URL (got ${JSON.stringify(raw)})`)
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ConnectxError('invalid_argument', `${name} must be http or https (got ${url.protocol})`)
  }
  return raw.replace(/\/+$/, '')
}

/**
 * `did:web` for a public URL, per the did:web method: the host becomes the first
 * identifier segment, with `:` percent-encoded, and each path segment follows as its own
 * `:`-separated segment.
 *
 *   https://agentx.example            -> did:web:agentx.example
 *   http://localhost:8787             -> did:web:localhost%3A8787
 *   https://example.com/agentx/inbox  -> did:web:example.com:agentx:inbox
 *
 * The path is percent-decoded before it is appended, because the DID document is served
 * at the decoded path and the two spellings would otherwise name different DIDs.
 */
export function didWebFor(publicUrl: string): string {
  const url = new URL(publicUrl)
  const segments = url.pathname.split('/').filter((segment) => segment !== '').map(decodeURIComponent)
  return ['did:web', url.host.replace(/:/g, '%3A'), ...segments].join(':')
}

/** The public URL a bare listen address implies: loopback binds are a development
 *  setup, and anything else is reached over TLS by its own host. A non-loopback host
 *  with a derived `http://` URL is refused rather than guessed at, because a public
 *  service DID resting on a plaintext endpoint is worse than a startup failure. */
function impliedPublicUrl(listen: ListenAddress): string {
  const loopback = listen.host === '127.0.0.1' || listen.host === '::1' || listen.host === 'localhost'
  if (loopback) return `http://${listen.host === '::1' ? '[::1]' : listen.host}:${listen.port}`
  throw new ConnectxError(
    'invalid_argument',
    `AGENTX_PUBLIC_URL is required when AGENTX_LISTEN is not a loopback address ` +
      `(got ${listen.host}); this service's DID and the endpoints it hands out are derived from it`,
  )
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const listen = parseListen(env.AGENTX_LISTEN ?? DEFAULT_LISTEN)
  const publicUrl = normalizeUrl(env.AGENTX_PUBLIC_URL ?? impliedPublicUrl(listen), 'AGENTX_PUBLIC_URL')

  const config: Config = {
    listen,
    publicUrl,
    serviceDid: env.AGENTX_SERVICE_DID ?? didWebFor(publicUrl),
    dbPath: env.AGENTX_DB ?? DEFAULT_DB,
    maxBody: parsePositive(env.AGENTX_MAX_BODY, 'AGENTX_MAX_BODY', DEFAULT_MAX_BODY),
  }
  if (env.AGENTX_KEY_FILE !== undefined && env.AGENTX_KEY_FILE !== '') config.keyFile = env.AGENTX_KEY_FILE
  if (env.AGENTX_OBJECT_DIR !== undefined && env.AGENTX_OBJECT_DIR !== '') config.objectDir = env.AGENTX_OBJECT_DIR
  return config
}
