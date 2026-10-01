// AgentXAgent's configuration, read from the environment.
//
// The names and defaults are message-service.md §14 verbatim. Two of them are not
// values but derivations (`AGENTX_SERVICE_DID` from the public URL, the public URL
// itself from the listen address), and both are resolved here so that no other module
// has to know how a deployment gets a service DID.
//
// The rule §14 states in prose is enforced by what this file does NOT have: there is no
// switch that turns `origin_proof` verification off. A local integration test relaxes the
// DID resolution policy instead — `AGENTX_DID_DEV_HOSTS` names hosts that may be private
// or speak plain http — which is a policy on the resolver and not a hole in the auth path.
// Those hosts still have to be named one by one, so no value of it makes resolution
// unbounded; the allowlist is exact at every setting.

import { ConnectxError } from '@agentx/core'

/** 1 MiB, §14. Attachments travel on the data plane and never through this limit. */
const DEFAULT_MAX_BODY = 1024 * 1024

const DEFAULT_LISTEN = '127.0.0.1:8787'
const DEFAULT_DB = './agentx.db'

export interface ListenAddress {
  host: string
  port: number
}

/**
 * 远程解析 DID 文档时的网络边界。字段与 core 的 `ResolveDidOptions` 同名，所以这里算出来
 * 的就是解析器选项本身，中间不再有一层转写。
 *
 * core 把 `allowedHosts` 定成**必填**的（`resolveDid.ts:431`：清单为空就拒绝任何远程解析），
 * 所以这里没有"不填就放行"这一档。两个变量都不设时本服务只认内联文档、一封外来消息都验
 * 不过——对消息服务来说，"什么也解析不了"是安全的，"什么都能解析"不是，缺省落在前者。
 */
export interface DidResolution {
  /** 精确主机名，没有通配。 */
  allowedHosts: string[]
  /** 本地联调才设的一对豁免：这些主机免掉"解析到私有地址"与"必须走 https"两道闸。 */
  allowPrivateHosts?: string[]
  allowInsecureTransport?: string[]
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
  /** How far outbound DID resolution is allowed to reach. */
  didResolution: DidResolution
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

/** 逗号或空白分隔的主机名清单。空串按缺席处理——`X=` 是 shell 事故，不是"一个叫空串的
 *  主机"；两种读法的结果都是空清单，但写成缺席才不用解释一个不存在的元素。 */
function parseHosts(raw: string | undefined): string[] {
  if (raw === undefined) return []
  return raw.split(/[\s,]+/).filter((host) => host !== '')
}

/**
 * 两个变量算成一份解析器策略。
 *
 * 联调主机**同时进 `allowedHosts`**：那两个豁免放宽的是闸门，不是允许清单，不进清单就
 * 永远解析不到。反过来，清单本身始终是精确主机名——没有为了联调就出现通配或者"跳过
 * 检查"的分支。
 */
function parseDidResolution(env: NodeJS.ProcessEnv): DidResolution {
  const devHosts = parseHosts(env.AGENTX_DID_DEV_HOSTS)
  const resolution: DidResolution = {
    allowedHosts: [...new Set([...parseHosts(env.AGENTX_ALLOWED_DID_HOSTS), ...devHosts])],
  }
  if (devHosts.length > 0) {
    resolution.allowPrivateHosts = devHosts
    resolution.allowInsecureTransport = devHosts
  }
  return resolution
}

/**
 * §8.7 L512：`serviceDid` **MUST** 是 DID 字符串，而不是 DID URL。
 *
 * `#` 是 fragment、`?` 是 query（DID Core 的 DID URL 定义），带上任何一个就不再是"这个
 * 服务"。代价不只是难听：`serviceDid` 会被写进 DID 文档，也是跨域外层签名 `keyid` 的解析
 * 基准——`did:web:example.com#svc` 在那里指的是那个 DID 的某一个 key，不是这个服务，于是
 * 一次跨域调用会拿着一个指向密钥的 id 去找服务身份。
 *
 * **不校验方法名**：`did:web` / `did:wba` 之外还有别的 DID 方法部署方可以用，这里只判它
 * 确实是一个 DID。
 */
function parseServiceDid(raw: string): string {
  if (!raw.startsWith('did:')) {
    throw new ConnectxError('invalid_argument', `AGENTX_SERVICE_DID must be a DID string (got ${JSON.stringify(raw)})`)
  }
  if (raw.includes('#') || raw.includes('?')) {
    throw new ConnectxError(
      'invalid_argument',
      `AGENTX_SERVICE_DID must be a DID, not a DID URL (got ${JSON.stringify(raw)}); it may carry no fragment or query`,
    )
  }
  return raw
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
    serviceDid: parseServiceDid(env.AGENTX_SERVICE_DID ?? didWebFor(publicUrl)),
    didResolution: parseDidResolution(env),
    dbPath: env.AGENTX_DB ?? DEFAULT_DB,
    maxBody: parsePositive(env.AGENTX_MAX_BODY, 'AGENTX_MAX_BODY', DEFAULT_MAX_BODY),
  }
  if (env.AGENTX_KEY_FILE !== undefined && env.AGENTX_KEY_FILE !== '') config.keyFile = env.AGENTX_KEY_FILE
  if (env.AGENTX_OBJECT_DIR !== undefined && env.AGENTX_OBJECT_DIR !== '') config.objectDir = env.AGENTX_OBJECT_DIR
  return config
}
