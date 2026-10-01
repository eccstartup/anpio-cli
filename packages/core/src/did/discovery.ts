// DID-server discovery — read a server's own vocabulary off the document it publishes
// for itself, instead of inferring it from the URL you happened to reach it at.
//
// A DID server IS a DID holder: it publishes the document for its own DID at
// `<origin>/.well-known/did.json` (ANP-03 §2.5.1's WBA well-known path, the same URL
// `didToUrl` derives for a bare-domain DID). Two of the things a registering client
// needs are in that document and nowhere else:
//
//   1. The DID DOMAIN the server hosts under — the `did:wba:<domain>` its `id` names.
//      This is NOT the host in the URL: a server reached at `127.0.0.1:8765` may publish
//      as `did:wba:localhost`, and a client DID composed under the URL's host would be
//      refused as a foreign domain. So the domain is read, never guessed.
//   2. The server's own `ANPMessageService` entry. A server judges the document it is
//      sent against its own configuration (that service's endpoint and `serviceDid`), so
//      the entry a client publishes has to be the server's own entry, verbatim.
//
// What this deliberately does NOT do is verify the document's proof or apply a resolution
// policy (allowlists, DNS pinning, https-only). It reads a document from the server that
// is about to judge the registration: an entry that arrives tampered does not survive —
// it is exactly what the server compares against its own configuration, so it fails
// closed at the server. Running `resolveDidDocument`'s policy on top would instead refuse
// the plaintext, loopback deployments this flow exists to register against.
//
// (`readBodyBounded` is shared with `actions.ts` so both read a peer's body under one
// implementation of the same 1 MiB cap.)

import type { DidDocumentService } from '../crypto/didDocument'
import { ConnectxError } from '../errors'
import { readBodyBounded } from '../actions'

/** The server's `ANPMessageService` entry exactly as published, unknown members included:
 *  everything in it is covered by the proof of the document a client submits, so the
 *  entry has to be carried over untouched (awiki publishes `profiles`, `securityProfiles`
 *  and `authSchemes` there as well). */
export interface DidServerService extends DidDocumentService {
  [member: string]: unknown
}

export interface DiscoveredDidServer {
  /** The document's `id` — the DID the SERVER publishes for itself. */
  did: string
  /** The domain to compose client DIDs under: the host segment of {@link did}, decoded.
   *  `did:wba:<didDomain>:<path…>:<fingerprint>` is the shape a server accepts. */
  didDomain: string
  /** The single `ANPMessageService` entry, verbatim — inject it into the document handed
   *  to the connector (`anpCli`'s `service` option) BEFORE that document is signed. */
  service: DidServerService
  /** The URL the document was read from. */
  documentUrl: string
}

export interface DiscoverDidServerOptions {
  /** Optional transport override; defaults to globalThis.fetch. */
  transport?: (url: string, init: RequestInit) => Promise<Response>
}

/** The DID-host shape a `did:wba` host segment may take, mirroring the pattern
 *  `didToUrl` enforces before it will derive a URL from a DID. A port is spelled with
 *  `%3A` in the DID (`encodeDidHost`), so the decoded form is what this sees. */
const DID_HOST = /^[A-Za-z0-9-]([A-Za-z0-9._-]*[A-Za-z0-9])?(:[0-9]+)?$/

/** The host segment of a `did:wba` DID — the first segment after the method. */
function didDomainOf(did: string, documentUrl: string): string {
  const segments = did.split(':')
  if (segments[0] !== 'did' || segments[1] !== 'wba' || !segments[2]) {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl} publishes "${did}" as its id: a DID server that hosts client DIDs under this contract serves a did:wba domain`,
    )
  }
  let domain: string
  try {
    domain = decodeURIComponent(segments[2])
  } catch (err) {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl} publishes a host with broken percent-encoding ("${segments[2]}")`,
      { cause: err },
    )
  }
  // A leftover `%` is a double encoding, which the DID layer would decode a second time.
  if (domain.includes('%') || !DID_HOST.test(domain)) {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl} publishes "${domain}" as its DID host, which is not a host this SDK can compose a DID under`,
    )
  }
  return domain
}

/** A JSON value narrowed to a plain object, or `undefined` for anything else (null, an
 *  array, a scalar) — a peer's body is untrusted input and must not become a TypeError. */
function plainObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

/**
 * Read the DID document a server publishes for itself and return the two facts a
 * registration needs: the DID domain to compose the client DID under, and the
 * `ANPMessageService` entry that document must carry verbatim.
 *
 * `origin` may be any URL on the server — only its origin is used, since the well-known
 * path is absolute from the root, so a caller can pass the register endpoint it was
 * given. A missing document, a non-JSON one, a non-`did:wba` id, or anything other than
 * exactly one `ANPMessageService` entry is an `invalid_argument` that names the URL:
 * every one of those means the value cannot be read, and none of them may be guessed.
 */
export async function discoverDidServer(
  origin: string,
  options: DiscoverDidServerOptions = {},
): Promise<DiscoveredDidServer> {
  let documentUrl: string
  try {
    documentUrl = new URL('/.well-known/did.json', origin).toString()
  } catch (err) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot read a DID document from "${origin}": that is not a URL`,
      { cause: err },
    )
  }

  const transport = options.transport ?? globalThis.fetch.bind(globalThis)
  let res: Response
  try {
    res = await transport(documentUrl, { headers: { accept: 'application/json' } })
  } catch (err) {
    // A transport failure is reported as what it is, not as a missing document: the two
    // have different fixes (an unreachable server vs a server that publishes nothing).
    throw new ConnectxError(
      'invalid_argument',
      `GET ${documentUrl} failed: ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    )
  }
  if (!res.ok) {
    throw new ConnectxError(
      'invalid_argument',
      `GET ${documentUrl} answered ${res.status}: the server publishes no DID document there`,
      { status: res.status },
    )
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(await readBodyBounded(res)) as unknown
  } catch (err) {
    if (err instanceof ConnectxError) throw err
    throw new ConnectxError('invalid_argument', `GET ${documentUrl} did not answer JSON`, {
      cause: err,
      status: res.status,
    })
  }
  const document = plainObject(parsed)
  if (!document) {
    throw new ConnectxError(
      'invalid_argument',
      `GET ${documentUrl} answered ${Array.isArray(parsed) ? 'an array' : typeof parsed}, not a DID document`,
      { status: res.status },
    )
  }

  const id = document.id
  if (typeof id !== 'string' || id === '') {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl} has no "id", so the DID domain to register under cannot be read from it`,
    )
  }

  const entries = Array.isArray(document.service) ? document.service : []
  const services = entries
    .map(plainObject)
    .filter((entry): entry is DidServerService => entry !== undefined && entry.type === 'ANPMessageService')
  if (services.length !== 1) {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl} publishes ${services.length} ANPMessageService entries; a registration needs exactly one, because the server checks the document it is sent against that entry`,
    )
  }
  const service = services[0]
  if (typeof service.serviceEndpoint !== 'string' || service.serviceEndpoint === '') {
    throw new ConnectxError(
      'invalid_argument',
      `${documentUrl}'s ANPMessageService has no "serviceEndpoint", so a document carrying it could not be accepted`,
    )
  }

  return { did: id, didDomain: didDomainOf(id, documentUrl), service, documentUrl }
}
