import { sha256, utf8, bytesToBase64 } from './encoding'
import { ConnectxError } from '../errors'

// HTTP Message Signatures (draft-ietf-http-message-signatures) — the subset
// ANP-02 uses for its auth. Pure/string-based so the browser signer and Node
// verifier build identical bytes.
//
// The SDK signs with the OFFICIAL ANP-02 branch: it covers `@target-uri` and
// appends a `@signature-params` line carrying created/expires/nonce/keyid.

// Single source of truth for the ANP-02 covered components. Both the signer
// (`signer.ts`) and the proof adapter (`protocol/anp.ts`) build the signed
// bytes from this list; keeping one copy avoids sign/verify divergence.
export const ANP_COMPONENTS = ['@method', '@target-uri', '@authority', 'content-digest']

export interface CoveredComponent {
  name: string // '@method' | '@path' | '@authority' | header name
  value: string
}

export interface ParsedSignatureInput {
  /** The RFC 9421 signature label (the `sig1` in `sig1=(...)`). */
  label: string
  components: string[]
  params: Record<string, string | number>
  /** The verbatim signature-params value (everything after `label=`), i.e.
   *  `(components);params`. This is exactly the `@signature-params` line value. */
  signatureParamsValue: string
}

// Params the verifier understands and therefore re-serializes. Any other param in
// a Signature-Input header is rejected: silently dropping an unrecognized param
// would let a header that was NOT covered by the signature pass verification, and
// a policy-bearing param could be mistaken for signed input.
const ALLOWED_PARAMS = new Set(['created', 'expires', 'nonce', 'keyid', 'alg'])

export function parseSignatureInput(input: string): ParsedSignatureInput {
  const trimmed = input.trim()
  const open = trimmed.indexOf('(')
  if (open === -1) throw new ConnectxError('signature_malformed', 'Malformed Signature-Input header')

  // A full Signature-Input field is `label=(components);params`, but callers also
  // pass the bare `(components);params` portion. Detect and strip an optional label.
  let label = ''
  let rest = trimmed
  const eq = trimmed.indexOf('=')
  if (eq > 0 && eq < open) {
    label = trimmed.slice(0, eq).trim()
    if (!/^[A-Za-z0-9_-]+$/.test(label)) throw new ConnectxError('signature_malformed', 'Invalid Signature-Input label')
    rest = trimmed.slice(eq + 1)
  }

  const close = rest.indexOf(')')
  if (close === -1 || close <= rest.indexOf('(')) throw new ConnectxError('signature_malformed', 'Malformed Signature-Input header')

  const components = rest
    .slice(rest.indexOf('(') + 1, close)
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((c) => c.replace(/^"|"$/g, ''))

  const params: Record<string, string | number> = {}
  for (const part of rest.slice(close + 1).split(';')) {
    if (!part.trim()) continue
    const pEq = part.indexOf('=')
    if (pEq === -1) throw new ConnectxError('signature_malformed', 'Malformed Signature-Input param')
    const name = part.slice(0, pEq).trim()
    const raw = part.slice(pEq + 1).trim()
    const value = raw.replace(/^"|"$/g, '')
    if (!ALLOWED_PARAMS.has(name)) throw new ConnectxError('signature_malformed', `Unsupported Signature-Input param: ${name}`)
    if (params[name] !== undefined) throw new ConnectxError('signature_malformed', `Duplicate Signature-Input param: ${name}`)
    // created/expires are unquoted Unix timestamps; coerce so freshness checks work.
    params[name] = /^\d+$/.test(raw) ? Number(value) : value
  }

  return { label, components, params, signatureParamsValue: rest }
}

export interface BuildSignatureBaseInput {
  method: string
  path: string
  authority: string
  targetUri?: string
  headers: Record<string, string> // lowercase header name → raw value
  components: string[]
  // Serialized "@signature-params" value (e.g. `("@method" ...);created=..;keyid="..."`).
  // Appended after the covered-component lines, matching the official ANP-02 client.
  // Omit for the legacy browser shim, which signed without it.
  signatureParams?: string
}

// Reconstruct the signature base per the covered components, in their declared order.
export function buildSignatureBase(input: BuildSignatureBaseInput): string {
  const lines = input.components
    .map((comp) => {
      let value: string
      switch (comp) {
        case '@method':
          value = input.method.toUpperCase()
          break
        case '@path':
          value = input.path
          break
        case '@target-uri':
          value = input.targetUri ?? input.path
          break
        case '@authority':
          value = input.authority
          break
        default:
          value = input.headers[comp.toLowerCase()] ?? ''
      }
      return `"${comp}": ${value}`
    })
  if (input.signatureParams) lines.push(`"@signature-params": ${input.signatureParams}`)
  return lines.join('\n')
}

// Serialize Signature-Input params exactly as the official ANP-02 client:
// `(<quoted components>);created=..;expires=..;nonce="..";keyid=".."`.
export function serializeSignatureParams(
  components: string[],
  params: { created?: number; expires?: number; nonce?: string; keyid: string; alg?: string },
): string {
  const list = components.map((c) => `"${c}"`).join(' ')
  const p: string[] = []
  if (params.created != null) p.push(`created=${params.created}`)
  if (params.expires != null) p.push(`expires=${params.expires}`)
  if (params.nonce != null) p.push(`nonce="${params.nonce}"`)
  p.push(`keyid="${params.keyid}"`)
  if (params.alg) p.push(`alg="${params.alg}"`)
  return `(${list});${p.join(';')}`
}

export function buildSignatureInputHeader(
  components: string[],
  params: { keyid: string; alg?: string; created?: number },
): string {
  const list = components.map((c) => `"${c}"`).join(' ')
  const p: string[] = []
  if (params.created) p.push(`created=${params.created}`)
  p.push(`keyid="${params.keyid}"`)
  if (params.alg) p.push(`alg="${params.alg}"`)
  return `(${list});${p.join(';')}`
}

// Content-Digest header value for a body: sha-256=<base64 of digest>
export async function buildContentDigestValue(body: Uint8Array): Promise<string> {
  const digest = await sha256(body)
  return `sha-256=:${bytesToBase64(digest)}:`
}

// The body bytes a signature binds to. HTTP Message Signatures covers the body
// via a content-digest header, not the raw body, so both sides hash `body`
// after it has been transmitted.
export function signatureBaseBytes(base: string): Uint8Array {
  return utf8(base)
}
