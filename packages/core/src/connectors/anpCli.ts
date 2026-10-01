import type { AnpConnector, AnpIdentity, SignRequest, SignResult } from '../types'
import type { IWallet } from '../wallet/wallet'
import { cryptoWalletProver } from '../protocol/anp'
import { keypairWallet } from '../protocol/adapters/chain'
import type { WalletProver } from '../protocol/proof'
import type { ParsedKey } from '../keys/parse'
import type { DidDocumentServices } from '../crypto/didDocument'

// ANP CLI connector — the agent-side local-key path. An agent that holds a key
// file / mnemonic / keystore / PEM (parsed via the keys module) wraps it in a
// local `IWallet` and exposes the SAME uniform `AnpConnector` surface as a
// browser extension or web3 wallet. The server sees a normal ANP-02 proof and
// never knows the key came from a CLI key file.

export interface AnpCliOptions {
  /** Host used as the DID document's controller (not the DID itself in CAIP-10 mode). */
  host: string
  /** CAIP-2 `chain_id` (e.g. `eip155:1`). With `address`, the DID is the CAIP-10
   *  account id; without it, the DID falls back to the path-type `did:wba` identity.
   *  Static fallback — a source wallet implementing `getAccount()` reports its live
   *  account/chain, which wins (see `buildWalletIdentity`). */
  chainId?: string
  /** The local key's address on `chainId` (e.g. `0x…`). */
  address?: string
  /** Path segments for the path-type `did:wba` DID before the key fingerprint
   *  (defaults to `['user','default']`). Ignored in CAIP-10 mode. */
  path?: string[]
  /** Services to publish in the built DID document (ANP-03 §service). Pass a
   *  function to build one from the DID — an `agentDescriptionService` endpoint
   *  usually embeds it. Signed into the document, so it cannot be added later. */
  service?: DidDocumentServices
  /** The DID document to use **as the DID server has it on file**, instead of one
   *  composed from the key. See `IdentityDescriptor.baseDocument` — an update hop's
   *  retirement document has to be the document on file plus `deactivated` +
   *  `successorDid` (§2.5.3 L417), so a caller that keeps a copy of what the server
   *  publishes can hand it back here. Mutually exclusive with `service`. */
  baseDocument?: Record<string, unknown>
  /** Optional prover override; defaults to the official ANP-02 prover. */
  prover?: WalletProver
  /**
   * Connector id. Defaults to `'anp-cli'`. Override it when you configure two
   * CLI connectors (e.g. two keys/hosts) — ids must be unique within a config.
   */
  id?: string
}

export type AnpCliSource = IWallet | ParsedKey

function toWallet(source: AnpCliSource): IWallet {
  // A raw parsed key → a local keypair wallet. A caller passing an `IWallet`
  // (e.g. a remote/web3 wallet bridged to CLI) uses it directly.
  if ('privateKey' in source) return keypairWallet(source.privateKey, { curve: source.curve })
  return source
}

// Wrap a local key (or wallet) as a `type: 'anp-cli'` connector. This is the CLI
// dual-path main line: generate the public key / DID locally, sign locally, and
// present the same ANP-02 proof a browser wallet would.
export function anpCli(source: AnpCliSource, opts: AnpCliOptions): AnpConnector {
  const wallet = toWallet(source)
  const prover = opts.prover ?? cryptoWalletProver()
  const identityDescriptor = {
    chainId: opts.chainId,
    address: opts.address,
    path: opts.path,
    service: opts.service,
    baseDocument: opts.baseDocument,
  }
  return {
    id: opts.id ?? 'anp-cli',
    name: 'ANP CLI',
    type: 'anp-cli',
    isAvailable: () => Promise.resolve(true),
    async getIdentity(): Promise<AnpIdentity> {
      return prover.buildIdentity(wallet, opts.host, identityDescriptor)
    },
    async signRequest(req: SignRequest): Promise<SignResult> {
      const identity = await prover.buildIdentity(wallet, opts.host, identityDescriptor)
      return prover.signRequest(wallet, identity, req)
    },
  }
}

export type { AnpIdentity }
