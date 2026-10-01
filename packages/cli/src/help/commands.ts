// The command surface, as DATA.
//
// Every consumer of "what commands exist and what do they take" reads this file:
//   - `render.ts`      renders the L0 index and the L1/L2 pages
//   - `cli.ts`         rejects a flag a command does not accept
//   - help tests       assert every documented flag is accepted and vice versa
//   - the docs gate    reconciles githubpages/cli/api/*.md against it
//   - the skill gate   checks SKILL.md's command and flag mentions
//
// That is the point of the file: a command's shape is stated ONCE, so help, the
// parser, the docs and the skill cannot drift apart. Adding a command means
// adding an entry here, not editing four surfaces.
//
// A page ACCEPTS exactly the flags it DOCUMENTS. There is no second list to keep
// in sync: `acceptedFlags()` reads the option rows below. A flag that is not on
// the page is rejected at parse time instead of being silently ignored.

/** One row in a page's Options section. Rendered as one line per flag. */
export interface OptionRow {
  /** The flag as typed, e.g. `--target <uri>`. */
  signature: string
  /** One sentence. No trailing period. No second person. */
  summary: string
  /** Rendered after the summary, e.g. `default: 7d`. */
  fallback?: string
}

/** A titled group of option rows (a page's Options is usually 2-4 groups). */
export interface OptionGroup {
  title: string
  rows: OptionRow[]
  /** One sentence about the GROUP, rendered under its rows. For a fact that is true
   *  of every row (or of none in particular) and would read as noise repeated on
   *  each one — a per-row note is `fallback`. */
  note?: string
}

export interface ExitCode {
  code: string
  meaning: string
}

/** One positional argument a page takes, in the order it appears on the command
 *  line. The counterpart to `acceptedFlags`: a flag is accepted because the page
 *  documents it, an argument because the page declares it here. Without this a
 *  leftover positional argument (`connectx agent show bob`) is parsed, dispatched,
 *  and silently dropped — the command answers a different question than the one
 *  that was asked. */
export interface ArgSpec {
  /** Placeholder as it appears in the usage line and in the rejection, e.g. `did`. */
  name: string
  /** A required argument is also checked for presence; an optional one may be
   *  omitted. Presence is still reported by the command itself — this is what
   *  makes an EXTRA argument a rejection instead of a discard. */
  required: boolean
}

/** One page of help: an L1 command page, or an L2 subcommand page. */
export interface PageSpec {
  /** Subcommand path segment. Undefined for a command with no subcommands. */
  sub?: string
  /** One line under the title. */
  purpose: string
  /** Usage lines, rendered after `connectx `. */
  usage: string[]
  /** Positional arguments this page takes, in order. Absent means it takes none,
   *  which is the common case and why it is optional. */
  args?: ArgSpec[]
  options: OptionGroup[]
  /** Free-form output description. */
  output?: string[]
  exits?: ExitCode[]
  examples: string[]
  /** Docs page for the WHY, which is deliberately not in --help. */
  see?: string
}

export interface CommandSpec {
  /** Dispatch key — also the `case` label in cli.ts and the docs page name. */
  name: string
  /** L0 group heading. */
  group: string
  /** L1 heading. Says what the whole command is about, not what one page does. */
  purpose: string
  /** L0 index rows: the form shown and its one-line brief. */
  index: Array<{ form: string; brief: string }>
  pages: PageSpec[]
}

/** Accepted by every command, on top of what its page documents. */
export const GLOBAL_FLAGS = ['json', 'help', 'version'] as const

/** Flags `cli.ts` implements but no page documents, because they are handled
 *  before dispatch (`--help`/`--version`) or are pure output switches. */
const UNDOCUMENTED: Record<string, string[]> = {}

/** Store flags, for a command that resolves an identity. */
const STORE: OptionGroup = {
  title: 'Store',
  note:
    'An agent id is any name the caller picks. did list prints the ids already stored. ' +
    'When the flag is absent, CONNECTX_AGENT supplies one, then the current agent ' +
    '(connectx agent use), then detection, then "default".',
  rows: [
    { signature: '--agent <id>', summary: 'who is acting', fallback: 'default: the current agent, else detected' },
    { signature: '--profile <name>', summary: 'identity within an agent', fallback: 'default: "default"' },
    { signature: '--password-file <path>', summary: 'read the key password from this file' },
    { signature: '--password-stdin', summary: 'read the key password from stdin' },
  ],
}

/** Store location only — for a command that touches no key material. */
const STORE_ID: OptionGroup = {
  title: 'Store',
  rows: STORE.rows.slice(0, 2),
}

/** Key resolution for the ANP layer, where a web3 wallet is a first-class choice: it
 *  answers a request with a signature and never shows the key. */
const KEY: OptionGroup = {
  title: 'Key',
  note:
    'A web3 wallet signs inside the wallet, so one login opens three confirmations: one to recover ' +
    "the public key, then one for each of two signed attempts. The first carries no nonce and only " +
    "fetches the server's challenge; the second carries it. The recovery is cached per process, and " +
    'every CLI run is a new process.',
  rows: [
    { signature: '--wallet <cli|web3>', summary: 'where the signing key lives', fallback: 'default: cli' },
    { signature: '--key <spec>', summary: 'cli only. key material instead of the identity store' },
    {
      signature: '--curve <ed25519|secp256k1>',
      summary: 'curve of the key material given by --key',
      fallback: 'default: detected from the material',
    },
    {
      signature: '--provider <module>',
      summary:
        'web3 only, and required there. EIP-1193 provider: a file path, or a package name resolved from the cwd',
    },
    { signature: '--address <addr>', summary: 'web3 only, and required there. account address the wallet signs with' },
    {
      signature: '--chain-id <id>',
      summary: 'web3 only, and required there. CAIP-2 chain id: with the address it IS the identity, e.g. eip155:1',
    },
    { signature: '--bip39-path <path>', summary: 'derivation path for a mnemonic key' },
  ],
}

/** The rows of `KEY` that name no wallet: the material, its curve, and its derivation
 *  path. The difference is the whole layering rule between the two groups. */
const KEY_CLI_ROW_SIGNATURES = ['--key <spec>', '--curve <ed25519|secp256k1>', '--bip39-path <path>']

/** Key resolution for the DID layer. `--wallet` is absent on purpose: a web3 wallet
 *  yields a CAIP-10 account id (`eip155:1:0x…`), which is not a DID, so no page here
 *  accepts it. A caller whose identity lives in a wallet uses the `anp` group. */
const KEY_CLI: OptionGroup = {
  title: 'Key',
  rows: KEY.rows.filter((row) => KEY_CLI_ROW_SIGNATURES.includes(row.signature)),
}

/** The rows of `KEY` that a page reading an ALREADY-STORED identity accepts: the wallet
 *  choice, its provider and its account. It carries no `--key` / `--curve` /
 *  `--bip39-path`, because those describe material handed in on the command line and a
 *  page that prints the stored identity has none to describe. */
const KEY_WALLET: OptionGroup = {
  title: 'Key',
  note: KEY.note,
  rows: KEY.rows.filter((row) => !KEY_CLI_ROW_SIGNATURES.includes(row.signature)),
}

const OUTPUT: OptionGroup = {
  title: 'Output',
  rows: [{ signature: '--json', summary: 'machine-readable output on stdout' }],
}

export const COMMANDS: CommandSpec[] = [
  {
    name: 'did',
    purpose:
      "create this agent's identity, read it, list what is stored, claim a handle for it, and keep its key current",
    group: 'DID server',
    index: [
      { form: 'did create', brief: "create this agent's key (no DID yet)" },
      { form: 'did show', brief: 'print the stored identity and its DID document' },
      { form: 'did list', brief: 'list the agents stored on this machine' },
      { form: 'did register', brief: 'claim a host and a handle: this is where the DID appears' },
      { form: 'did resolve <did>', brief: 'read: is this DID still current?' },
      { form: 'did update', brief: "write: retire this identity's key" },
      { form: 'did restore', brief: 'restore an identity from a recovery key (in development)' },
    ],
    pages: [
      {
        sub: 'create',
        purpose: 'generate a key for this (agent, profile) and seal it in the store',
        usage: ['did create [options]'],
        options: [
          {
            title: 'Identity',
            rows: [
              {
                signature: '--curve <ed25519|secp256k1>',
                summary: 'curve of the key to generate',
                fallback: 'default: ed25519',
              },
              { signature: '--force', summary: 'overwrite an identity that already exists' },
            ],
          },
          STORE,
          OUTPUT,
        ],
        output: [
          'agent/profile, the curve, the binding key (its multibase for Ed25519, its JWK for secp256k1), and the files written.',
          'No DID and no host yet. A did:wba DID is composed under the server that hosts the document, so both arrive with `connectx did register`, together with the handle.',
        ],
        exits: [
          { code: '0', meaning: 'created' },
          { code: '1', meaning: 'failed' },
        ],
        examples: ['did create', 'did create --curve secp256k1 --agent claude-code'],
        see: 'cli/api/did.md',
      },
      {
        sub: 'show',
        purpose: 'print the identity already stored for this (agent, profile); contacts nothing',
        usage: ['did show [options]'],
        options: [STORE, OUTPUT],
        output: [
          'agent/profile, the curve, the binding key (its multibase for Ed25519, its JWK for secp256k1), the key file and its mode, and the DID document.',
          'Once registered, also the host, the handle, the stable subject and the DID. An identity that has only been created has no DID to print, and the output says so.',
          'A wallet-held identity has no DID either. That side of the identity is on `connectx anp show`.',
        ],
        exits: [
          { code: '0', meaning: 'printed' },
          { code: '1', meaning: 'no identity stored, or the key could not be read' },
        ],
        examples: ['did show', 'did show --agent claude-code --json'],
        see: 'cli/api/did.md',
      },
      {
        sub: 'list',
        purpose: 'list every agent stored under the store root, one line each',
        usage: ['did list [options]'],
        options: [OUTPUT],
        output: [
          'One line per agent profile: agent/profile, the DID it is registered on, its curve, and the directory. An identity that has not been registered yet prints `not registered` in place of a DID.',
        ],
        exits: [
          { code: '0', meaning: 'printed, including when nothing is stored' },
          { code: '1', meaning: 'failed' },
        ],
        examples: ['did list', 'did list --json'],
        see: 'cli/api/did.md',
      },
      {
        sub: 'register',
        purpose: 'claim a handle for this identity on the DID server, and record it locally',
        usage: ['did register --target <uri> --handle <name> [options]'],
        options: [
          {
            title: 'Request',
            rows: [
              {
                signature: '--target <uri>',
                summary: "required. The DID server's own register endpoint, not the application's login endpoint",
              },
              {
                signature: '--handle <name>',
                summary: 'required. Name to claim. The server owns its syntax; what is recorded is the name it confirmed',
              },
              {
                signature: '--rpc',
                summary:
                  "speak the DID server's own JSON-RPC register contract, reading its DID domain and its ANPMessageService entry from the document it publishes for itself",
              },
              { signature: '--nonce <n>', summary: 'server nonce', fallback: 'default: empty' },
              {
                signature: '--host <host>',
                summary: 'DID host to compose the identity under',
                fallback: "default: the host of --target",
              },
            ],
          },
          KEY_CLI,
          STORE,
          OUTPUT,
        ],
        output: [
          'The confirmed handle and the DID, plus the token when the server returns one.',
          'The host, the handle and the DID are written to the stored identity: this is where the identity acquires them, and later commands read them from there.',
        ],
        exits: [
          { code: '0', meaning: 'registered' },
          { code: '1', meaning: 'failed (a taken handle is reported by name on stderr)' },
        ],
        examples: [
          'did register --target http://localhost:3000/api/register --handle alice',
          'did register --target https://did.example.com/register --handle alice --json',
          'did register --target http://127.0.0.1:8765/user-service/v1/did-auth/rpc --handle alice --rpc',
        ],
        see: 'cli/api/did.md',
      },
      {
        sub: 'resolve',
        purpose: "ask the DID's host what it publishes right now, always over the network",
        usage: ['did resolve <did> [options]'],
        args: [{ name: 'did', required: true }],
        options: [
          {
            title: 'Query',
            rows: [
              {
                signature: '--chain',
                summary: 'walk the update chain instead of fetching one document, and report each hop assurance',
              },
            ],
          },
          {
            title: 'Network policy',
            rows: [
              {
                signature: '--allow-host <host>',
                summary:
                  'required, repeatable. hostname allowed to be contacted; no port, no scheme, no default. localhost, 127.0.0.1 and ::1 are also allowed to be private and to answer over http',
              },
              {
                signature: '--allow-private-host <host>',
                summary: 'allow a host that is local without being spelled that way to be private and to answer over http',
              },
            ],
          },
          {
            title: 'Chain policy (--chain only)',
            rows: [
              { signature: '--accept-provider-asserted', summary: 'also accept "provider_asserted" hops', fallback: 'default: off' },
              { signature: '--report-low-assurance', summary: 'report a low-assurance result instead of failing' },
            ],
          },
          STORE_ID,
          OUTPUT,
        ],
        output: [
          'One document, or the chain when --chain. The document served for this store own identity is also recorded beside it as did.json, the base a later did update retires.',
        ],
        exits: [
          { code: '0', meaning: 'the DID is current' },
          { code: '2', meaning: 'the DID is no longer current: the chain walked on, or the document is a retirement' },
          { code: '3', meaning: 'the update chain did not verify (did_chain_broken)' },
          { code: '1', meaning: 'anything else: network, policy, bad input' },
        ],
        examples: [
          'did resolve did:wba:example.com:user:alice:e1_abc --allow-host example.com',
          'did resolve did:wba:example.com:user:alice:e1_abc --chain --allow-host example.com --json',
        ],
        see: 'cli/api/did.md',
      },
      {
        sub: 'update',
        purpose: 'generate a successor key for this subject and deliver one retirement hop to the DID server',
        usage: ['did update --target <uri> [options]', 'did update --resume [options]'],
        options: [
          {
            title: 'Delivery',
            rows: [
              {
                signature: '--target <uri>',
                summary: "required. The DID server's own update endpoint. No ANP document defines one, so it is never derived",
              },
              { signature: '--nonce <n>', summary: 'server nonce', fallback: 'default: empty' },
            ],
          },
          {
            title: 'Resume',
            rows: [
              {
                signature: '--resume',
                summary: 'settle a staged key.next by asking the DID server which DID it serves as current. Delivers nothing',
              },
            ],
          },
          {
            title: 'Document fetch',
            rows: [
              {
                signature: '--allow-private-host <host>',
                summary: "allow this identity's own host to be private and to answer over http; a loopback host needs no flag",
              },
            ],
          },
          STORE,
          OUTPUT,
        ],
        output: [
          'The store moves only after the server accepts. The successor key is staged to key.next before anything is sent, so a crash never loses the only key to the successor.',
          'An ambiguous failure keeps key.next and prints its path; a settled failure drops it.',
        ],
        exits: [
          { code: '0', meaning: 'accepted, or under --resume the staged successor is what the server now serves' },
          { code: '1', meaning: 'failed, refused, or nothing to resume' },
        ],
        examples: ['did update --target https://did.example.com/update', 'did update --resume'],
        see: 'cli/api/did.md',
      },
      {
        sub: 'restore',
        purpose:
          'restore this identity from a recovery key, when the signing key is lost. In development',
        usage: ['did restore [options]'],
        options: [STORE_ID, OUTPUT],
        output: [
          'Nothing yet. The command is reserved: it reports that it is in development and exits 1, without reading or writing the store.',
        ],
        exits: [{ code: '1', meaning: 'in development: nothing was restored' }],
        examples: ['did restore', 'did restore --agent claude-code'],
        see: 'cli/api/did.md',
      },
    ],
  },
  {
    name: 'anp',
    purpose: 'authenticate to an application: show the identity, log in, and sign a request',
    group: 'ANP server',
    index: [
      { form: 'anp show', brief: 'print the identity this agent signs as (DID or web3)' },
      { form: 'anp login', brief: 'sign in to a site; print and cache the session token' },
      { form: 'anp sign', brief: 'produce RFC 9421 signature headers (no network)' },
    ],
    pages: [
      {
        sub: 'show',
        purpose: 'print the identity this agent signs as, from the store or from a wallet; contacts nothing',
        usage: ['anp show [options]'],
        options: [KEY_WALLET, STORE, OUTPUT],
        output: [
          'agent/profile, the curve, the binding key (its multibase for Ed25519, its JWK for secp256k1), the key file and its mode, and the identifier a peer sees.',
          'With --wallet cli the stored identity is printed exactly as `connectx did show` prints it, DID document included. An identity that has only been created has no DID yet, and the output says so.',
          'With --wallet web3 the identifier is a CAIP-10 account id (eip155:1:0x…). It is not a DID and has no document, so no document is printed.',
        ],
        exits: [
          { code: '0', meaning: 'printed' },
          { code: '1', meaning: 'no identity stored, or the wallet could not be reached' },
        ],
        examples: ['anp show', 'anp show --wallet web3 --provider ./wallet.mjs --address 0xabc --json'],
        see: 'cli/api/anp.md',
      },
      {
        sub: 'login',
        purpose: 'sign an ANP login request, POST it, print the token, and cache it',
        usage: ['anp login --target <uri> [options]'],
        options: [
          {
            title: 'Request',
            rows: [
              {
                signature: '--target <uri>',
                summary: 'required. URL the signed login request is POSTed to: the ANP verify endpoint of the site',
              },
              { signature: '--nonce <n>', summary: 'server nonce; a 401 challenge is re-signed automatically', fallback: 'default: empty' },
            ],
          },
          KEY,
          STORE,
          {
            title: 'Session',
            rows: [
              {
                signature: '--session-ttl <dur>',
                summary: 'cache lifetime cap (7d, 24h, 3600s); never exceeds the server JWT exp',
                fallback: 'default: 7d',
              },
              { signature: '--no-save-session', summary: 'print the token only, write nothing' },
            ],
          },
          {
            title: 'Prompt',
            rows: [
              { signature: '--yes', summary: 'skip the confirmation card' },
              { signature: '--json', summary: 'force the NDJSON stream on stdout' },
            ],
          },
        ],
        output: [
          'On a terminal, a card is drawn: Enter approves it, n cancels it.',
          'On a pipe, or with --json, a state stream instead: one JSON object per line, in the states this command can observe (connecting, signing, connected, error).',
          'A stored identity signs as the DID its registration produced. One that has only been created is refused with identity_not_registered.',
        ],
        exits: [
          { code: '0', meaning: 'signed in' },
          { code: '1', meaning: "failed or cancelled (the error code \"cancelled\" is on the stream)" },
        ],
        examples: [
          'anp login --target http://localhost:3000/api/login/anp/verify',
          'anp login --target https://site/api/login/anp/verify --json',
        ],
        see: 'cli/api/anp.md',
      },
      {
        sub: 'sign',
        purpose: 'produce the RFC 9421 signature headers for one request. sends nothing',
        usage: ['anp sign --target <uri> [options]'],
        options: [
          {
            title: 'Request',
            rows: [
              { signature: '--target <uri>', summary: 'required. URL the headers are computed for' },
              { signature: '--method <verb>', summary: 'HTTP method covered by the signature', fallback: 'default: POST' },
              { signature: '--nonce <n>', summary: 'server nonce to cover', fallback: 'default: empty' },
            ],
          },
          KEY,
          STORE,
          OUTPUT,
        ],
        output: [
          'the signature headers as JSON (there is no human rendering of a header set)',
          'A stored identity signs as the DID its registration produced. One that has only been created is refused with identity_not_registered.',
        ],
        exits: [
          { code: '0', meaning: 'signed' },
          { code: '1', meaning: 'failed' },
        ],
        examples: [
          'anp sign --target http://localhost:3000/api/resource',
          'anp sign --target https://site/api/resource --method GET',
        ],
        see: 'cli/api/anp.md',
      },
    ],
  },
  {
    name: 'agent',
    purpose: 'choose which stored agent the commands act as when no flag names one',
    // With `did`, not `version`: this reads and writes the identity store (`identity/paths`,
    // `identity/store`) and answers "which identity am I acting as" — the same thing
    // `did show`/`did list` are about, and the same thing `--agent` selects. General would
    // say "miscellaneous", which is exactly what it is not.
    group: 'DID server',
    index: [
      { form: 'agent show', brief: 'print the agent the commands act as, and what decided it' },
      { form: 'agent use <id>', brief: 'act as this agent from now on' },
      { form: 'agent list', brief: 'list the agents stored here, the current one marked' },
    ],
    pages: [
      {
        sub: 'show',
        purpose: 'print the agent the commands act as, and which step decided it; contacts nothing',
        usage: ['agent show [options]'],
        options: [OUTPUT],
        output: [
          'The agent id, then the source that decided it: the current agent, CONNECTX_AGENT, detection from the environment, or the fallback "default".',
        ],
        exits: [
          { code: '0', meaning: 'printed' },
          { code: '1', meaning: 'the environment matches more than one agent (agent_ambiguous)' },
        ],
        examples: ['agent show', 'agent show --json'],
        see: 'cli/api/agent.md',
      },
      {
        sub: 'use',
        purpose: 'act as this agent in every later command that names no agent of its own',
        usage: ['agent use <id> [options]'],
        args: [{ name: 'id', required: true }],
        options: [OUTPUT],
        output: [
          'The id is written to current-agent under the store root. Later commands act as it unless --agent or CONNECTX_AGENT says otherwise.',
          'An id with nothing stored is accepted, and reported on stderr: selecting an agent and then creating its key is the order a new agent is born in.',
          'A selection moves by being replaced with another id, or by deleting the current-agent file.',
        ],
        exits: [
          { code: '0', meaning: 'selected' },
          { code: '1', meaning: 'failed (the id is not a usable agent id)' },
        ],
        examples: ['agent use claude-code', 'agent use work --json'],
        see: 'cli/api/agent.md',
      },
      {
        sub: 'list',
        purpose: 'list the agents stored on this machine, marking the one the commands act as',
        usage: ['agent list [options]'],
        options: [OUTPUT],
        output: [
          'One line per stored identity, in the form `did list` prints: agent/profile, the DID it is registered on, its curve, and the directory. The rows of the current agent start with `current`, and a current agent that has nothing stored is listed too and says so.',
          'An empty list means no identity is stored anywhere under the store root.',
        ],
        exits: [
          { code: '0', meaning: 'printed' },
          { code: '1', meaning: 'failed (the current agent file holds no usable agent id)' },
        ],
        examples: ['agent list', 'agent list --json'],
        see: 'cli/api/agent.md',
      },
    ],
  },
  {
    name: 'version',
    purpose: 'print the CLI version',
    group: 'General',
    index: [{ form: 'version', brief: 'print the CLI version' }],
    pages: [
      {
        purpose: 'print the version of the build being run, and nothing else; contacts nothing',
        usage: ['version [options]'],
        options: [OUTPUT],
        output: ['the version string, or with --json an object carrying one field, "version"'],
        // This command has no failure path: `cliVersion` falls back to the string
        // "unknown" rather than throwing. Listing an exit 1 here would be a promise
        // the code does not keep.
        exits: [{ code: '0', meaning: 'printed' }],
        examples: ['version', 'version --json'],
        see: 'cli/api/version.md',
      },
    ],
  },
]

/** The docs site, for the one `See:` line a page may carry. */
export const DOCS_BASE = 'https://github.com/eccstartup/connectx/blob/master/githubpages'

export function findCommand(name: string): CommandSpec | undefined {
  return COMMANDS.find((c) => c.name === name)
}

export function findPage(command: CommandSpec, sub: string | undefined): PageSpec | undefined {
  return command.pages.find((p) => p.sub === sub)
}

/** The flag name written in a signature: `--target <uri>` -> `target`. One name, and
 *  the literal one — `allowNegative` is off, so a page that writes `--no-install` is
 *  describing a key spelled `no-install` and nothing else. The positive form is a flag
 *  no page shows and the parser does not have. */
export function flagNames(signature: string): string[] {
  const m = /^--([a-z][a-z0-9-]*)/.exec(signature)
  return m === null ? [] : [m[1]]
}

/** The signatures a page documents, in reading order and deduped. What the
 *  rejection message lists: a bare `--save-session` would be a flag no page
 *  shows, even though `parseArgs` happens to accept it. */
export function acceptedSignatures(page: PageSpec): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const group of page.options) {
    for (const row of group.rows) {
      if (seen.has(row.signature)) continue
      seen.add(row.signature)
      out.push(row.signature)
    }
  }
  return out
}

/** The flag keys a page accepts: what it documents, plus the global flags. */
export function acceptedFlags(page: PageSpec): Set<string> {
  const out = new Set<string>(GLOBAL_FLAGS)
  for (const group of page.options) {
    for (const row of group.rows) for (const name of flagNames(row.signature)) out.add(name)
  }
  for (const name of UNDOCUMENTED[page.sub ?? ''] ?? []) out.add(name)
  return out
}

/** The positional arguments a usage line spells, in order, as name + required. `<did>`
 *  is a required argument, `[name]` an optional one; `[options]` is the flag tail, not
 *  an argument. Tokens are read only up to the first `--flag`, because a flag's own
 *  value placeholder (`--target <uri>`) is spelled just like a positional and is not
 *  one. The usage line is what a reader sees, so this is the check that keeps the
 *  parser's `args` declaration and the help one fact rather than two that can drift.
 *  Only the FIRST usage line is read: the rest are flag variants of the same shape. */
export function usageArgs(usage: string): ArgSpec[] {
  const out: ArgSpec[] = []
  for (const token of usage.split(/\s+/)) {
    if (token.startsWith('--')) break
    const req = /^<([a-z][a-z0-9-]*)>$/.exec(token)
    if (req !== null) {
      out.push({ name: req[1], required: true })
      continue
    }
    const opt = /^\[([a-z][a-z0-9-]*)\]$/.exec(token)
    if (opt !== null && opt[1] !== 'options') out.push({ name: opt[1], required: false })
  }
  return out
}

/** The positional arguments a page takes, in order. */
export function acceptedArgs(page: PageSpec): ArgSpec[] {
  return page.args ?? []
}

/** Every flag key any page of a command accepts — the command-level union the
 *  docs gate reconciles against. */
export function acceptedFlagsOfCommand(name: string): Set<string> {
  const command = findCommand(name)
  if (command === undefined) return new Set()
  const out = new Set<string>(GLOBAL_FLAGS)
  for (const page of command.pages) for (const f of acceptedFlags(page)) out.add(f)
  return out
}

/** Every signature any page of a command SHOWS, deduped, in reading order. This is
 *  the spelling a reference page has to carry: `--no-save-session`, never the
 *  implicit positive form `parseArgs` also answers to. */
export function acceptedSignaturesOfCommand(name: string): string[] {
  const command = findCommand(name)
  if (command === undefined) return []
  const out: string[] = []
  const seen = new Set<string>()
  for (const page of command.pages) {
    for (const signature of acceptedSignatures(page)) {
      if (seen.has(signature)) continue
      seen.add(signature)
      out.push(signature)
    }
  }
  return out
}
