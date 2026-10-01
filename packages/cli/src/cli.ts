#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { runAgent } from './commands/agent'
import { runDidStore, runAnp } from './commands/auth'
import { runDid } from './commands/did'
import { runMsg } from './commands/msg'
import { cliVersion } from './version'
import { acceptedArgs, acceptedFlags, findCommand, findPage } from './help/commands'
import {
  commandPath,
  renderCommandIndex,
  renderExtraArgument,
  renderHelp,
  renderIndex,
  renderUnknownCommand,
  renderUnknownFlag,
  renderUnknownSubcommand,
} from './help/render'

// The parse table. Every flag the CLI can tokenize is here; which COMMAND may
// use it is decided in `help/commands.ts`, where each flag is documented on the
// page that accepts it. The two are kept honest by a test, not by comments.
const OPTIONS = {
  host: { type: 'string' },
  // did create / did register / anp login / anp sign
  wallet: { type: 'string' },
  key: { type: 'string' },
  curve: { type: 'string' },
  force: { type: 'boolean', default: false },
  // identity store — an agent names (agent, profile); never a key
  agent: { type: 'string' },
  profile: { type: 'string' },
  'chain-id': { type: 'string' },
  address: { type: 'string' },
  method: { type: 'string', default: 'POST' },
  nonce: { type: 'string', default: '' },
  handle: { type: 'string' },
  // did register — answer the DID server's OWN JSON-RPC register contract (the
  // "canonical User Service v1" awiki-open-server serves) instead of the ANP-02 signed
  // request. ANP-03 §2.5.3 L427 leaves that interface to the implementation, so this is
  // a second contract rather than an option on the first.
  rpc: { type: 'boolean', default: false },
  'password-file': { type: 'string' },
  'password-stdin': { type: 'boolean', default: false },
  'bip39-path': { type: 'string' },
  provider: { type: 'string' },
  // the endpoint a signed request is delivered to — login, register, sign, did update
  target: { type: 'string' },
  // msg send — the recipient of a `direct.send` and the body it carries. `--to` is NOT
  // `--target`: a target is the URL a request is POSTed to, while this is the DID a
  // message is addressed to, whose service endpoint is discovered rather than given.
  to: { type: 'string' },
  text: { type: 'string' },
  body: { type: 'string' },
  'content-type': { type: 'string' },
  'operation-id': { type: 'string' },
  // session store — the token cache written by `login`. On by default, so declared as
  // `--no-save-session`; `--save-session` is unknown.
  'no-save-session': { type: 'boolean', default: false },
  'session-ttl': { type: 'string' },
  // login — approve the card without a keypress (a terminal that is not a person)
  yes: { type: 'boolean', default: false },
  // did resolve — the network policy maps onto the SDK's ResolveDidOptions. There are
  // two host lists, both repeatable (parseArgs then hands them over as arrays): the
  // allowlist, and the hosts that may resolve inward and answer over http.
  chain: { type: 'boolean', default: false },
  'allow-host': { type: 'string', multiple: true },
  'allow-private-host': { type: 'string', multiple: true },
  'accept-provider-asserted': { type: 'boolean', default: false },
  'report-low-assurance': { type: 'boolean', default: false },
  // did update --resume — settle a delivery whose outcome is unknown by asking the
  // DID server which DID it serves as current.
  resume: { type: 'boolean', default: false },
  json: { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
  version: { type: 'boolean', short: 'v', default: false },
} as const

/** Set once by `main` so the top-level error handler can pick its channel. */
let jsonMode = false

/** `parseArgs` needs the whole table to know a flag's arity, but the help we want
 *  to print on a parse error is per-command. The command is the first one or two
 *  non-flag tokens, which can be found without parsing: a token after a
 *  string-valued flag is that flag's value, never a positional. */
function leadingPositionals(argv: string[]): string[] {
  const table = OPTIONS as unknown as Record<string, { type: string } | undefined>
  const out: string[] = []
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--') {
      out.push(...argv.slice(i + 1))
      break
    }
    if (arg.startsWith('--')) {
      const body = arg.slice(2)
      if (body.includes('=')) continue
      if (table[body.replace(/^no-/, '')]?.type === 'string') i += 1
      continue
    }
    if (arg.startsWith('-') && arg.length > 1) continue
    out.push(arg)
    if (out.length === 2) break
  }
  return out
}

/** The flag name Node complained about, e.g. `--bogus` from
 *  "Unknown option '--bogus'. To specify a positional argument…". */
function badFlag(message: string): string | undefined {
  return /(?:Unknown option|option) '([^']+)'/.exec(message)?.[1]
}

interface Parsed {
  values: Record<string, unknown>
  positionals: string[]
  tokens: Array<{ kind: string; name: string }>
}

function parse(argv: string[]): Parsed {
  return parseArgs({
    args: argv,
    options: OPTIONS,
    allowPositionals: true,
    // Off: the negative form of a boolean is NOT auto-derived. Every `--no-x` this CLI
    // accepts is declared under that literal key above (and is documented on the page
    // that takes it), so `--no-json`, `--no-force`, `--install` and friends are plain
    // unknown options — the flag checker never has to reason about a spelling no page
    // shows. Turning this on would hand every boolean a second, undocumented name.
    allowNegative: false,
    tokens: true,
  }) as unknown as Parsed
}

async function main(argv: string[]): Promise<number> {
  const pre = leadingPositionals(argv)
  let parsed: Parsed
  try {
    parsed = parse(argv)
  } catch (err) {
    // A flag that is in no table at all never reaches the per-command check, so
    // it is reported here — against the same page, in the same shape.
    const message = (err as Error).message
    const flag = badFlag(message)
    const command = findCommand(pre[0] ?? '')
    const page = command === undefined ? undefined : findPage(command, pre[1])
    if (flag !== undefined && page !== undefined) {
      console.error(renderUnknownFlag(flag, commandPath(pre), page))
      return 1
    }
    console.error(`connectx: ${message.split('. To specify')[0]}`)
    return 1
  }
  const { values, positionals, tokens } = parsed
  // Laundered through `unknown`: a repeatable flag (`multiple: true`, e.g. --allow-host)
  // arrives as a string[], which the shared `Values` type does not model. Command code
  // reads those flags through a coercion helper instead of trusting this type.
  const v = values as unknown as Record<string, string | boolean | undefined>
  jsonMode = v.json === true

  if (v.version) {
    console.log(cliVersion())
    return 0
  }
  if (v.help) {
    console.log(renderHelp(pre))
    return 0
  }
  // A bare `connectx` names no command, so it answers with the index rather than
  // guessing at one.
  const cmd = positionals[0]
  if (cmd === undefined) {
    console.log(renderIndex())
    return 0
  }

  const command = findCommand(cmd)
  if (command === undefined) {
    console.error(renderUnknownCommand(cmd))
    return 1
  }
  // A command whose page carries no subcommand has no subcommands to name, so
  // everything past its own name is an argument: `version foo` is a leftover
  // positional, and answering it with the subcommand rejection would report a
  // subcommand list that is empty.
  const sub = command.pages.some((p) => p.sub === undefined) ? undefined : positionals[1]
  const page = findPage(command, sub)
  if (page === undefined) {
    // `connectx did` — a group named without a member. That is a question, not
    // an error, so it answers with the group's index. With `sub` set, the page
    // lookup was for a real subcommand name and it does not exist.
    if (sub === undefined) {
      console.log(renderCommandIndex(command))
      return 0
    }
    console.error(renderUnknownSubcommand(sub, command))
    return 1
  }

  // The page documents exactly what the command accepts, so this is the whole
  // applicability check — and it cannot fall out of sync with the help text.
  const ok = acceptedFlags(page)
  for (const token of tokens) {
    if (token.kind !== 'option' || ok.has(token.name)) continue
    console.error(renderUnknownFlag(`--${token.name}`, commandPath(positionals), page))
    return 1
  }

  // The positional half of the same check, from the same source. Every command
  // path segment comes first (two when the command has subcommands, one otherwise),
  // then the page's own arguments; anything past that was parsed, dispatched, and
  // dropped — `connectx agent show bob` answered about the current agent as if
  // `bob` had never been typed. Same reason to reject as an unknown flag.
  const consumed = page.sub === undefined ? 1 : 2
  const extra = positionals.slice(consumed + acceptedArgs(page).length)
  if (extra.length > 0) {
    console.error(renderExtraArgument(extra[0], commandPath(positionals), page))
    return 1
  }

  switch (cmd) {
    case 'anp':
      await runAnp(v, sub)
      return 0
    case 'did':
      // `create` / `show` / `list` / `register` report nothing themselves: they throw, and
      // the top-level handler above prints the SDK's error `code` on the human line. For
      // register that code is the point (a taken handle arrives as `register_failed`,
      // carrying the peer's own `serverCode`). `resolve` / `update` / `restore` own their
      // exit codes instead (`did resolve` exits 2 for a superseded DID, which is a
      // conclusion, not a failure) and keep their own reporting. Routing the first four
      // through `runDid` would drop the code from every failure line.
      if (sub === 'create' || sub === 'show' || sub === 'list' || sub === 'register') {
        await runDidStore(v, sub)
        return 0
      }
      return await runDid(v, sub, positionals[2])
    case 'msg':
      // The message layer's own client. The page layer has already rejected any flag or
      // extra argument this family does not take, so `runMsg` sees only its own.
      await runMsg(v, sub, positionals[2])
      return 0
    case 'agent':
      // The store's current agent: which id the other commands act as when neither
      // `--agent` nor `$CONNECTX_AGENT` names one. Reads and writes one file, and
      // contacts nothing.
      await runAgent(v, sub, positionals[2])
      return 0
    case 'version':
      // The command form. `-v` / `--version` is answered before dispatch, so this is
      // reached only by typing the word.
      console.log(v.json === true ? JSON.stringify({ version: cliVersion() }) : cliVersion())
      return 0
    default:
      console.error(renderUnknownCommand(cmd))
      return 1
  }
}

// `process.exitCode`, never `process.exit()`: exit() truncates anything still queued
// on stdout, which for `did resolve --json` would be the entire payload.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
  },
  (err) => {
    // One stable line, and the SDK's own error `code` on it, so a caller can branch
    // on the code without going through --json. `--json` gets the same fact as JSON.
    const e = err as { message?: unknown; code?: unknown }
    const message = typeof e?.message === 'string' ? e.message : String(err)
    const code = typeof e?.code === 'string' ? e.code : undefined
    if (jsonMode) process.stderr.write(`${JSON.stringify({ ok: false, code: code ?? null, message })}\n`)
    else console.error(code === undefined ? `connectx: ${message}` : `connectx: ${code}: ${message}`)
    process.exitCode = 1
  },
)
