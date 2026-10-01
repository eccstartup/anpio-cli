// Identity-store addressing: WHERE a given (agent, profile) lives on disk, and
// WHO the current agent is. Kept separate from `store.ts` so the precedence rules
// (flag > env > current agent > detection > default) and the name-safety checks are
// testable in isolation.
//
// The store root is `~/.connectx`, overridable with `$CONNECTX_HOME` — used by
// tests to run in a temp dir, and by anyone who wants the store elsewhere.
//
// The one file READ here is `current-agent`, the pointer an agent selection writes
// (see `setCurrentAgent` in `./store`). The read is on this side because the
// precedence chain below is what consumes it, and that chain cannot call up into
// `store.ts` — which imports this module. The WRITE lives up there, beside the other
// store writes and their temp+rename.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { ConnectxError } from '@agentx/core'

// A path segment must be a safe, single directory name. This is a security
// boundary: agent / profile flow into `join()` and would otherwise be a path-
// escape primitive (`--profile ../../etc`).
const SEGMENT = /^[a-zA-Z0-9._-]+$/

export interface StoreLocation {
  agent: string
  profile: string
  /** `~/.connectx/agents/<agent>/<profile>` */
  dir: string
  keyFile: string
  identityFile: string
  sessionFile: string
  /** A successor key that has been generated but NOT yet installed — see
   *  `stageSuccessorKey`. It exists only while an update is in flight. */
  stagedKeyFile: string
  /** The copy of the DID document as the DID server has it on file — see
   *  `readDidDocumentCopy`. Named after the file the spec publishes (§2.5.3 L409). */
  documentFile: string
}

/** Resolve the store root (honours `$CONNECTX_HOME`, else `~/.connectx`). */
export function storeRoot(): string {
  const override = process.env.CONNECTX_HOME
  return override && override.trim() !== '' ? resolve(override) : join(homedir(), '.connectx')
}

/** Validate one path segment (agent id / profile name). Rejects traversal. */
function assertSegment(value: string, label: string): string {
  if (value === '' || value === '.' || value === '..' || !SEGMENT.test(value)) {
    throw new ConnectxError(
      'invalid_argument',
      `Invalid ${label} "${value}" (allowed: letters, digits, dot, dash, underscore — no path separators)`,
    )
  }
  return value
}

export function assertAgentId(id: string): string {
  return assertSegment(id, 'agent id')
}

export function assertProfileName(name: string): string {
  return assertSegment(name, 'profile name')
}

/** Compose the on-disk layout for an (agent, profile) pair. */
export function storeLocation(agent: string, profile: string): StoreLocation {
  const dir = join(storeRoot(), 'agents', assertAgentId(agent), assertProfileName(profile))
  return {
    agent,
    profile,
    dir,
    keyFile: join(dir, 'key'),
    identityFile: join(dir, 'identity.json'),
    sessionFile: join(dir, 'session.json'),
    stagedKeyFile: join(dir, 'key.next'),
    documentFile: join(dir, 'did.json'),
  }
}

// Agent markers. Each agent is identified by any of its env vars. The list is
// scanned IN FULL (no early-out) so a second agent's marker cannot be masked by
// whichever entry happens to be first.
const AGENT_MARKERS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['claude-code', ['CLAUDECODE']],
  ['codex', ['CODEX_SANDBOX', 'CODEX_HOME']],
]

/** Detect which agent is running, from the environment. Best-effort: an unknown
 *  environment resolves to `default`. But an environment matching MORE THAN ONE
 *  agent is REFUSED (`agent_ambiguous`) rather than guessed — because env vars are
 *  inherited down the process tree, a Codex launched from inside a Claude Code
 *  shell carries both markers, and silently binding either identity is the wrong
 *  principal. The caller must say who it is: `--agent` / `$CONNECTX_AGENT`. */
export function detectAgentId(): string {
  const matched = AGENT_MARKERS.filter(([, vars]) => vars.some((name) => process.env[name])).map(([id]) => id)
  if (matched.length > 1) {
    throw new ConnectxError(
      'agent_ambiguous',
      `Ambiguous agent: environment matches ${matched.map((id) => `"${id}"`).join(' and ')}. ` +
        'Say who you are with --agent <id> or $CONNECTX_AGENT (inherited env vars make detection unreliable).',
    )
  }
  return matched[0] ?? 'default'
}

/** `--agent` > `$CONNECTX_AGENT` > the current agent > detection > `default`.
 *
 *  The current agent (`connectx agent use`) sits BELOW the flag and the env var — each
 *  of those is said for one invocation, and a script that names an agent must not be
 *  redirected by a selection left lying in the store — and ABOVE detection, which is a
 *  guess from markers a nested shell may carry twice: a selection is a statement of who
 *  is acting, so it also settles the ambiguity detection would refuse. */
export function resolveAgentId(flagValue?: string): string {
  const flag = flagValue?.trim()
  if (flag !== undefined && flag !== '') return assertAgentId(flag)
  const env = process.env.CONNECTX_AGENT?.trim()
  if (env !== undefined && env !== '') return assertAgentId(env)
  const current = readCurrentAgent()
  if (current !== undefined) return current
  return assertAgentId(detectAgentId())
}

/** `--profile` > `$CONNECTX_PROFILE` > `default`. */
export function resolveProfileName(flagValue?: string): string {
  const raw = flagValue && flagValue !== '' ? flagValue : (process.env.CONNECTX_PROFILE ?? 'default')
  return assertProfileName(raw.trim())
}

/** `<store root>/current-agent` — the pointer a selection writes. A selection names a
 *  directory that may not exist yet, so the file is a statement of who is acting, never
 *  evidence that an identity is there. */
export function currentAgentFile(): string {
  return join(storeRoot(), 'current-agent')
}

/** The selected agent, or `undefined` when none was selected.
 *
 *  Tolerant about a MISSING file (that is the ordinary state) and strict about a
 *  malformed one: a value that cannot be an agent id would otherwise fail later inside
 *  `assertAgentId`, naming the id but not the file it came from — and that file is the
 *  only thing that can be edited to fix it. */
export function readCurrentAgent(): string | undefined {
  const file = currentAgentFile()
  let raw: string
  try {
    raw = readFileSync(file, 'utf8')
  } catch {
    return undefined
  }
  const value = raw.trim()
  if (value === '') return undefined
  try {
    return assertAgentId(value)
  } catch {
    throw new ConnectxError(
      'invalid_argument',
      `The current agent (${file}) is not a usable agent id: "${value}". ` +
        'Run: connectx agent use <id>',
    )
  }
}
