// `connectx agent show|use|list` — the store's CURRENT agent: the id every command
// acts as when neither `--agent` nor `$CONNECTX_AGENT` names one.
//
// The selection is one file at the store root, so it is machine-wide rather than
// per-process: it applies to every later command reading that root, including another
// agent's. That is the point — naming the agent on every command was the alternative —
// and it is why the flag and the env var stay ABOVE it: a script, or an agent that must
// not be redirected, names itself on the invocation.
//
// There is no `unset`: overwriting the selection with another `agent use` is how it
// moves, and deleting that one file is how it is dropped.

import { assertAgentId, currentAgentFile, detectAgentId, readCurrentAgent } from '../identity/paths'
import { listIdentities, setCurrentAgent } from '../identity/store'
import type { Values } from './auth'

/** Which step of the chain answered. The chain itself is `resolveAgentId`; this reports
 *  WHICH step spoke, because that is the question the command exists to answer. */
type Source = 'current' | 'env' | 'detected' | 'default'

interface Resolution {
  agent: string
  source: Source
}

function describeAgent(): Resolution {
  const env = process.env.CONNECTX_AGENT?.trim()
  if (env !== undefined && env !== '') return { agent: assertAgentId(env), source: 'env' }
  const current = readCurrentAgent()
  if (current !== undefined) return { agent: current, source: 'current' }
  const detected = detectAgentId()
  return { agent: detected, source: detected === 'default' ? 'default' : 'detected' }
}

function sourceText(resolution: Resolution): string {
  switch (resolution.source) {
    case 'current':
      return `the current agent (${currentAgentFile()})`
    case 'env':
      return 'CONNECTX_AGENT'
    case 'detected':
      return 'detected from the environment'
    default:
      return 'nothing named one: the fallback'
  }
}

/** `connectx agent show|use|list`. Nothing here signs, so every failure belongs on the
 *  top-level handler with its code, as in `runDidStore`. */
export async function runAgent(v: Values, sub: string | undefined, id: string | undefined): Promise<void> {
  switch (sub) {
    case 'show':
      return runAgentShow(v)
    case 'use':
      return runAgentUse(v, id)
    case 'list':
      return runAgentList(v)
    default:
      // cli.ts resolves the page first and answers an unknown subcommand itself.
      throw new Error(`No subcommand "${sub}" for \`connectx agent\``)
  }
}

function runAgentShow(v: Values): void {
  const resolution = describeAgent()
  if (v.json === true) {
    console.log(JSON.stringify({ ...resolution, file: currentAgentFile() }, null, 2))
    return
  }
  const field = (label: string, value: string) => console.log(`${label.padEnd(8)} ${value}`)
  field('agent:', resolution.agent)
  field('source:', sourceText(resolution))
}

function runAgentUse(v: Values, id: string | undefined): void {
  const value = id?.trim()
  if (value === undefined || value === '') throw new Error('Missing required argument <id>')
  // The same guard the store layout applies: an id becomes a path segment, so the
  // boundary is checked here rather than left for the first `join()` to trip over.
  const agent = assertAgentId(value)
  setCurrentAgent(agent)

  if (v.json === true) {
    console.log(JSON.stringify({ agent, file: currentAgentFile() }, null, 2))
  } else {
    console.log(`current agent: ${agent}`)
  }
  // An id with no identity is accepted on purpose (selecting an agent, then creating its
  // key, is the order a new agent is born in) — but it is said out loud, because every
  // later command would otherwise fail with `identity_not_found` and no explanation.
  if (!listIdentities().some((stored) => stored.agent === agent)) {
    console.error(
      `connectx: warning: no identity is stored for agent "${agent}" yet; ` +
        'agent list prints the agents stored here. Run: connectx did create',
    )
  }
}

/** `connectx agent list` — the agents this machine can act as, with the current one
 *  marked. Reads the store; contacts nothing.
 *
 *  Rows are the identities `did list` prints, because the id `agent use` takes is the
 *  agent half of one of them. What this adds is the marker, so the list answers "which
 *  one is in force" as well as "which exist". */
function runAgentList(v: Values): void {
  const identities = listIdentities()
  const current = readCurrentAgent()

  if (v.json === true) {
    console.log(JSON.stringify({ current: current ?? null, identities }, null, 2))
    return
  }
  if (identities.length === 0 && current === undefined) {
    console.log('No agents are stored. Run: connectx did create')
    return
  }
  const mark = (agent: string) => (agent === current ? 'current ' : '        ')
  for (const i of identities) {
    const named = i.registered ? (i.lastDid ?? i.subject ?? '-') : 'not registered'
    console.log(`${mark(i.agent)}${i.agent}/${i.profile}  ${named}  ${i.curve ?? '?'}  ${i.dir}`)
  }
  // A selection that names an agent with nothing stored belongs here too: it is the agent
  // every later command acts as, and "no identity stored" is the whole explanation for the
  // `identity_not_found` that follows.
  if (current !== undefined && !identities.some((i) => i.agent === current)) {
    console.log(`${mark(current)}${current}  no identity stored`)
  }
}
