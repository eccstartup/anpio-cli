// Renders help from `commands.ts`. Nothing here knows what a command DOES.
//
// Three levels, one source:
//   L0  `connectx`                  every command, grouped
//   L1  `connectx did`              a command's subcommands
//   L2  `connectx did create`       one page: usage, options, output, exits
//
// A page's accepted flags are read back out of what it renders (see
// `acceptedFlags`), so "help never promises a flag the command rejects" holds by
// construction rather than by review.

import {
  COMMANDS,
  DOCS_BASE,
  acceptedArgs,
  acceptedFlags,
  acceptedSignatures,
  argSpelling,
  findCommand,
  findPage,
  flagNames,
  type CommandSpec,
  type OptionGroup,
  type PageSpec,
} from './commands'

const INDENT = '  '
const WIDTH = 80
/** Signature column, capped. Set past the longest signature in the manifest
 *  (`--curve <ed25519|secp256k1>`, 27) so no label ever wraps onto its own line.
 *  Longer signatures would put their summary on the next line. */
const LABEL_MAX = 28

/** Wraps at `WIDTH`, hanging-indented. Words longer than the line are left whole. */
function wrap(text: string, indent: string): string[] {
  const room = WIDTH - indent.length
  const out: string[] = []
  let line = ''
  for (const word of text.split(' ')) {
    if (line === '') line = word
    else if (line.length + 1 + word.length <= room) line += ` ${word}`
    else {
      out.push(indent + line)
      line = word
    }
  }
  if (line !== '') out.push(indent + line)
  return out
}

/** A comma-separated list that continues under `INDENT`, breaking after a comma rather
 *  than at a space. `wrap` would split `--key <spec>` across two lines, where it reads as
 *  two flags; a flag and its value are one token to the reader. */
function wrapList(prefix: string, items: string[]): string[] {
  const out: string[] = []
  let line = prefix
  for (const item of items) {
    if (line === prefix) line += item
    else if (line.length + 2 + item.length <= WIDTH) line += `, ${item}`
    else {
      out.push(`${line},`)
      line = INDENT + item
    }
  }
  out.push(line)
  return out
}

/** A two-column block: label, then a wrapped summary. */
function rows(items: Array<{ label: string; text: string }>, base: string): string[] {
  if (items.length === 0) return []
  const width = Math.min(LABEL_MAX, Math.max(...items.map((i) => i.label.length)))
  const out: string[] = []
  for (const item of items) {
    const text = item.text === '' ? '' : `${item.text}`
    if (text === '') {
      out.push(base + item.label)
      continue
    }
    const head = base + item.label.padEnd(width) + INDENT
    if (item.label.length > width) {
      // No room beside the label — the summary starts under it.
      out.push(base + item.label)
      out.push(...wrap(text, base + INDENT + INDENT))
      continue
    }
    const headRoom = WIDTH - head.length
    if (text.length <= headRoom) {
      out.push(head + text)
      continue
    }
    // Fill the first line, then hang the rest under the summary column.
    const words = text.split(' ')
    let line = ''
    let i = 0
    while (i < words.length && line.length + 1 + words[i].length <= headRoom) {
      line = line === '' ? words[i] : `${line} ${words[i]}`
      i += 1
    }
    if (line === '') {
      out.push(head + words[0])
      i = 1
    } else {
      out.push(head + line)
    }
    out.push(...wrap(words.slice(i).join(' '), ' '.repeat(head.length)))
  }
  return out
}

function optionRowText(group: OptionGroup): Array<{ label: string; text: string }> {
  return group.rows.map((row) => ({
    label: row.signature,
    text: row.fallback === undefined ? row.summary : `${row.summary}. ${row.fallback}`,
  }))
}

function section(title: string, body: string[]): string[] {
  if (body.length === 0) return []
  return [`${title}:`, ...body, '']
}

/** `-h, --help` and friends, on every page, so no page has to repeat them. */
function globalGroup(): OptionGroup {
  return {
    title: 'Global',
    rows: [
      { signature: '-h, --help', summary: 'this page' },
      { signature: '-v, --version', summary: 'print the CLI version' },
    ],
  }
}

function usageLines(page: PageSpec): string[] {
  return page.usage.map((u) => `connectx ${u}`)
}

/** The heading above every page: `connectx did update — <purpose>`. The purpose wraps
 *  under a plain indent. It is measured against the whole heading, not the purpose
 *  alone — the command path is already part of the first line, and a heading that ran
 *  to 104 columns was what a purpose measured on its own bought. */
function title(path: string, purpose: string): string[] {
  const head = `connectx ${path} — `
  const out: string[] = []
  let line = head
  for (const word of purpose.split(' ')) {
    // The first word lands on the heading line whatever its length, the way `wrap`
    // leaves an over-long word whole.
    if (line === head || line.length + 1 + word.length <= WIDTH) line = line === head ? head + word : `${line} ${word}`
    else {
      out.push(line)
      line = INDENT + word
    }
  }
  out.push(line)
  return out
}

/** L2, or L1 for a command that has exactly one page. */
function renderPage(command: CommandSpec, page: PageSpec): string {
  const path = page.sub === undefined ? command.name : `${command.name} ${page.sub}`
  const out: string[] = [...title(path, page.purpose), '']
  out.push(...section('Usage', usageLines(page).map((l) => INDENT + l)))

  const groups = [...page.options, globalGroup()].filter((g) => g.rows.length > 0)
  const fixed: string[] = []
  for (const group of groups) {
    if (fixed.length > 0) fixed.push('')
    fixed.push(`${INDENT}${group.title}:`)
    fixed.push(...rows(optionRowText(group), INDENT + INDENT))
    // A group note is prose, not a row: it sits below the rows after a blank line,
    // so it reads as a sentence about the group rather than as another flag.
    if (group.note !== undefined) fixed.push('', ...wrap(group.note, INDENT + INDENT))
  }
  out.push(...section('Options', fixed))

  out.push(...section('Output', (page.output ?? []).flatMap((l) => wrap(l, INDENT))))
  out.push(
    ...section(
      'Exit codes',
      (page.exits ?? []).flatMap((e) => {
        // The meaning hangs under itself, so a wrapped one still reads as the
        // row it belongs to.
        const head = INDENT + e.code.padEnd(3)
        const lines = wrap(e.meaning, ' '.repeat(head.length))
        return [`${head}${lines[0].trimStart()}`, ...lines.slice(1)]
      }),
    ),
  )
  out.push(...section('Examples', page.examples.map((e) => INDENT + `connectx ${e}`)))
  if (page.see !== undefined) out.push(`See: ${DOCS_BASE}/${page.see}`, '')
  return out.join('\n').replace(/\n+$/, '')
}

/** L1: a command that has subcommands, invoked without one. */
export function renderCommandIndex(command: CommandSpec): string {
  const out: string[] = [...title(command.name, command.purpose), '']
  out.push(...section('Usage', [`${INDENT}connectx ${command.name} <subcommand> [options]`]))
  out.push(
    ...section(
      'Subcommands',
      rows(
        command.pages.map((p) => ({ label: p.sub ?? '', text: p.purpose })),
        INDENT,
      ),
    ),
  )
  out.push(`Run \`connectx ${command.name} <subcommand> --help\` for flags, examples, and exit codes.`)
  return out.join('\n')
}

/** L0: every command, grouped. */
export function renderIndex(): string {
  const out: string[] = ['connectx — identity, login, and messaging on the Agent Network Protocol', '']
  out.push(...section('Usage', [`${INDENT}connectx <command> [subcommand] [options]`]))

  const groups = new Map<string, Array<{ form: string; brief: string }>>()
  for (const command of COMMANDS) {
    const rows = groups.get(command.group) ?? []
    rows.push(...command.index)
    groups.set(command.group, rows)
  }
  const width = Math.min(LABEL_MAX, Math.max(...[...groups.values()].flat().map((r) => r.form.length)))
  for (const [group, items] of groups) {
    out.push(`${group}:`)
    for (const item of items) {
      const head = INDENT + item.form.padEnd(width) + INDENT
      if (item.brief.length <= WIDTH - head.length) out.push(head + item.brief)
      else {
        out.push(INDENT + item.form)
        out.push(...wrap(item.brief, INDENT + INDENT))
      }
    }
    out.push('')
  }

  out.push(
    ...section(
      'Options',
      rows(
        [
          { label: '-h, --help', text: 'help for one command: `connectx <command> --help`' },
          { label: '-v, --version', text: 'print version' },
          { label: '--json', text: 'machine-readable output on stdout' },
          {
            label: '--agent <id>',
            text: 'who is acting (default: the current agent, else detected). agent list prints the stored ids',
          },
          { label: '--profile <name>', text: 'identity within an agent. default: "default"' },
        ],
        INDENT,
      ),
    ),
  )
  out.push('Run `connectx <command> --help` for flags, examples, and exit codes.')
  return out.join('\n')
}

/** Renders whatever help the invocation asked for. Never fails: an unresolvable
 *  path falls back to the level above it. */
export function renderHelp(positionals: string[]): string {
  const command = findCommand(positionals[0] ?? '')
  if (command === undefined) return renderIndex()
  const sub = positionals[1]
  const page = findPage(command, sub)
  if (page !== undefined) return renderPage(command, page)
  return renderCommandIndex(command)
}

/** The command path this invocation names, for error messages: `connectx did resolve`. */
export function commandPath(positionals: string[]): string {
  const command = findCommand(positionals[0] ?? '')
  if (command === undefined) return positionals[0] ?? ''
  const page = findPage(command, positionals[1])
  return page?.sub === undefined ? command.name : `${command.name} ${page.sub}`
}

/** Levenshtein, capped — only used to offer one suggestion for a typo. */
function distance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i += 1) {
    let diag = prev[0]
    prev[0] = i
    for (let j = 1; j <= b.length; j += 1) {
      const tmp = prev[j]
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1))
      diag = tmp
    }
  }
  return prev[b.length]
}

/** Every name a user could type at the top level, longest useful form first. A command
 *  with subcommands contributes both its own name (which lands on the L1 index) and
 *  each sub-page — `connectx did` is as typeable as `connectx did create`, and
 *  leaving it out made `connectx didd` find nothing nearer than a sub-page. */
function allNames(): string[] {
  const out: string[] = []
  for (const command of COMMANDS) {
    if (command.pages.length > 1) out.push(command.name)
    for (const page of command.pages) out.push(page.sub === undefined ? command.name : `${command.name} ${page.sub}`)
  }
  return out
}

/** A bare verb that only exists as a subcommand (`connectx init` -> `project init`). */
function namespacedVerb(typed: string): string | undefined {
  const hits = allNames().filter((n) => n.split(' ')[1] === typed)
  return hits.length === 1 ? hits[0] : undefined
}

export function renderUnknownCommand(typed: string): string {
  const names = allNames()
  const best = names
    .map((n) => ({ n, d: distance(typed, n) }))
    .sort((x, y) => x.d - y.d)[0]
  // A truncation (`vers` for `version`) is further than the edit distance allows for,
  // so a name the typed word is a prefix of is offered before the edit-distance one.
  const prefix = names.find((n) => n.startsWith(typed))
  const suggested = namespacedVerb(typed) ?? prefix ?? (best !== undefined && best.d <= 2 ? best.n : undefined)
  const paths = COMMANDS.filter((c) => c.pages.length > 1).map((c) => `${c.name} <subcommand>`)
  const out = [`connectx: unknown command "${typed}"`]
  if (suggested !== undefined) out.push(`  did you mean: connectx ${suggested} --help`)
  out.push(
    ...wrap(
      `commands: ${[COMMANDS.filter((c) => c.pages.length === 1).map((c) => c.name), paths].flat().join(', ')}`,
      INDENT,
    ),
  )
  out.push('  run `connectx --help` for the full index')
  return out.join('\n')
}

/** A positional argument the page has no slot for. The flag rejection has the same
 *  shape; the difference is that there is no near name to suggest — an extra
 *  argument is a leftover, and the remedy is to remove it. */
export function renderExtraArgument(extra: string, path: string, page: PageSpec): string {
  const out = [`connectx: unexpected argument "${extra}" for \`${path}\``]
  const args = acceptedArgs(page)
  if (args.length === 0) out.push(`  \`${path}\` takes no arguments`)
  else out.push(`  \`${path}\` takes: ${args.map(argSpelling).join(' ')}`)
  out.push(`  usage: connectx ${page.usage[0]}`)
  out.push(`  run \`connectx ${path} --help\``)
  return out.join('\n')
}

/** A subcommand that does not exist under a command that has subcommands. */
export function renderUnknownSubcommand(typed: string, command: CommandSpec): string {
  const subs = command.pages.map((p) => p.sub ?? '')
  const best = subs
    .map((s) => ({ s, d: distance(typed, s) }))
    .sort((x, y) => x.d - y.d)[0]
  const out = [`connectx: unknown subcommand "${typed}" for \`connectx ${command.name}\``]
  if (best !== undefined && best.d <= 2) out.push(`  did you mean: connectx ${command.name} ${best.s} --help`)
  out.push(`  subcommands: ${subs.join(', ')}`)
  out.push(`  run \`connectx ${command.name} --help\``)
  return out.join('\n')
}

/** The other pages that document this flag. The option groups are laid out by layer
 *  (`--wallet` is an `anp` choice, `--force` a `did create` one), so "this flag exists,
 *  just not here" is the common way to land on a rejection — and the page that does take
 *  it is the one the caller meant.
 *
 *  The match is on the literal spelling, because that is what a page accepts: nothing
 *  derives `--no-json` from `--json`, so a page offering `--json` is NOT a page that
 *  takes `--no-json` and must not be named as one. The direction that does help is the
 *  other one — a caller typing `--install` for a flag that only exists as `--no-install`
 *  is pointed at the page that has it — so a positive name also matches its `no-` form. */
function pagesAccepting(flag: string, exclude: string): string[] {
  const typed = flag.replace(/^-+/, '')
  const wanted = typed.startsWith('no-') ? [typed] : [typed, `no-${typed}`]
  const out: string[] = []
  for (const command of COMMANDS) {
    for (const page of command.pages) {
      const path = page.sub === undefined ? command.name : `${command.name} ${page.sub}`
      if (path === exclude) continue
      if (acceptedSignatures(page).some((s) => wanted.includes(flagNames(s)[0]))) out.push(path)
    }
  }
  return out
}

/** The one rejection a flag a command does not accept gets. Names the flag, the
 *  command's own page, and the nearest flag that page does accept. */
export function renderUnknownFlag(typed: string, path: string, page: PageSpec): string {
  const signatures = acceptedSignatures(page)
  const best = signatures
    .map((s) => ({ s, d: distance(typed.replace(/^no-/, ''), flagNames(s)[0].replace(/^no-/, '')) }))
    .sort((x, y) => x.d - y.d)[0]
  const out = [`connectx: unknown option "${typed}" for \`${path}\``]
  if (best !== undefined && best.d <= 3) out.push(`  did you mean: ${best.s}`)
  // The accepted list is every flag the page takes, so on the widest commands it runs to a
  // couple of hundred columns and the terminal hard-wraps it into an unreadable block. It is
  // wrapped here instead, under its own indent, like every other prose line.
  out.push(...wrapList(`${INDENT}\`${path}\` accepts: `, signatures))
  const elsewhere = pagesAccepting(typed, path)
  if (elsewhere.length > 0) {
    out.push(...wrap(`${INDENT}\`${typed}\` is taken by: ${elsewhere.map((p) => `connectx ${p}`).join(', ')}`, INDENT))
  }
  out.push(`  run \`connectx ${path} --help\``)
  return out.join('\n')
}
