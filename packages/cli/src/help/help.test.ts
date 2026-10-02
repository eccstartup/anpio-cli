// Guards on the command surface and on the help rendered from it.
//
// Four things are being kept true, each of which was false at some point:
//
//  1. A page shows every flag it accepts and accepts every flag it shows. That is
//     what lets the docs gate treat a missing flag mention as a failure: the help is
//     not a summary of the surface, it IS the surface.
//  2. The help obeys the style contract: state, don't argue; no first or second person;
//     no emoji; no ALL-CAPS emphasis; no em dash spliced into prose. Checked on the
//     authored strings, since the `—` in the heading is the renderer's own separator and
//     not something anyone wrote.
//  3. Every `See:` line reaches a page the docs site has. It is the only outgoing link
//     in help, so a rename under `vercel/` would otherwise 404 every page silently.
//
// The skill gate that used to live here (SKILL.md's verbatim invocations naming only
// commands this build has) moved to the Rust side when the skill was renamed to
// `skill/agentx-cli/SKILL.md` and rewritten for the Rust client — the skill describes
// `agentx-cli` now, so its invocations are checked against that binary in
// `rust/crates/agentx-cli/tests/cli_surface.rs`. A gate on this side would have been
// checking the wrong command surface.

import { existsSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  COMMANDS,
  DOCS_BASE,
  GLOBAL_FLAGS,
  acceptedArgs,
  acceptedFlags,
  acceptedFlagsOfCommand,
  acceptedSignatures,
  acceptedSignaturesOfCommand,
  flagNames,
  usageArgs,
  type CommandSpec,
  type PageSpec,
} from './commands'
import {
  renderCommandIndex,
  renderExtraArgument,
  renderHelp,
  renderIndex,
  renderUnknownCommand,
  renderUnknownFlag,
  renderUnknownSubcommand,
} from './render'

const CLI_SRC = readFileSync(new URL('../cli.ts', import.meta.url), 'utf8')

const WIDTH = 80

function pagesOf(command: CommandSpec): Array<{ path: string; page: PageSpec }> {
  return command.pages.map((page) => ({
    path: page.sub === undefined ? command.name : `${command.name} ${page.sub}`,
    page,
  }))
}

const allPages = COMMANDS.flatMap(pagesOf)

describe('help rendering', () => {
  it('renders every command at every level', () => {
    const index = renderIndex()
    expect(index).toContain('Usage:')
    for (const command of COMMANDS) {
      for (const item of command.index) expect(index).toContain(item.form.split(' ')[0])

      const level1 = renderCommandIndex(command)
      expect(level1).toContain(`connectx ${command.name}`)
      for (const { path, page } of pagesOf(command)) {
        const text = renderHelp(path.split(' '))
        expect(text).toContain('Usage:')
        expect(text).toContain('Options:')
        expect(text).toContain('Examples:')
        expect(text).toContain(`connectx ${path} —`)
        expect(text).toContain(page.examples[0])
      }
    }
  })

  it('wraps every prose line, and leaves the runnable ones alone', () => {
    // The three rejection messages are on this list because they were the ones that got
    // past a gate that only looked at help: `unknown option` names every flag the page
    // takes, so on `login` it printed one 250-column line for the terminal to hard-wrap.
    const widest = [...allPages].sort((a, b) => acceptedSignatures(b.page).length - acceptedSignatures(a.page).length)[0]
    const texts = [
      renderIndex(),
      ...COMMANDS.map(renderCommandIndex),
      ...allPages.map((p) => renderHelp(p.path.split(' '))),
      renderUnknownCommand('didd'),
      renderUnknownFlag('--bogus', widest.path, widest.page),
      renderUnknownSubcommand('bogus', COMMANDS[0]),
      ...allPages.map((p) => renderExtraArgument('leftover', p.path, p.page)),
    ]
    for (const text of texts) {
      const lines = text.split('\n')
      const exampleAt = lines.indexOf('Examples:')
      for (const [i, line] of lines.entries()) {
        // Two kinds of line are exempt, for the same reason: wrapping them would break
        // them. A `See:` line is one URL and breaking it makes it unclickable; a line
        // under `Examples:` is a command, and a paste of a wrapped command fails.
        if (line.includes('http')) continue
        if (exampleAt !== -1 && i > exampleAt) continue
        expect(line.length, `${JSON.stringify(line)} is ${line.length} columns`).toBeLessThanOrEqual(WIDTH)
      }
    }
  })

  it('a page shows every flag it accepts and accepts every flag it shows', () => {
    for (const { path, page } of allPages) {
      const rendered = renderHelp(path.split(' '))
      const options = rendered.slice(rendered.indexOf('Options:'), rendered.indexOf('\nOutput:'))
      const shown = new Set<string>()
      for (const match of options.matchAll(/--[a-z][a-z0-9-]*/g)) {
        const name = flagNames(match[0])[0]
        if (name !== undefined) shown.add(name)
      }
      // The manifest spells a boolean that defaults on as `--no-x` and `flagNames` also
      // yields the positive alias; help shows the `--no-` form, so the comparison is
      // against the shown spelling plus the two flags on every page.
      const expected = new Set<string>(GLOBAL_FLAGS)
      for (const signature of acceptedSignatures(page)) expected.add(flagNames(signature)[0])
      expect([...shown].sort(), `${path} renders a different flag set than it documents`).toEqual([...expected].sort())
    }
  })

  it('offers a suggestion for a truncated name as well as a mistyped one', () => {
    expect(renderUnknownCommand('vers')).toContain('connectx version --help')
    expect(renderUnknownCommand('didd')).toContain('connectx did --help')
    // A bare verb that only lives under a namespace still finds its home.
    expect(renderUnknownCommand('use')).toContain('connectx agent use --help')
  })
})

/** Every string an author typed into the manifest — the renderer's own punctuation
 *  (the `—` after a command path, the indentation) is not on this list. */
function authoredStrings(): Array<{ where: string; text: string }> {
  const out: Array<{ where: string; text: string }> = []
  const add = (where: string, text: string) => out.push({ where, text })
  for (const command of COMMANDS) {
    add(`command ${command.name}`, command.purpose)
    add(`command ${command.name}`, command.group)
    for (const item of command.index) add(`index ${item.form}`, item.brief)
    for (const { path, page } of pagesOf(command)) {
      add(`page ${path}`, page.purpose)
      for (const line of page.usage) add(`page ${path} usage`, line)
      for (const group of page.options) {
        add(`page ${path} group`, group.title)
        if (group.note !== undefined) add(`page ${path} note`, group.note)
        for (const row of group.rows) {
          add(`page ${path} ${row.signature}`, row.summary)
          if (row.fallback !== undefined) add(`page ${path} ${row.signature}`, row.fallback)
        }
      }
      for (const line of page.output ?? []) add(`page ${path} output`, line)
      for (const exit of page.exits ?? []) add(`page ${path} exit ${exit.code}`, exit.meaning)
      for (const example of page.examples) add(`page ${path} example`, example)
    }
  }
  return out
}

describe('help style', () => {
  const authored = authoredStrings()

  it('has something to check', () => {
    expect(authored.length).toBeGreaterThan(100)
  })

  it('uses no emoji', () => {
    for (const { where, text } of authored) {
      expect(/\p{Extended_Pictographic}/u.test(text), `${where}: ${text}`).toBe(false)
    }
  })

  it('uses neither the first nor the second person', () => {
    for (const { where, text } of authored) {
      expect(/\b(I|we|us|our|ours|you|your|yours)\b/i.test(text), `${where}: ${text}`).toBe(false)
    }
  })

  it('does not shout', () => {
    for (const { where, text } of authored) {
      expect(
        /\b(NEVER|ALWAYS|MUST|IMPORTANT|WARNING|CAUTION|REQUIRED|NOTE)\b/.test(text),
        `${where}: ${text}`,
      ).toBe(false)
    }
  })

  it('inserts no em dash into prose', () => {
    for (const { where, text } of authored) {
      expect(text.includes('—'), `${where}: ${text}`).toBe(false)
    }
  })
})

/** The `const OPTIONS = { … } as const` block of cli.ts, as text. Importing the entry
 *  instead would run `main()`; reading it is the same trick the docs gate uses to read
 *  the dispatch. */
const OPTIONS_BLOCK = (() => {
  const block = /^const OPTIONS = \{([\s\S]*?)^\} as const/m.exec(CLI_SRC)
  if (block === null) throw new Error('cli.ts no longer declares `const OPTIONS = { … } as const`')
  return block[1]
})()

function parseTableFlags(): string[] {
  return [...OPTIONS_BLOCK.matchAll(/^ {2}'?([a-z][a-z0-9-]*)'?:/gm)].map((m) => m[1])
}

describe('command surface', () => {
  it('is the same set of flags on both sides of the parse table', () => {
    // Exact spellings, no `--no-` normalization: `allowNegative` is off, so the parser
    // answers to the literal key a page writes and nothing else. A page showing
    // `--no-install` and a table carrying `install` are two different flags.
    const documented = new Set<string>()
    for (const command of COMMANDS) {
      for (const signature of acceptedSignaturesOfCommand(command.name)) {
        const name = flagNames(signature)[0]
        if (name !== undefined) documented.add(name)
      }
    }
    const known = new Set([...documented, ...GLOBAL_FLAGS])
    const table = parseTableFlags()

    // Both directions matter: a flag the parser knows but no page documents is
    // invisible help, and a flag a page documents but the parser rejects fails at
    // the terminal. Neither is allowed to be the only side that changed.
    expect(table.filter((f) => !known.has(f)).sort()).toEqual([])
    expect([...known].filter((f) => !table.includes(f)).sort()).toEqual([])
  })

  it('keeps the web3 wallet out of the DID layer, and inside the ANP layer', () => {
    // The layering rule, as an executable claim. `did` is DID-protocol only, and `msg`
    // addresses a DID, so neither may offer a wallet: a web3 wallet yields a CAIP-10
    // account id (`eip155:1:0x…`) rather than a DID, and neither family has a place to
    // put one. `anp` signs for an application, where a wallet and a stored key are two
    // sources of the same thing, so every one of its pages takes both.
    const WALLET_FLAGS = ['wallet', 'provider', 'address', 'chain-id']
    for (const command of COMMANDS) {
      if (command.name === 'did' || command.name === 'msg') {
        const flags = acceptedFlagsOfCommand(command.name)
        expect(WALLET_FLAGS.filter((f) => flags.has(f)), `${command.name} takes a wallet flag`).toEqual([])
      }
      if (command.name === 'anp') {
        for (const { path, page } of pagesOf(command)) {
          const flags = acceptedFlags(page)
          expect(WALLET_FLAGS.filter((f) => !flags.has(f)), `${path} does not accept the wallet flags`).toEqual([])
        }
      }
    }
  })

  it('shows a boolean that defaults on in its `--no-` form', () => {
    // `--install` and `--save-session` are not accepted at all: `allowNegative` is off,
    // so the parser knows only the literal `no-` key, and a page documenting the positive
    // spelling would promise a word that fails at the terminal. Checked in both
    // directions — a `no-` key no page shows is invisible help, and a page showing
    // `--no-x` for a key the parser does not have is the same broken promise reversed.
    const negated = parseTableFlags().filter((f) => f.startsWith('no-'))
    expect(negated.length).toBeGreaterThan(0)

    const shown = new Set<string>()
    for (const { page } of allPages) {
      for (const group of page.options) {
        for (const row of group.rows) {
          const name = flagNames(row.signature)[0]
          if (name !== undefined) shown.add(name)
        }
      }
    }
    expect(negated.filter((f) => !shown.has(f)).sort()).toEqual([])
    expect([...shown].filter((f) => f.startsWith('no-') && !negated.includes(f)).sort()).toEqual([])
  })
})

describe('positional arguments', () => {
  it('declares on a page exactly the arguments its usage line spells', () => {
    // The positional counterpart of the flag gate. `args` is what `cli.ts` counts
    // leftovers against and the usage line is what a reader sees; one of them drifting
    // from the other is how `connectx agent show bob` came to answer for the current
    // agent, having dropped `bob` on the floor.
    for (const { path, page } of allPages) {
      expect(acceptedArgs(page), `${path}: args and its first usage line disagree`).toEqual(usageArgs(page.usage[0]))
    }
  })

  it('has both kinds of page, so the check above has teeth', () => {
    expect(allPages.filter((p) => acceptedArgs(p.page).length > 0).length).toBeGreaterThan(0)
    expect(allPages.filter((p) => acceptedArgs(p.page).length === 0).length).toBeGreaterThan(0)
  })

  it('names the leftover argument, and what the page takes instead', () => {
    const required = allPages.find((p) => p.path === 'agent use')
    const none = allPages.find((p) => p.path === 'agent show')
    expect(required && none).toBeTruthy()
    if (required === undefined || none === undefined) return

    const withRequired = renderExtraArgument('bob', required.path, required.page)
    expect(withRequired).toContain('unexpected argument "bob" for `agent use`')
    expect(withRequired).toContain('`agent use` takes: <id>')
    expect(withRequired).toContain('usage: connectx agent use <id> [options]')

    // A page with no arguments says so, rather than printing an empty list.
    expect(renderExtraArgument('bob', none.path, none.page)).toContain('`agent show` takes no arguments')
  })
})

// The `See:` line is the one place help leaves this repo, so it is the one place a
// rename over in `vercel/` can turn every page into a 404 without any test noticing.
// The base is checked too: it spent a while pointing at a different repo's site, which
// no path check on this side could have caught.
describe('the docs a page points at exist', () => {
  const DOCS_ROOT = new URL('../../../../vercel/', import.meta.url)

  const cited = COMMANDS.flatMap((command) =>
    pagesOf(command)
      .filter(({ page }) => page.see !== undefined)
      .map(({ path, page }) => ({ path, see: page.see as string })),
  )

  it('is an origin, so `see` is the only variable part', () => {
    expect(DOCS_BASE).toMatch(/^https:\/\/[^/]+$/)
  })

  it('has pages that carry one', () => {
    expect(cited.length).toBeGreaterThan(0)
  })

  it('names a page the docs site actually has', () => {
    for (const { path, see } of cited) {
      expect(see, `\`${path}\`: \`see\` must be relative to ${DOCS_BASE}`).not.toMatch(/^\/|:\/\//)
      expect(existsSync(new URL(`${see}.md`, DOCS_ROOT)), `\`${path}\`: no docs page \`vercel/${see}.md\``).toBe(true)
    }
  })

  it('sends English help to the English half of the site', () => {
    for (const { path, see } of cited) {
      expect(see.startsWith('en/'), `\`${path}\`: this help is English`).toBe(true)
    }
  })
})
