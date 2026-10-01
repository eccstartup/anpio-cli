// The version of the build being run, read from the CLI's own `package.json`.
//
// One reader, because two callers need it and they must not disagree: `connectx --version`
// reports it, and `project init` stamps it into the scaffolded project's dependency range.
// A template that pinned its own literal would drift from the build that copied it out —
// and drift is silent until someone scaffolds a project, installs, and finds the API it
// was written against is not in the version it got.

import { readFileSync } from 'node:fs'

export function cliVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version?: string
    }
    return pkg.version ?? 'unknown'
  } catch {
    return 'unknown'
  }
}
