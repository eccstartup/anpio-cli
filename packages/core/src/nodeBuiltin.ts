// The one door for Node-only modules.
//
// No module specifier ever appears, because a browser bundler would try to resolve one and
// there is nothing to resolve it to. A literal import does not survive the build either:
// esbuild drops the `node:` prefix under the default (browser) platform, so what ships is
// a bare `dns` / `http` / `crypto` and every consumer's bundler warns about a branch that
// cannot run in a browser. Hiding the specifier behind an expression is worse — Turbopack
// fails the whole page on `import(<dynamic>)`. `process.getBuiltinModule` is the API built
// for this case: the module is loaded by name at runtime, so no bundler sees a specifier,
// and in a runtime without it (a browser) this returns `null` for the callers to fall back.
//
// Callers pass the *bare* name and the module type:
//   getNodeBuiltin<typeof import('node:dns')>('dns')
// The type argument is a type node, erased before any bundler sees it.
type ProcessWithBuiltins = {
  process?: { getBuiltinModule?: (id: string) => unknown }
}

export function getNodeBuiltin<T>(name: string): T | null {
  const proc = (globalThis as ProcessWithBuiltins).process
  if (typeof proc?.getBuiltinModule !== 'function') return null
  return proc.getBuiltinModule(name) as T
}
