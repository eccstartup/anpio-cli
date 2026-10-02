import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.test.ts'],
    // Every case in this package boots a real service on a real port and runs one
    // exchange through it, so the file is a few seconds of work, not a few hundred ms.
    // Nothing here is shared between files — each one owns its process-wide state
    // (`CONNECTX_HOME`, the keystore) — so they must not run concurrently.
    fileParallelism: false,
    testTimeout: 30_000,
  },
})
