import path from 'path'
import { loadEnv } from 'payload/node'
import { fileURLToPath } from 'url'
import tsconfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vitest/config'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

export default defineConfig(() => {
  loadEnv(path.resolve(dirname, './dev'))

  return {
    plugins: [
      tsconfigPaths({
        ignoreConfigErrors: true,
      }),
    ],
    test: {
      environment: 'node',
      // One in-memory MongoDB for the whole run, started before any worker forks.
      globalSetup: ['./dev/helpers/globalSetup.ts'],
      hookTimeout: 60_000,
      // e2e.spec.ts belongs to Playwright.
      include: ['dev/**/*.int.spec.ts'],
      testTimeout: 30_000,
    },
  }
})
