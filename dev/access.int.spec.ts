import type { Access, CollectionConfig, GlobalConfig } from 'payload'

import { describe, expect, it } from 'vitest'

import {
  authenticated,
  can,
  permissionsOf,
  withAuth,
  withKeycloakAccess,
  withKeycloakGlobalAccess,
} from '../src/access.js'
import { makeTestReq } from './helpers/payload.js'

const editor = { id: 1, collection: 'users', permissions: { posts: { edit: true } } }
const reader = { id: 2, collection: 'users', permissions: { posts: { edit: false } } }
const args = (user: unknown) => ({ req: { user } }) as never
const rules = { read: authenticated, write: can('posts.edit') }

const collection = (access: CollectionConfig['access']): CollectionConfig => ({
  slug: 'x',
  access,
  fields: [],
})
const run = (fn: Access | undefined, user: unknown) => Promise.resolve(fn!(args(user)))

describe('authenticated / can / permissionsOf', () => {
  it('authenticated takes any user, can takes only an explicit true', () => {
    expect(authenticated(args(null))).toBe(false)
    expect(authenticated(args(reader))).toBe(true)
    expect(can('posts.edit')(args(null))).toBe(false)
    expect(can('posts.edit')(args(reader))).toBe(false)
    expect(can('posts.edit')(args(editor))).toBe(true)
    expect(can('posts.delete')(args(editor))).toBe(false)
    expect(permissionsOf(null)).toEqual({})
    expect(permissionsOf({})).toEqual({})
  })
})

describe('withKeycloakAccess', () => {
  it('turns read: () => true into "authenticated" and makes writes need the permission', async () => {
    const [wrapped] = withKeycloakAccess(
      [collection({ read: () => true, readVersions: () => true })],
      rules,
    )
    expect(await run(wrapped.access?.read, null)).toBe(false)
    expect(await run(wrapped.access?.read, reader)).toBe(true)
    expect(await run(wrapped.access?.readVersions, reader)).toBe(true)
    expect(await run(wrapped.access?.create, reader)).toBe(false)
    expect(await run(wrapped.access?.update, editor)).toBe(true)
    expect(await run(wrapped.access?.delete, editor)).toBe(true)
  })

  it('an existing denial wins, and a Where from the existing rule survives', async () => {
    const where = { id: { equals: 1 } }
    const [wrapped] = withKeycloakAccess(
      [collection({ create: () => false, read: () => where, update: () => true })],
      rules,
    )
    expect(await run(wrapped.access?.create, editor)).toBe(false)
    expect(await run(wrapped.access?.update, editor)).toBe(true)
    expect(await run(wrapped.access?.update, reader)).toBe(false)
    expect(await run(wrapped.access?.read, reader)).toEqual(where)
    // An anonymous caller is cut off by our rule before the Where matters.
    expect(await run(wrapped.access?.read, null)).toBe(false)
  })

  it('two Where results are intersected, not one silently dropped', async () => {
    const ownRule = { tenant: { equals: 't1' } }
    const pluginRule = { owner: { equals: 1 } }
    const [wrapped] = withKeycloakAccess([collection({ read: () => ownRule })], {
      read: () => pluginRule,
      write: () => false,
    })
    expect(await run(wrapped.access?.read, reader)).toEqual({ and: [ownRule, pluginRule] })
  })

  it('a collection without access is closed too, and skip leaves one alone', async () => {
    const [bare, skipped] = withKeycloakAccess(
      [collection(undefined), { ...collection({ read: () => true }), slug: 'users' }],
      rules,
      ['users'],
    )
    expect(await run(bare.access?.read, null)).toBe(false)
    expect(await run(bare.access?.update, reader)).toBe(false)
    expect(await run(skipped.access?.read, null)).toBe(true)
    expect(skipped.access?.update).toBeUndefined()
  })

  it('globals: read needs a user, update needs the permission', async () => {
    const global: GlobalConfig = { slug: 'g', access: { read: () => true }, fields: [] }
    const [wrapped] = withKeycloakGlobalAccess([global], rules)
    expect(await run(wrapped.access?.read, null)).toBe(false)
    expect(await run(wrapped.access?.read, reader)).toBe(true)
    expect(await run(wrapped.access?.update, reader)).toBe(false)
    expect(await run(wrapped.access?.update, editor)).toBe(true)
  })
})

describe('withAuth', () => {
  const handler = withAuth(() => Response.json({ ok: true }), can('posts.edit'))

  it('401 without a user, 403 without the permission, 200 with it', async () => {
    expect((await handler(await makeTestReq())).status).toBe(401)
    expect((await handler(await makeTestReq({ user: reader as never }))).status).toBe(403)
    const ok = await handler(await makeTestReq({ user: editor as never }))
    expect(ok.status).toBe(200)
    expect(await ok.json()).toEqual({ ok: true })
  })

  it('defaults to requiring authentication only', async () => {
    const anyUser = withAuth(() => new Response(null, { status: 204 }))
    expect((await anyUser(await makeTestReq({ user: reader as never }))).status).toBe(204)
    expect((await anyUser(await makeTestReq())).status).toBe(401)
  })
})
