import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { KeycloakUser, PluginContext } from '../src/types.js'

import { createKeycloak } from '../src/keycloak.js'
import {
  createInternalStrategy,
  createStrategy,
  extractToken,
  INTERNAL_STRATEGY_NAME,
  INTERNAL_SUB,
  STRATEGY_NAME,
} from '../src/strategy.js'
import { COOKIE, testContext } from './helpers/context.js'
import { fakeKeycloak, type FakeKeycloak, KC } from './helpers/keycloak.js'
import { getTestPayload } from './helpers/payload.js'

const SUB = '__kc_test_sub'
const ORIGIN = 'http://localhost:3000'
const INTERNAL_HOST = 'app-svc.internal:3000'

let fake: FakeKeycloak
let ctx: PluginContext

const info = (overrides: Record<string, unknown> = {}) => ({
  name: 'KC Test',
  email: 'KC@test.local',
  permissions: { posts: { edit: true } },
  sub: SUB,
  ...overrides,
})

async function authenticate(headers: Record<string, string>, canSetHeaders = false) {
  const payload = await getTestPayload()
  const result = await createStrategy(ctx).authenticate({
    canSetHeaders,
    headers: new Headers(headers),
    payload,
  })
  return { ...result, user: result.user as KeycloakUser | null }
}

async function cleanup() {
  const payload = await getTestPayload()
  await payload.delete({
    collection: 'users',
    where: {
      or: [{ keycloakSub: { like: '__kc_test_' } }, { keycloakSub: { equals: INTERNAL_SUB } }],
    },
  })
}

beforeAll(async () => {
  fake = await fakeKeycloak()
  ctx = testContext(fake.getKey, { internalHosts: [INTERNAL_HOST] })
  await cleanup()
})

beforeEach(() => {
  fake.userInfo = () => info()
  fake.tokens = null
  // A fresh instance means a fresh userinfo cache, so cases do not leak into each other.
  ctx.keycloak = createKeycloak({ ...KC, getKey: fake.getKey })
})

afterAll(async () => {
  await cleanup()
  fake.restore()
})

describe('extractToken', () => {
  it('Bearer wins, the cookie is accepted only from an allowed origin', () => {
    expect(
      extractToken(new Headers({ authorization: 'Bearer abc' }), COOKIE.access, [ORIGIN]),
    ).toEqual({ fromCookie: false, token: 'abc' })
    expect(
      extractToken(new Headers({ cookie: `${COOKIE.access}=ck` }), COOKIE.access, [ORIGIN]),
    ).toEqual({ fromCookie: true, token: 'ck' })
    expect(
      extractToken(new Headers({ cookie: `${COOKIE.access}=ck`, origin: ORIGIN }), COOKIE.access, [
        ORIGIN,
      ])?.token,
    ).toBe('ck')
    expect(
      extractToken(
        new Headers({ cookie: `${COOKIE.access}=ck`, origin: 'https://evil.example' }),
        COOKIE.access,
        [ORIGIN],
      ),
    ).toBeUndefined()
    expect(extractToken(new Headers(), COOKIE.access, [ORIGIN])).toBeUndefined()
  })
})

describe('keycloak strategy', () => {
  it('Bearer: creates the user by sub, lowercases the email, reads permissions from userinfo', async () => {
    const token = await fake.sign({ sub: SUB })
    const { user } = await authenticate({ authorization: `Bearer ${token}` })

    expect(user).not.toBeNull()
    expect(user?.keycloakSub).toBe(SUB)
    expect(user?.email).toBe('kc@test.local')
    expect(user?.name).toBe('KC Test')
    expect(user?.permissions).toEqual({ posts: { edit: true } })
    expect(user?.collection).toBe('users')
    expect(user?._strategy).toBe(STRATEGY_NAME)

    const payload = await getTestPayload()
    const rows = await payload.find({
      collection: 'users',
      where: { keycloakSub: { equals: SUB } },
    })
    expect(rows.totalDocs).toBe(1)
  })

  it('reads permissions from a custom claim when one is configured', async () => {
    const custom = testContext(fake.getKey, { permissionsClaim: 'abac' })
    fake.userInfo = () => ({ abac: { posts: { edit: true } }, permissions: {}, sub: SUB })
    const payload = await getTestPayload()
    const result = await createStrategy(custom).authenticate({
      canSetHeaders: false,
      headers: new Headers({ authorization: `Bearer ${await fake.sign({ sub: SUB })}` }),
      payload,
    })
    expect((result.user as KeycloakUser | null)?.permissions).toEqual({ posts: { edit: true } })
  })

  it('a second sign-in reuses the row and updates the name', async () => {
    const first = await authenticate({ authorization: `Bearer ${await fake.sign({ sub: SUB })}` })
    fake.userInfo = () => info({ name: 'Renamed' })
    // The second token has to differ: RS256 is deterministic and the userinfo cache key is the
    // token itself, so a byte-identical one would hand back the previous response.
    const second = await authenticate({
      authorization: `Bearer ${await fake.sign({ sub: SUB }, { expiresIn: 301 })}`,
    })

    expect(second.user?.id).toBe(first.user?.id)
    expect(second.user?.name).toBe('Renamed')
    const payload = await getTestPayload()
    expect(
      (await payload.find({ collection: 'users', where: { keycloakSub: { equals: SUB } } }))
        .totalDocs,
    ).toBe(1)
  })

  it('a parallel first sign-in with one token yields one user and one row', async () => {
    const sub = '__kc_test_race'
    fake.userInfo = () => info({ sub })
    const headers = { authorization: `Bearer ${await fake.sign({ sub })}` }

    const [a, b] = await Promise.all([authenticate(headers), authenticate(headers)])

    expect(a.user?.keycloakSub).toBe(sub)
    expect(b.user?.id).toBe(a.user?.id)
    const payload = await getTestPayload()
    expect(
      (await payload.find({ collection: 'users', where: { keycloakSub: { equals: sub } } }))
        .totalDocs,
    ).toBe(1)
  })

  it('a cookie without Origin authenticates, one from a foreign Origin does not', async () => {
    const token = await fake.sign({ sub: SUB })
    expect((await authenticate({ cookie: `${COOKIE.access}=${token}` })).user?.keycloakSub).toBe(SUB)
    expect(
      (
        await authenticate({
          cookie: `${COOKIE.access}=${token}`,
          origin: 'https://evil.example',
        })
      ).user,
    ).toBeNull()
  })

  it('broken, foreign and expired-without-refresh tokens are anonymous', async () => {
    expect((await authenticate({ authorization: 'Bearer nope' })).user).toBeNull()
    const foreign = await fake.sign({ sub: SUB }, { issuer: `${KC.url}/realms/other` })
    expect((await authenticate({ authorization: `Bearer ${foreign}` })).user).toBeNull()
    const expired = await fake.sign({ sub: SUB }, { expiresIn: -60 })
    expect((await authenticate({ cookie: `${COOKIE.access}=${expired}` })).user).toBeNull()
  })

  it('expired access plus a refresh cookie: silent refresh, Set-Cookie only when canSetHeaders', async () => {
    const expired = await fake.sign({ sub: SUB }, { expiresIn: -60 })
    const fresh = await fake.sign({ sub: SUB })
    fake.tokens = {
      access_token: fresh,
      expires_in: 300,
      refresh_expires_in: 1800,
      refresh_token: 'rt-2',
    }

    const cookie = `${COOKIE.access}=${expired}; ${COOKIE.refresh}=rt-1`
    const silent = await authenticate({ cookie })
    expect(silent.user?.keycloakSub).toBe(SUB)
    expect(silent.responseHeaders).toBeUndefined()

    ctx.keycloak = createKeycloak({ ...KC, getKey: fake.getKey })
    const rest = await authenticate({ cookie }, true)
    expect(rest.user?.keycloakSub).toBe(SUB)
    const cookies = rest.responseHeaders?.getSetCookie() ?? []
    expect(cookies.some((c) => c.startsWith(`${COOKIE.access}=${fresh}`))).toBe(true)
    expect(cookies.some((c) => c.startsWith(`${COOKIE.refresh}=rt-2`))).toBe(true)
  })

  it('a Bearer token is never refreshed', async () => {
    const expired = await fake.sign({ sub: SUB }, { expiresIn: -60 })
    expect(
      (
        await authenticate({
          authorization: `Bearer ${expired}`,
          cookie: `${COOKIE.refresh}=rt-1`,
        })
      ).user,
    ).toBeNull()
  })

  it('a 401 from userinfo leaves the user authenticated without permissions', async () => {
    fake.userInfo = () => null
    const { user } = await authenticate({
      authorization: `Bearer ${await fake.sign({ email: 'fallback@test.local', sub: SUB })}`,
    })
    expect(user?.keycloakSub).toBe(SUB)
    expect(user?.permissions).toEqual({})
    expect(user?.email).toBe('fallback@test.local')
  })
})

describe('internal strategy', () => {
  const authenticate = async (headers: Record<string, string>) => {
    const payload = await getTestPayload()
    const result = await createInternalStrategy(ctx).authenticate({
      canSetHeaders: false,
      headers: new Headers(headers),
      payload,
    })
    return result.user as KeycloakUser | null
  }

  it('an internal Host without a token reads without permissions, on a single users row', async () => {
    const user = await authenticate({ host: INTERNAL_HOST })
    expect(user?.keycloakSub).toBe(INTERNAL_SUB)
    expect(user?.permissions).toEqual({})
    expect(user?._strategy).toBe(INTERNAL_STRATEGY_NAME)

    const again = await authenticate({ host: INTERNAL_HOST })
    expect(again?.id).toBe(user?.id)
  })

  it('a public Host is anonymous', async () => {
    expect(await authenticate({ host: 'app.example.com' })).toBeNull()
    expect(await authenticate({})).toBeNull()
  })
})
