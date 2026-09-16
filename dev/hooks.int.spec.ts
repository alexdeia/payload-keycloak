import type { PayloadRequest } from 'payload'

import { Forbidden } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { PluginContext } from '../src/types.js'

import { createAfterLogoutHook, createMeHook, createRefreshHook } from '../src/hooks.js'
import { createKeycloak, expiresAt } from '../src/keycloak.js'
import { COOKIE, testContext } from './helpers/context.js'
import { fakeKeycloak, type FakeKeycloak, KC } from './helpers/keycloak.js'
import { makeTestReq } from './helpers/payload.js'

let fake: FakeKeycloak
let ctx: PluginContext
const user = { id: 1, collection: 'users' } as never

type WithExp = { exp: number } | undefined
const reqWith = (cookie: string) =>
  makeTestReq({ headers: new Headers({ cookie }) } as Partial<PayloadRequest>)

beforeAll(async () => {
  fake = await fakeKeycloak()
  ctx = testContext(fake.getKey)
})

beforeEach(() => {
  fake.tokens = null
  ctx.keycloak = createKeycloak({ ...KC, getKey: fake.getKey })
})

afterAll(() => fake.restore())

describe('hooks.me', () => {
  it('takes exp from the refresh token, falling back to the access token', async () => {
    const access = await fake.sign({ sub: 's' }, { expiresIn: 300 })
    const refresh = await fake.sign({ sub: 's', typ: 'Refresh' }, { expiresIn: 1800 })
    const me = createMeHook(ctx)

    const both = (await me({
      args: {
        req: await reqWith(`${COOKIE.access}=${access}; ${COOKIE.refresh}=${refresh}`),
      } as never,
      user,
    })) as WithExp
    expect(both?.exp).toBe(Math.floor(expiresAt(refresh)! / 1000))

    const accessOnly = (await me({
      args: { req: await reqWith(`${COOKIE.access}=${access}`) } as never,
      user,
    })) as WithExp
    expect(accessOnly?.exp).toBe(Math.floor(expiresAt(access)! / 1000))

    expect(await me({ args: { req: await reqWith('') } as never, user })).toBeUndefined()
    expect(
      await me({
        args: { req: await reqWith(`${COOKIE.access}=${access}`) } as never,
        user: null as never,
      }),
    ).toBeUndefined()
  })
})

describe('hooks.refresh', () => {
  it('without a refresh cookie it is Forbidden, so Payload never mints its own JWT', async () => {
    const refresh = createRefreshHook(ctx)
    await expect(
      refresh({ args: { req: await reqWith('') } as never, user }),
    ).rejects.toBeInstanceOf(Forbidden)
  })

  it('rotates the pair: access via refreshedToken/setCookie, refresh and id via responseHeaders', async () => {
    const access = await fake.sign({ sub: 's' }, { expiresIn: 300 })
    const rotated = await fake.sign({ sub: 's', typ: 'Refresh' }, { expiresIn: 1800 })
    fake.tokens = {
      access_token: access,
      expires_in: 300,
      id_token: 'id-2',
      refresh_expires_in: 1800,
      refresh_token: rotated,
    }

    const req = await reqWith(`${COOKIE.refresh}=rt-old`)
    const result = (await createRefreshHook(ctx)({ args: { req } as never, user })) as WithExp

    expect(result).toMatchObject({ refreshedToken: access, setCookie: true, user })
    expect(result?.exp).toBe(Math.floor(expiresAt(rotated)! / 1000))
    const cookies = req.responseHeaders?.getSetCookie() ?? []
    expect(cookies.some((c) => c.startsWith(`${COOKIE.refresh}=${rotated}`))).toBe(true)
    expect(cookies.some((c) => c.startsWith(`${COOKIE.idToken}=id-2`))).toBe(true)
    expect(cookies.some((c) => c.startsWith(`${COOKIE.access}=`))).toBe(false)
    expect(new URLSearchParams(fake.calls.at(-1)?.body).get('refresh_token')).toBe('rt-old')
  })
})

describe('hooks.afterLogout', () => {
  it('clears the refresh and id cookies, Payload clears the access one', async () => {
    const req = await reqWith(`${COOKIE.refresh}=rt; ${COOKIE.idToken}=id`)
    createAfterLogoutHook(ctx)({ collection: {} as never, context: {}, req })
    const cookies = req.responseHeaders?.getSetCookie() ?? []
    expect(cookies).toHaveLength(2)
    expect(cookies.some((c) => c.startsWith(`${COOKIE.refresh}=; Path=/; Max-Age=0`))).toBe(true)
    expect(cookies.some((c) => c.startsWith(`${COOKIE.idToken}=; Path=/; Max-Age=0`))).toBe(true)
  })
})
