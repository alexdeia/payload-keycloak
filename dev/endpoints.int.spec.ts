import type { Endpoint, PayloadHandler, PayloadRequest } from 'payload'

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { createEndpoints } from '../src/endpoints.js'
import { COOKIE, testContext } from './helpers/context.js'
import { fakeKeycloak, type FakeKeycloak, KC, OIDC } from './helpers/keycloak.js'
import { makeTestReq } from './helpers/payload.js'

const SERVER = 'https://app.test'
const BASE = '/sub-path'

let fake: FakeKeycloak
let handlers: Record<string, PayloadHandler>

const call = (
  path: string,
  query = '',
  headers: Record<string, string> = {},
  on: Record<string, PayloadHandler> = handlers,
) =>
  makeTestReq({
    headers: new Headers(headers),
    url: `${SERVER}${BASE}/api${path}${query}`,
  } as Partial<PayloadRequest>).then((req) => on[path](req) as Promise<Response>)

const cookieValue = (response: Response, name: string) =>
  response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith(`${name}=`))
    ?.split(';')[0]
    .slice(name.length + 1)

const endpointsFor = (basePath: string): Record<string, PayloadHandler> =>
  Object.fromEntries(
    createEndpoints(
      testContext(fake.getKey, {
        allowedOrigins: [SERVER],
        basePath,
        cookieSettings: { sameSite: 'Lax', secure: true },
        serverURL: SERVER,
      }),
    ).map((endpoint: Endpoint) => [endpoint.path, endpoint.handler]),
  )

beforeAll(async () => {
  fake = await fakeKeycloak()
  handlers = endpointsFor(BASE)
})

beforeEach(() => {
  fake.calls.length = 0
  fake.tokens = null
})

afterAll(() => fake.restore())

describe('GET /auth/login', () => {
  it('302 to Keycloak with PKCE, state and the callback redirect_uri; state/verifier/redirect in an httpOnly cookie', async () => {
    const res = await call('/auth/login', '?redirect=%2Fadmin%2Fcollections%2Fposts')
    expect(res.status).toBe(302)

    const location = new URL(res.headers.get('location')!)
    expect(location.origin + location.pathname).toBe(`${OIDC}/auth`)
    expect(location.searchParams.get('client_id')).toBe(KC.clientId)
    expect(location.searchParams.get('redirect_uri')).toBe(`${SERVER}${BASE}/api/auth/callback`)
    expect(location.searchParams.get('code_challenge_method')).toBe('S256')

    const raw = cookieValue(res, COOKIE.login)
    const saved = JSON.parse(decodeURIComponent(raw!))
    expect(saved.state).toBe(location.searchParams.get('state'))
    expect(saved.verifier).toHaveLength(43)
    expect(saved.redirect).toBe('/admin/collections/posts')
    expect(res.headers.getSetCookie()[0]).toContain('HttpOnly; SameSite=Lax; Secure')
  })

  it('an external or protocol-relative redirect falls back to /admin', async () => {
    for (const bad of ['https://evil.example/', '//evil.example', 'admin']) {
      const res = await call('/auth/login', `?redirect=${encodeURIComponent(bad)}`)
      expect(JSON.parse(decodeURIComponent(cookieValue(res, COOKIE.login)!)).redirect).toBe('/admin')
    }
  })
})

describe('GET /auth/callback', () => {
  const loginCookie = (state = 'st-1', redirect = '/admin/x') =>
    `${COOKIE.login}=${encodeURIComponent(JSON.stringify({ redirect, state, verifier: 'ver-1' }))}`

  it('a missing cookie or mismatched state lands on the login view with state_mismatch and clears the cookie', async () => {
    const noCookie = await call('/auth/callback', '?code=c&state=st-1')
    expect(noCookie.headers.get('location')).toBe(
      `${SERVER}${BASE}/admin/login?error=state_mismatch`,
    )

    const mismatch = await call('/auth/callback', '?code=c&state=other', { cookie: loginCookie() })
    expect(mismatch.status).toBe(302)
    expect(mismatch.headers.get('location')).toContain('error=state_mismatch')
    expect(mismatch.headers.getSetCookie().some((c) => c.startsWith(`${COOKIE.login}=; `))).toBe(
      true,
    )
    expect(fake.calls).toHaveLength(0)
  })

  it('an error from Keycloak is passed through', async () => {
    const res = await call('/auth/callback', '?error=access_denied&state=st-1', {
      cookie: loginCookie(),
    })
    expect(res.headers.get('location')).toBe(`${SERVER}${BASE}/admin/login?error=access_denied`)
  })

  it('success: the code is exchanged with the verifier, three session cookies, redirect to the saved path', async () => {
    const access = await fake.sign({ sub: 'sub-1' })
    fake.tokens = {
      access_token: access,
      expires_in: 300,
      id_token: 'id-1',
      refresh_expires_in: 1800,
      refresh_token: 'rt-1',
    }

    const res = await call('/auth/callback', '?code=c-1&state=st-1', {
      cookie: loginCookie('st-1', '/admin/x'),
    })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${SERVER}${BASE}/admin/x`)

    const body = new URLSearchParams(fake.calls.at(-1)?.body)
    expect(body.get('code')).toBe('c-1')
    expect(body.get('code_verifier')).toBe('ver-1')
    expect(body.get('redirect_uri')).toBe(`${SERVER}${BASE}/api/auth/callback`)

    expect(cookieValue(res, COOKIE.access)).toBe(access)
    expect(cookieValue(res, COOKIE.refresh)).toBe('rt-1')
    expect(cookieValue(res, COOKIE.idToken)).toBe('id-1')
    expect(cookieValue(res, COOKIE.login)).toBe('')
  })

  it('a failed code exchange lands on the login view with code_exchange_failed', async () => {
    fake.fetchMock.mockImplementationOnce(() =>
      Promise.resolve(new Response('{"error":"invalid_grant"}', { status: 400 })),
    )
    const res = await call('/auth/callback', '?code=bad&state=st-1', { cookie: loginCookie() })
    expect(res.headers.get('location')).toBe(
      `${SERVER}${BASE}/admin/login?error=code_exchange_failed`,
    )
    expect(res.headers.getSetCookie().some((c) => c.startsWith(`${COOKIE.access}=`))).toBe(false)
  })
})

describe('custom admin login route', () => {
  it('a failure redirects to admin.routes.login, not a hardcoded /login', async () => {
    const custom = Object.fromEntries(
      createEndpoints(
        testContext(fake.getKey, {
          allowedOrigins: [SERVER],
          basePath: BASE,
          cookieSettings: { sameSite: 'Lax', secure: true },
          loginRoute: '/sign-in',
          serverURL: SERVER,
        }),
      ).map((endpoint: Endpoint) => [endpoint.path, endpoint.handler]),
    )
    const res = await call('/auth/callback', '?error=access_denied&state=x', {}, custom)
    expect(res.headers.get('location')).toBe(`${SERVER}${BASE}/admin/sign-in?error=access_denied`)
  })
})

describe('GET /auth/logout', () => {
  it('clears the session cookies and leaves for end_session with id_token_hint', async () => {
    const res = await call('/auth/logout', '', {
      cookie: `${COOKIE.idToken}=id-1; ${COOKIE.access}=a`,
    })
    expect(res.status).toBe(302)

    const location = new URL(res.headers.get('location')!)
    expect(location.origin + location.pathname).toBe(`${OIDC}/logout`)
    expect(location.searchParams.get('id_token_hint')).toBe('id-1')
    expect(location.searchParams.get('post_logout_redirect_uri')).toBe(`${SERVER}${BASE}/admin`)

    const cleared = res.headers.getSetCookie()
    for (const name of [COOKIE.access, COOKIE.refresh, COOKIE.idToken]) {
      expect(cleared.some((c) => c.startsWith(`${name}=; Path=/; Max-Age=0`))).toBe(true)
    }
  })
})

describe('cookie paths', () => {
  const setCookieFor = (response: Response, name: string) =>
    response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`))

  it('the login cookie is scoped to the app prefix, session cookies stay on Path=/', async () => {
    const withBase = await call('/auth/login', '', {}, endpointsFor(BASE))
    expect(setCookieFor(withBase, COOKIE.login)).toContain(`Path=${BASE}/api/auth;`)

    const withoutBase = await call('/auth/login', '', {}, endpointsFor(''))
    expect(setCookieFor(withoutBase, COOKIE.login)).toContain('Path=/api/auth;')

    // Cleared on the same Path, otherwise the browser leaves the cookie in place.
    const cleared = await call('/auth/callback', '?code=c&state=nope', {}, endpointsFor(BASE))
    expect(setCookieFor(cleared, COOKIE.login)).toBe(
      `${COOKIE.login}=; Path=${BASE}/api/auth; Max-Age=0; HttpOnly; SameSite=Lax; Secure`,
    )

    // Payload writes the access cookie itself on refresh-token and logout with a hardcoded Path=/.
    const session = await call('/auth/logout', '', {}, endpointsFor(BASE))
    for (const name of [COOKIE.access, COOKIE.refresh, COOKIE.idToken]) {
      expect(setCookieFor(session, name)).toContain('Path=/;')
    }
  })
})
