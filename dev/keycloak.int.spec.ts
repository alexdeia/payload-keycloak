import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { clearCookie, cookieNames, readCookie, sessionCookies, setCookie } from '../src/cookies.js'
import { createKeycloak, expiresAt, KeycloakError, pkce } from '../src/keycloak.js'
import { fakeKeycloak, type FakeKeycloak, ISSUER, KC, OIDC } from './helpers/keycloak.js'

const COOKIE = cookieNames('payload')

let fake: FakeKeycloak

beforeAll(async () => {
  fake = await fakeKeycloak()
})

afterAll(() => fake.restore())

beforeEach(() => {
  fake.calls.length = 0
  fake.userInfo = () => null
  fake.tokens = null
})

const keycloak = () => createKeycloak({ ...KC, getKey: fake.getKey, userInfoTtl: 300 })

describe('createKeycloak.verify', () => {
  it('accepts a token from its own issuer and returns the claims', async () => {
    const token = await fake.sign({ email: 'a@b.c', sub: 'sub-1' })
    const claims = await keycloak().verify(token)
    expect(claims.sub).toBe('sub-1')
    expect(claims.email).toBe('a@b.c')
  })

  it('rejects a foreign issuer, an expired token and garbage', async () => {
    await expect(
      keycloak().verify(await fake.sign({ sub: 'x' }, { issuer: `${KC.url}/realms/other` })),
    ).rejects.toThrow()
    await expect(
      keycloak().verify(await fake.sign({ sub: 'x' }, { expiresIn: -60 })),
    ).rejects.toThrow()
    await expect(keycloak().verify('not.a.jwt')).rejects.toThrow()
  })

  it('builds the issuer from url and realm, trailing slash included', () => {
    expect(keycloak().issuer).toBe(ISSUER)
    expect(createKeycloak({ ...KC, getKey: fake.getKey, url: `${KC.url}/` }).issuer).toBe(ISSUER)
  })
})

describe('createKeycloak.userInfo', () => {
  it('caches the response per token: two calls, one fetch', async () => {
    fake.userInfo = () => ({ permissions: { posts: { edit: true } }, sub: 'sub-1' })
    const kc = keycloak()
    const token = await fake.sign({ sub: 'sub-1' })
    const first = await kc.userInfo(token)
    const second = await kc.userInfo(token)
    expect(first.permissions).toEqual({ posts: { edit: true } })
    expect(second).toEqual(first)
    expect(fake.calls.filter((call) => call.url === `${OIDC}/userinfo`)).toHaveLength(1)
  })

  it('never caches a 401 and throws a KeycloakError carrying the status', async () => {
    const kc = keycloak()
    const token = await fake.sign({ sub: 'sub-2' })
    await expect(kc.userInfo(token)).rejects.toBeInstanceOf(KeycloakError)
    await expect(kc.userInfo(token)).rejects.toMatchObject({ status: 401 })
    expect(fake.calls.filter((call) => call.url === `${OIDC}/userinfo`)).toHaveLength(2)
  })

  it('aborts a stalling /userinfo instead of holding the request open', async () => {
    // Keycloak accepts the connection and goes quiet: without a signal this would sit there
    // until undici's own 300 s timeout.
    fake.fetchMock.mockImplementationOnce(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          expect(init?.signal).toBeInstanceOf(AbortSignal)
          init?.signal?.addEventListener('abort', () =>
            reject(new Error(String(init.signal?.reason))),
          )
        }),
    )
    await expect(keycloak().userInfo(await fake.sign({ sub: 'sub-hang' }))).rejects.toMatchObject({
      status: 503,
    })
  }, 10_000)

  it('caches a transport failure and a 5xx briefly, a 401 still never', async () => {
    const kc = keycloak()

    // The same error object on the second call means it came from the negative cache, no network.
    fake.fetchMock.mockImplementationOnce(() => Promise.reject(new TypeError('fetch failed')))
    const offline = await fake.sign({ sub: 'sub-offline' })
    const firstOffline = await kc.userInfo(offline).catch((err: unknown) => err)
    expect(firstOffline).toBeInstanceOf(KeycloakError)
    expect(firstOffline).toMatchObject({ status: 503 })
    expect(await kc.userInfo(offline).catch((err: unknown) => err)).toBe(firstOffline)

    fake.fetchMock.mockImplementationOnce(() =>
      Promise.resolve(new Response('boom', { status: 503 })),
    )
    const broken = await fake.sign({ sub: 'sub-5xx' })
    const firstBroken = await kc.userInfo(broken).catch((err: unknown) => err)
    expect(firstBroken).toMatchObject({ status: 503 })
    expect(await kc.userInfo(broken).catch((err: unknown) => err)).toBe(firstBroken)

    // A revoked session has to lose its permissions on the very next request.
    const revoked = await fake.sign({ sub: 'sub-401' })
    const firstRevoked = await kc.userInfo(revoked).catch((err: unknown) => err)
    const secondRevoked = await kc.userInfo(revoked).catch((err: unknown) => err)
    expect(firstRevoked).toMatchObject({ status: 401 })
    expect(secondRevoked).toMatchObject({ status: 401 })
    expect(secondRevoked).not.toBe(firstRevoked)
    expect(fake.calls.filter((call) => call.url === `${OIDC}/userinfo`)).toHaveLength(2)
  })
})

describe('createKeycloak: code flow', () => {
  it('authorizationUrl carries PKCE S256, state and redirect_uri', () => {
    const url = new URL(
      keycloak().authorizationUrl({
        codeChallenge: 'ch',
        redirectUri: 'http://app/cb',
        state: 'st',
      }),
    )
    expect(url.origin + url.pathname).toBe(`${OIDC}/auth`)
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: KC.clientId,
      code_challenge: 'ch',
      code_challenge_method: 'S256',
      redirect_uri: 'http://app/cb',
      response_type: 'code',
      scope: 'openid',
      state: 'st',
    })
  })

  it('exchangeCode posts authorization_code with the verifier and no client_secret', async () => {
    const tokens = await keycloak().exchangeCode('code-1', 'http://app/cb', 'ver-1')
    expect(tokens.access_token).toBeTruthy()
    const body = new URLSearchParams(fake.calls.at(-1)?.body)
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code')).toBe('code-1')
    expect(body.get('code_verifier')).toBe('ver-1')
    expect(body.get('redirect_uri')).toBe('http://app/cb')
    expect(body.get('client_id')).toBe(KC.clientId)
    expect(body.has('client_secret')).toBe(false)
  })

  it('refresh coalesces parallel and repeated calls with the same refresh token', async () => {
    const kc = keycloak()
    const [a, b] = await Promise.all([kc.refresh('rt-1'), kc.refresh('rt-1')])
    const c = await kc.refresh('rt-1')
    expect(a).toBe(b)
    expect(c).toBe(a)
    expect(fake.calls.filter((call) => call.url === `${OIDC}/token`)).toHaveLength(1)
  })

  it('a different refresh token is its own request, and a failure is not cached', async () => {
    const kc = keycloak()
    await kc.refresh('rt-a')
    await kc.refresh('rt-b')
    expect(fake.calls.filter((call) => call.url === `${OIDC}/token`)).toHaveLength(2)

    fake.fetchMock.mockImplementationOnce(() =>
      Promise.resolve(new Response('{"error":"invalid_grant"}', { status: 400 })),
    )
    await expect(kc.refresh('rt-c')).rejects.toBeInstanceOf(KeycloakError)
    await expect(kc.refresh('rt-c')).resolves.toHaveProperty('access_token')
  })

  /*
   * Payload treats a token-endpoint error as public on any status but 500 and puts its `message`
   * in the response body. So Keycloak's own body must not reach `message` — only the status does;
   * the body lives on a separate field that stays server-side and reaches the log.
   */
  it('keeps the token endpoint response body out of message but on the error', async () => {
    fake.fetchMock.mockImplementationOnce(() =>
      Promise.resolve(
        new Response('{"error":"invalid_grant","error_description":"MARKER-Do-Not-Leak"}', {
          status: 400,
        }),
      ),
    )
    const err = (await keycloak()
      .refresh('rt-leak')
      .catch((caught: unknown) => caught)) as KeycloakError

    expect(err).toBeInstanceOf(KeycloakError)
    expect(err.message).toBe('token endpoint failed: 400')
    expect(err.message).not.toContain('MARKER-Do-Not-Leak')
    expect(err.status).toBe(400)
    expect(err.body).toContain('MARKER-Do-Not-Leak')
  })

  it('endSessionUrl carries client_id, post_logout_redirect_uri and id_token_hint', () => {
    const url = new URL(
      keycloak().endSessionUrl({ idToken: 'id-1', postLogoutRedirectUri: 'http://app/admin' }),
    )
    expect(url.origin + url.pathname).toBe(`${OIDC}/logout`)
    expect(url.searchParams.get('client_id')).toBe(KC.clientId)
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('http://app/admin')
    expect(url.searchParams.get('id_token_hint')).toBe('id-1')
    expect(
      new URL(keycloak().endSessionUrl({ postLogoutRedirectUri: 'x' })).searchParams.has(
        'id_token_hint',
      ),
    ).toBe(false)
  })
})

describe('pkce / expiresAt', () => {
  it('challenge = base64url(sha256(verifier))', async () => {
    const { challenge, verifier } = pkce()
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
    expect(challenge).toBe(Buffer.from(digest).toString('base64url'))
    expect(verifier.length).toBeGreaterThanOrEqual(43)
  })

  it('expiresAt reads exp without verifying the signature, undefined for garbage', async () => {
    const token = await fake.sign({ sub: 'x' }, { expiresIn: 100 })
    const exp = expiresAt(token)
    expect(exp).toBeGreaterThan(Date.now())
    expect(exp).toBeLessThanOrEqual(Date.now() + 101_000)
    expect(expiresAt('garbage')).toBeUndefined()
    expect(expiresAt(undefined)).toBeUndefined()
  })
})

describe('cookies', () => {
  it('names derive from the Payload cookie prefix', () => {
    expect(cookieNames('payload')).toEqual({
      access: 'payload-token',
      idToken: 'payload-id-token',
      login: 'payload-oidc-login',
      refresh: 'payload-refresh',
    })
    expect(cookieNames('acme').access).toBe('acme-token')
  })

  it('readCookie picks its value out of the header and decodes it', () => {
    const headers = new Headers({ cookie: 'a=1; payload-token=x%3Dy; b=2' })
    expect(readCookie(headers, COOKIE.access)).toBe('x=y')
    expect(readCookie(headers, 'missing')).toBeUndefined()
    expect(readCookie(new Headers(), COOKIE.access)).toBeUndefined()
  })

  it('readCookie survives broken percent-encoding and returns the raw value', () => {
    expect(readCookie(new Headers({ cookie: 'a=1; payload-token=100%; b=2' }), COOKIE.access)).toBe(
      '100%',
    )
    expect(readCookie(new Headers({ cookie: 'payload-token=%E0%A4%A' }), COOKIE.access)).toBe(
      '%E0%A4%A',
    )
    expect(readCookie(new Headers({ cookie: 'payload-token=%C3%A9' }), COOKIE.access)).toBe('é')
  })

  it('setCookie/clearCookie: httpOnly, Lax, Secure only when secure', () => {
    expect(setCookie('n', 'v', { maxAge: 10, settings: { sameSite: 'Lax', secure: true } })).toBe(
      'n=v; Path=/; Max-Age=10; HttpOnly; SameSite=Lax; Secure',
    )
    expect(setCookie('n', 'v', { maxAge: 10, settings: { sameSite: 'Lax', secure: false } })).toBe(
      'n=v; Path=/; Max-Age=10; HttpOnly; SameSite=Lax',
    )
    expect(clearCookie('n', { sameSite: 'Lax', secure: false })).toBe(
      'n=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax',
    )
  })

  it('setCookie carries the auth collection settings: domain, sameSite, implied Secure', () => {
    expect(
      setCookie('n', 'v', {
        maxAge: 10,
        settings: { domain: '.example.com', sameSite: 'Strict', secure: true },
      }),
    ).toBe('n=v; Path=/; Domain=.example.com; Max-Age=10; HttpOnly; SameSite=Strict; Secure')
    // SameSite=None is rejected by browsers without Secure, so it implies it.
    expect(setCookie('n', 'v', { maxAge: 10, settings: { sameSite: 'None', secure: false } })).toBe(
      'n=v; Path=/; Max-Age=10; HttpOnly; SameSite=None; Secure',
    )
    expect(setCookie('n', 'v', { maxAge: 10, settings: {} })).toBe(
      'n=v; Path=/; Max-Age=10; HttpOnly',
    )
  })

  it('sessionCookies: lifetime from refresh_expires_in, refresh/id only when present', () => {
    const full = sessionCookies(
      {
        access_token: 'a',
        expires_in: 300,
        id_token: 'i',
        refresh_expires_in: 1800,
        refresh_token: 'r',
      },
      COOKIE,
      { sameSite: 'Lax', secure: false },
    )
    expect(full).toHaveLength(3)
    expect(full[0]).toContain(`${COOKIE.access}=a; Path=/; Max-Age=1800`)
    expect(full[1]).toContain(`${COOKIE.refresh}=r; Path=/; Max-Age=1800`)
    expect(full[2]).toContain(`${COOKIE.idToken}=i;`)

    const settings = { sameSite: 'Lax' as const, secure: false }
    const bare = sessionCookies({ access_token: 'a', expires_in: 300 }, COOKIE, settings)
    expect(bare).toEqual([setCookie(COOKIE.access, 'a', { maxAge: 300, settings })])
  })
})
