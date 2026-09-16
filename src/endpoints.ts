import type { Endpoint, PayloadHandler } from 'payload'

import { randomBytes } from 'node:crypto'

import type { PluginContext } from './types.js'

import { clearCookie, clearSessionCookies, readCookie, sessionCookies, setCookie } from './cookies.js'
import { pkce } from './keycloak.js'

const LOGIN_TTL_SECONDS = 600

type LoginState = { redirect: string; state: string; verifier: string }

const redirectTo = (location: string, cookies: string[] = []): Response => {
  const headers = new Headers({ Location: location })
  for (const cookie of cookies) {
    headers.append('Set-Cookie', cookie)
  }
  return new Response(null, { headers, status: 302 })
}

const parseLoginState = (raw: string | undefined): LoginState | undefined => {
  if (!raw) {
    return undefined
  }
  try {
    return JSON.parse(raw) as LoginState
  } catch {
    return undefined
  }
}

export function createEndpoints(ctx: PluginContext): Endpoint[] {
  const { adminRoute, apiRoute, basePath, cookies, cookieSettings, keycloak, loginRoute, serverURL } =
    ctx
  const absolute = (path: string) => `${serverURL}${basePath}${path}`
  const callbackUri = absolute(`${apiRoute}/auth/callback`)
  // Read only by /auth/callback, never by Payload. The session cookies stay at `/`: Payload writes
  // the access cookie itself on refresh-token and logout with a hardcoded `Path=/`, and two cookies
  // of the same name on different paths would be worse than the wide scope.
  const loginCookiePath = `${basePath}${apiRoute}/auth`

  // In-app paths only: an open redirect here would hand the fresh session to a third party.
  const safeRedirect = (value: null | string) =>
    value && value.startsWith('/') && !value.startsWith('//') ? value : adminRoute

  // LoginRedirect stops auto-redirecting when `error` is present, so a broken IdP cannot loop.
  const loginFailed = (reason: string) =>
    redirectTo(absolute(`${adminRoute}${loginRoute}?error=${encodeURIComponent(reason)}`), [
      clearCookie(cookies.login, cookieSettings, loginCookiePath),
    ])

  const login: PayloadHandler = (req) => {
    const { challenge, verifier } = pkce()
    const state: LoginState = {
      redirect: safeRedirect(req.searchParams.get('redirect')),
      state: randomBytes(16).toString('hex'),
      verifier,
    }
    return redirectTo(
      keycloak.authorizationUrl({
        codeChallenge: challenge,
        redirectUri: callbackUri,
        state: state.state,
      }),
      [
        setCookie(cookies.login, JSON.stringify(state), {
          maxAge: LOGIN_TTL_SECONDS,
          path: loginCookiePath,
          settings: cookieSettings,
        }),
      ],
    )
  }

  const callback: PayloadHandler = async (req) => {
    const error = req.searchParams.get('error')
    if (error) {
      return loginFailed(error)
    }
    const saved = parseLoginState(readCookie(req.headers, cookies.login))
    const code = req.searchParams.get('code')
    const state = req.searchParams.get('state')
    if (!saved || !code || !state || state !== saved.state) {
      return loginFailed('state_mismatch')
    }
    try {
      const tokens = await keycloak.exchangeCode(code, callbackUri, saved.verifier)
      return redirectTo(absolute(saved.redirect), [
        ...sessionCookies(tokens, cookies, cookieSettings),
        clearCookie(cookies.login, cookieSettings, loginCookiePath),
      ])
    } catch (err) {
      req.payload.logger.error({ err, msg: '[keycloak-auth] code exchange failed' })
      return loginFailed('code_exchange_failed')
    }
  }

  const logout: PayloadHandler = (req) =>
    redirectTo(
      keycloak.endSessionUrl({
        idToken: readCookie(req.headers, cookies.idToken),
        postLogoutRedirectUri: absolute(adminRoute),
      }),
      clearSessionCookies(cookies, cookieSettings),
    )

  return [
    { handler: login, method: 'get', path: '/auth/login' },
    { handler: callback, method: 'get', path: '/auth/callback' },
    { handler: logout, method: 'get', path: '/auth/logout' },
  ]
}
