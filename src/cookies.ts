import type { TokenSet } from './keycloak.js'

export type CookieNames = {
  access: string
  idToken: string
  login: string
  refresh: string
}

/**
 * Names derive from Payload's `cookiePrefix` so the access token lands in the cookie Payload
 * already owns: `/me` reports its `exp`, `logout` clears it and `refresh-token` rewrites it.
 */
export const cookieNames = (prefix: string): CookieNames => ({
  access: `${prefix}-token`,
  idToken: `${prefix}-id-token`,
  login: `${prefix}-oidc-login`,
  refresh: `${prefix}-refresh`,
})

export const sessionCookieNames = (names: CookieNames): string[] => [
  names.access,
  names.refresh,
  names.idToken,
]

/**
 * The auth collection's `auth.cookies`, shared with Payload so that a cookie written here and the
 * same cookie rewritten by Payload carry identical attributes — otherwise a `domain` or `sameSite`
 * set by the host app produces two cookies of the same name with different scopes.
 */
export type CookieSettings = {
  domain?: string
  sameSite?: 'Lax' | 'None' | 'Strict' | boolean
  secure?: boolean
}

export type CookieOptions = { maxAge: number; path?: string; settings: CookieSettings }

export function readCookie(headers: Headers, name: string): string | undefined {
  for (const part of headers.get('cookie')?.split(';') ?? []) {
    const [key, ...rest] = part.trim().split('=')
    if (key === name) {
      const raw = rest.join('=')
      // The Cookie header is client-controlled: a malformed value must not throw on the request path.
      try {
        return decodeURIComponent(raw)
      } catch {
        return raw
      }
    }
  }
  return undefined
}

export function setCookie(
  name: string,
  value: string,
  { maxAge, path = '/', settings }: CookieOptions,
): string {
  // `SameSite=None` without `Secure` is rejected by browsers; Payload forces the pair the same way.
  const secure = settings.secure || settings.sameSite === 'None'
  let cookie = `${name}=${encodeURIComponent(value)}; Path=${path}`
  if (settings.domain) {
    cookie += `; Domain=${settings.domain}`
  }
  cookie += `; Max-Age=${maxAge}; HttpOnly`
  if (settings.sameSite) {
    cookie += `; SameSite=${settings.sameSite}`
  }
  return secure ? `${cookie}; Secure` : cookie
}

export const clearCookie = (name: string, settings: CookieSettings, path?: string): string =>
  setCookie(name, '', { maxAge: 0, path, settings })

/** Cookie lifetime follows the refresh token; the access token inside carries its own exp. */
export function sessionCookies(
  tokens: TokenSet,
  names: CookieNames,
  settings: CookieSettings,
): string[] {
  const maxAge = tokens.refresh_expires_in || tokens.expires_in
  const cookies = [setCookie(names.access, tokens.access_token, { maxAge, settings })]
  if (tokens.refresh_token) {
    cookies.push(setCookie(names.refresh, tokens.refresh_token, { maxAge, settings }))
  }
  if (tokens.id_token) {
    cookies.push(setCookie(names.idToken, tokens.id_token, { maxAge, settings }))
  }
  return cookies
}

export const clearSessionCookies = (names: CookieNames, settings: CookieSettings): string[] =>
  sessionCookieNames(names).map((name) => clearCookie(name, settings))
