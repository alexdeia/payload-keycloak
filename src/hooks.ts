import type {
  CollectionAfterLogoutHook,
  CollectionMeHook,
  CollectionRefreshHook,
} from 'payload'

import { Forbidden } from 'payload'

import type { PluginContext } from './types.js'

import { clearSessionCookies, readCookie, sessionCookies } from './cookies.js'
import { expiresAt } from './keycloak.js'

const appendCookies = (req: { responseHeaders?: Headers }, cookies: string[]) => {
  req.responseHeaders = req.responseHeaders ?? new Headers()
  for (const cookie of cookies) {
    req.responseHeaders.append('Set-Cookie', cookie)
  }
}

const toSeconds = (ms: number) => Math.floor(ms / 1000)

/** Admin UI session timers follow the Keycloak SSO session (refresh token), not the short-lived access token. */
export const createMeHook =
  (ctx: PluginContext): CollectionMeHook =>
  ({ args, user }) => {
    if (!user) {
      return undefined
    }
    const { headers } = args.req
    const exp =
      expiresAt(readCookie(headers, ctx.cookies.refresh)) ??
      expiresAt(readCookie(headers, ctx.cookies.access))
    return exp ? { exp: toSeconds(exp), user } : undefined
  }

/** `POST {api}/{users}/refresh-token`: rotate Keycloak tokens instead of letting Payload mint its own JWT. */
export const createRefreshHook =
  (ctx: PluginContext): CollectionRefreshHook =>
  async ({ args, user }) => {
    const refreshToken = readCookie(args.req.headers, ctx.cookies.refresh)
    if (!refreshToken) {
      throw new Forbidden(args.req.t)
    }
    const tokens = await ctx.keycloak.refresh(refreshToken)
    // Payload writes the access-token cookie from `refreshedToken`; the rest goes through responseHeaders.
    appendCookies(args.req, sessionCookies(tokens, ctx.cookies, ctx.cookieSettings).slice(1))
    const exp =
      expiresAt(tokens.refresh_token) ??
      expiresAt(tokens.access_token) ??
      Date.now() + tokens.expires_in * 1000
    return { exp: toSeconds(exp), refreshedToken: tokens.access_token, setCookie: true, user }
  }

/** `POST {api}/{users}/logout` (inactivity screen): Payload clears the access cookie, we clear the rest. */
export const createAfterLogoutHook =
  (ctx: PluginContext): CollectionAfterLogoutHook =>
  ({ req }) => {
    appendCookies(req, clearSessionCookies(ctx.cookies, ctx.cookieSettings).slice(1))
  }
