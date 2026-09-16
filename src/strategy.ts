import type { AuthStrategy, Payload } from 'payload'

import type { Claims, UserInfo } from './keycloak.js'
import type { KeycloakUser, KeycloakUserDoc, Permissions, PluginContext } from './types.js'

import { readCookie, sessionCookies } from './cookies.js'

export const STRATEGY_NAME = 'keycloak'
export const INTERNAL_STRATEGY_NAME = 'internal'
/** `keycloakSub` of the shared read-only row used by trusted in-network callers. */
export const INTERNAL_SUB = 'service:internal'

type Extracted = { fromCookie: boolean; token: string }

/** Bearer header wins; the cookie is accepted only from allowed origins, the same CSRF gate Payload applies. */
export function extractToken(
  headers: Headers,
  cookieName: string,
  allowedOrigins: string[],
): Extracted | undefined {
  const authorization = headers.get('authorization')
  if (authorization?.startsWith('Bearer ')) {
    return { fromCookie: false, token: authorization.slice('Bearer '.length) }
  }
  const origin = headers.get('origin')
  if (origin && !allowedOrigins.includes(origin)) {
    return undefined
  }
  const token = readCookie(headers, cookieName)
  return token ? { fromCookie: true, token } : undefined
}

/** Find-or-create the user row by Keycloak `sub`; preferences and document locks reference it by FK. */
export async function upsertUser(
  payload: Payload,
  slug: string,
  claims: Claims,
  info: null | UserInfo,
): Promise<KeycloakUserDoc> {
  // The auth collection is named by config, so it cannot be tied to a generated slug union.
  const collection = slug as never
  const email = (info?.email ?? claims.email)?.toLowerCase() ?? null
  const name =
    info?.name ?? claims.name ?? info?.preferred_username ?? claims.preferred_username ?? null

  const findBySub = async (): Promise<KeycloakUserDoc | undefined> =>
    (
      await payload.find({
        collection,
        depth: 0,
        limit: 1,
        where: { keycloakSub: { equals: claims.sub } },
      })
    ).docs[0] as unknown as KeycloakUserDoc | undefined

  const doc = await findBySub()
  if (!doc) {
    try {
      return (await payload.create({
        collection,
        data: { name, email, keycloakSub: claims.sub } as never,
        depth: 0,
      })) as unknown as KeycloakUserDoc
    } catch (err) {
      // First-login race: a parallel request inserted the row first and the unique `keycloakSub`
      // index rejected ours. Without this the request would fall through to `{ user: null }` — a
      // silent 403.
      const raced = await findBySub()
      if (!raced) {
        throw err
      }
      return raced
    }
  }
  if ((doc.email ?? null) !== email || (doc.name ?? null) !== name) {
    return (await payload.update({
      id: doc.id,
      collection,
      data: { name, email } as never,
      depth: 0,
    })) as unknown as KeycloakUserDoc
  }
  return doc
}

export function createStrategy(ctx: PluginContext): AuthStrategy {
  const { cookies, keycloak, usersSlug } = ctx
  return {
    name: STRATEGY_NAME,
    authenticate: async ({ canSetHeaders, headers, payload }) => {
      const extracted = extractToken(headers, cookies.access, ctx.allowedOrigins)
      if (!extracted) {
        return { user: null }
      }

      let token = extracted.token
      let claims = await keycloak.verify(token).catch(() => null)
      let responseHeaders: Headers | undefined

      // Expired access token in the cookie: refresh silently while the Keycloak session is alive.
      const refreshToken = extracted.fromCookie ? readCookie(headers, cookies.refresh) : undefined
      if (!claims && refreshToken) {
        const tokens = await keycloak.refresh(refreshToken).catch(() => null)
        if (tokens) {
          token = tokens.access_token
          claims = await keycloak.verify(token).catch(() => null)
          if (claims && canSetHeaders) {
            responseHeaders = new Headers()
            for (const cookie of sessionCookies(tokens, cookies, ctx.cookieSettings)) {
              responseHeaders.append('Set-Cookie', cookie)
            }
          }
        }
      }
      if (!claims) {
        return { user: null }
      }

      // Keycloak unreachable or session revoked: authenticated, but without permissions.
      const info = await keycloak.userInfo(token).catch((err: unknown) => {
        payload.logger.warn({
          err,
          msg: '[keycloak-auth] userinfo unavailable, continuing without permissions',
        })
        return null
      })
      const doc = await upsertUser(payload, usersSlug, claims, info)
      const user: KeycloakUser = {
        ...doc,
        _strategy: STRATEGY_NAME,
        collection: usersSlug,
        permissions: (info?.[ctx.permissionsClaim] as Permissions | undefined) ?? {},
      }
      return { responseHeaders, user: user as never }
    },
  }
}

/**
 * Read-only access for trusted in-network callers that send no token. The gate is the `Host`
 * header, so it only holds when the public ingress forwards its own hostname and these values
 * cannot be reached from outside. Permissions are always empty, so writes are still rejected.
 */
export function createInternalStrategy(ctx: PluginContext): AuthStrategy {
  return {
    name: INTERNAL_STRATEGY_NAME,
    authenticate: async ({ headers, payload }) => {
      const host = headers.get('host')
      if (!host || !ctx.internalHosts.includes(host)) {
        return { user: null }
      }
      const doc = await upsertUser(
        payload,
        ctx.usersSlug,
        { name: 'internal', sub: INTERNAL_SUB },
        null,
      )
      const user: KeycloakUser = {
        ...doc,
        _strategy: INTERNAL_STRATEGY_NAME,
        collection: ctx.usersSlug,
        permissions: {},
      }
      return { user: user as never }
    },
  }
}
