import {
  createRemoteJWKSet,
  decodeJwt,
  type JWTPayload,
  jwtVerify,
  type JWTVerifyGetKey,
} from 'jose'
import { createHash, randomBytes } from 'node:crypto'

export type KeycloakOptions = {
  clientId: string
  getKey?: JWTVerifyGetKey
  realm: string
  scope?: string
  url: string
  userInfoTtl?: number
}

export type TokenSet = {
  access_token: string
  expires_in: number
  id_token?: string
  refresh_expires_in?: number
  refresh_token?: string
}

export type UserInfo = {
  [claim: string]: unknown
  email?: string
  name?: string
  preferred_username?: string
  sub: string
}

export type Claims = {
  email?: string
  name?: string
  preferred_username?: string
  sub: string
} & JWTPayload

export class KeycloakError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** Response body, kept out of `message`: Payload returns `message` to the client for any status but 500. */
    readonly body?: string,
  ) {
    super(message)
    this.name = 'KeycloakError'
  }
}

/** Window in which repeated refreshes with the same refresh token reuse one round-trip. */
const REFRESH_REUSE_MS = 60_000
const CACHE_SWEEP_SIZE = 1000

/** `/userinfo` sits on every authenticated request: a stalling Keycloak must not hold the request open. */
const USERINFO_TIMEOUT_MS = 5_000
/** The token endpoint runs only on login and refresh, where waiting a bit longer beats failing the flow. */
const TOKEN_TIMEOUT_MS = 10_000
/** How long an unreachable or 5xx `/userinfo` is remembered, so an outage is not re-probed by every request. */
const USERINFO_FAILURE_MS = 15_000

/** Expiry (ms since epoch) of a JWT without verifying it; undefined for anything that is not a JWT. */
export function expiresAt(token: string | undefined): number | undefined {
  if (!token) {
    return undefined
  }
  try {
    const { exp } = decodeJwt(token)
    return exp ? exp * 1000 : undefined
  } catch {
    return undefined
  }
}

export function pkce(): { challenge: string; verifier: string } {
  const verifier = randomBytes(32).toString('base64url')
  return { challenge: createHash('sha256').update(verifier).digest('base64url'), verifier }
}

export function createKeycloak(opts: KeycloakOptions) {
  const issuer = `${opts.url.replace(/\/+$/, '')}/realms/${opts.realm}`
  const oidc = `${issuer}/protocol/openid-connect`
  const getKey = opts.getKey ?? createRemoteJWKSet(new URL(`${oidc}/certs`))
  const scope = opts.scope ?? 'openid'
  const userInfoTtl = (opts.userInfoTtl ?? 300) * 1000

  // In-process caches: sized for a single replica, move to a shared store when scaling out.
  const userInfoCache = new Map<string, { until: number; value: UserInfo }>()
  // Outages only: a 401 stays uncached so that a revoked session drops to empty permissions on the
  // very next request. Verification is offline, so the token itself keeps working until its own `exp`.
  const userInfoFailures = new Map<string, { error: KeycloakError; until: number }>()
  const refreshInflight = new Map<string, { result: Promise<TokenSet>; until: number }>()

  const sweep = (map: Map<string, { until: number }>) => {
    if (map.size < CACHE_SWEEP_SIZE) {
      return
    }
    const now = Date.now()
    for (const [key, entry] of map) {
      if (entry.until <= now) {
        map.delete(key)
      }
    }
  }

  async function verify(token: string): Promise<Claims> {
    const { payload } = await jwtVerify(token, getKey, { issuer })
    if (!payload.sub) {
      throw new KeycloakError('token has no sub', 401)
    }
    return payload as Claims
  }

  const rememberFailure = (key: string, error: KeycloakError): KeycloakError => {
    sweep(userInfoFailures)
    userInfoFailures.set(key, { error, until: Date.now() + USERINFO_FAILURE_MS })
    return error
  }

  async function userInfo(token: string): Promise<UserInfo> {
    const key = createHash('sha256').update(token).digest('hex')
    const hit = userInfoCache.get(key)
    if (hit && hit.until > Date.now()) {
      return hit.value
    }
    const failed = userInfoFailures.get(key)
    if (failed && failed.until > Date.now()) {
      throw failed.error
    }

    let res: Response
    try {
      res = await fetch(`${oidc}/userinfo`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(USERINFO_TIMEOUT_MS),
      })
    } catch (err) {
      throw rememberFailure(key, new KeycloakError(`userinfo unreachable: ${String(err)}`, 503))
    }
    if (!res.ok) {
      const error = new KeycloakError(`userinfo failed: ${res.status}`, res.status)
      throw res.status >= 500 ? rememberFailure(key, error) : error
    }
    const value = (await res.json()) as UserInfo
    sweep(userInfoCache)
    userInfoCache.set(key, {
      until: Math.min(Date.now() + userInfoTtl, expiresAt(token) ?? Infinity),
      value,
    })
    return value
  }

  async function grant(body: Record<string, string>): Promise<TokenSet> {
    const res = await fetch(`${oidc}/token`, {
      body: new URLSearchParams({ client_id: opts.clientId, ...body }),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
    })
    if (!res.ok) {
      throw new KeycloakError(`token endpoint failed: ${res.status}`, res.status, await res.text())
    }
    return (await res.json()) as TokenSet
  }

  function authorizationUrl(args: {
    codeChallenge: string
    redirectUri: string
    state: string
  }): string {
    const params = new URLSearchParams({
      client_id: opts.clientId,
      code_challenge: args.codeChallenge,
      code_challenge_method: 'S256',
      redirect_uri: args.redirectUri,
      response_type: 'code',
      scope,
      state: args.state,
    })
    return `${oidc}/auth?${params}`
  }

  const exchangeCode = (
    code: string,
    redirectUri: string,
    codeVerifier: string,
  ): Promise<TokenSet> =>
    grant({
      code,
      code_verifier: codeVerifier,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
    })

  function refresh(refreshToken: string): Promise<TokenSet> {
    const hit = refreshInflight.get(refreshToken)
    if (hit && hit.until > Date.now()) {
      return hit.result
    }
    sweep(refreshInflight)
    const result = grant({ grant_type: 'refresh_token', refresh_token: refreshToken })
    refreshInflight.set(refreshToken, { result, until: Date.now() + REFRESH_REUSE_MS })
    result.catch(() => refreshInflight.delete(refreshToken))
    return result
  }

  function endSessionUrl(args: { idToken?: string; postLogoutRedirectUri: string }): string {
    const params = new URLSearchParams({
      client_id: opts.clientId,
      post_logout_redirect_uri: args.postLogoutRedirectUri,
    })
    if (args.idToken) {
      params.set('id_token_hint', args.idToken)
    }
    return `${oidc}/logout?${params}`
  }

  return { authorizationUrl, endSessionUrl, exchangeCode, issuer, refresh, userInfo, verify }
}

export type Keycloak = ReturnType<typeof createKeycloak>
