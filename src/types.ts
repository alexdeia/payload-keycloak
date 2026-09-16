import type { JWTVerifyGetKey } from 'jose'

import type { CookieNames, CookieSettings } from './cookies.js'
import type { Keycloak } from './keycloak.js'

/** Nested boolean permissions, e.g. `{ posts: { edit: true } }`, read from a userinfo claim. */
export type Permissions = Record<string, Record<string, boolean>>

export type KeycloakAuthMessages = {
  signIn: string
  signInFailed: string
  signOut: string
}

export type KeycloakAuthOptions = {
  /** Extra origins allowed to send the session cookie; `serverURL` is always allowed. */
  allowedOrigins?: string[]
  /** Next.js `basePath` this app is mounted under: `''` or `/sub-path`. @default '' */
  basePath?: string
  /** Public client with PKCE (S256); no client secret is involved. */
  clientId: string
  /** @default true */
  enabled?: boolean
  /** Override JWKS resolution; useful in tests. */
  getKey?: JWTVerifyGetKey
  /**
   * `Host` header values of trusted in-network callers that authenticate without a token and
   * always get empty permissions. Only safe when the public ingress rewrites `Host` to the public
   * hostname, so these values cannot be spoofed from outside. Off when empty.
   */
  internalHosts?: string[]
  /** Admin UI texts. */
  messages?: Partial<KeycloakAuthMessages>
  /** Userinfo claim holding nested boolean permissions. @default 'permissions' */
  permissionsClaim?: string
  realm: string
  /** OIDC scope. @default 'openid' */
  scope?: string
  /** Public origin of this app, e.g. `https://app.example.com`. Used for redirect URIs and the cookie CSRF allow-list. */
  serverURL: string
  /** Keycloak base URL without the realm, e.g. `https://sso.example.com` or `https://host/auth`. */
  url: string
  /** Userinfo cache TTL in seconds. @default 300 */
  userInfoTtl?: number
  /** Slug of the auth collection. @default 'users' */
  usersSlug?: string
}

export type PluginContext = {
  adminRoute: string
  allowedOrigins: string[]
  apiRoute: string
  basePath: string
  cookies: CookieNames
  cookieSettings: CookieSettings
  internalHosts: string[]
  keycloak: Keycloak
  loginRoute: string
  messages: KeycloakAuthMessages
  permissionsClaim: string
  serverURL: string
  usersSlug: string
}

export type KeycloakUserDoc = {
  email?: null | string
  id: number | string
  keycloakSub: string
  name?: null | string
}

export type KeycloakUser = {
  _strategy: string
  collection: string
  permissions: Permissions
} & KeycloakUserDoc
