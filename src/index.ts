import type { CollectionConfig, Config, Field, Plugin } from 'payload'

import type { KeycloakAuthMessages, KeycloakAuthOptions, PluginContext } from './types.js'

import { cookieNames } from './cookies.js'
import { createEndpoints } from './endpoints.js'
import { createAfterLogoutHook, createMeHook, createRefreshHook } from './hooks.js'
import { createKeycloak } from './keycloak.js'
import { createInternalStrategy, createStrategy } from './strategy.js'

export {
  authenticated,
  can,
  permissionsOf,
  withAuth,
  withKeycloakAccess,
  withKeycloakGlobalAccess,
} from './access.js'
export type { AccessRules } from './access.js'
export { KeycloakError } from './keycloak.js'
export {
  INTERNAL_STRATEGY_NAME,
  INTERNAL_SUB,
  STRATEGY_NAME,
} from './strategy.js'
export type {
  KeycloakAuthMessages,
  KeycloakAuthOptions,
  KeycloakUser,
  Permissions,
} from './types.js'

const DEFAULT_MESSAGES: KeycloakAuthMessages = {
  signIn: 'Sign in with Keycloak',
  signInFailed: 'Sign-in failed',
  signOut: 'Log out',
}

/** Lifetime Payload gives the access-token cookie on refresh; the tokens inside expire on their own. */
const COOKIE_LIFETIME_SECONDS = 10 * 60 * 60

/** Resolved through the host app's import map, so it must match this package's name. */
const RSC = 'payload-keycloak/rsc'

const USER_FIELDS: Field[] = [
  { name: 'email', type: 'email', admin: { readOnly: true } },
  {
    name: 'keycloakSub',
    type: 'text',
    admin: { readOnly: true },
    index: true,
    required: true,
    unique: true,
  },
  { name: 'name', type: 'text', admin: { readOnly: true } },
]

export const keycloakAuth =
  (options: KeycloakAuthOptions): Plugin =>
  (config: Config): Config => {
    if (options.enabled === false) {
      return config
    }
    for (const key of ['url', 'realm', 'clientId', 'serverURL'] as const) {
      if (!options[key]) {
        throw new Error(`[keycloak-auth] option "${key}" is required`)
      }
    }

    const usersSlug = options.usersSlug ?? 'users'
    const users = config.collections?.find((collection) => collection.slug === usersSlug)
    if (!users) {
      throw new Error(`[keycloak-auth] auth collection "${usersSlug}" not found`)
    }

    const declaredAuth = typeof users.auth === 'object' ? users.auth : {}
    const ctx: PluginContext = {
      adminRoute: config.routes?.admin ?? '/admin',
      allowedOrigins: [options.serverURL, ...(options.allowedOrigins ?? [])],
      apiRoute: config.routes?.api ?? '/api',
      basePath: options.basePath ?? '',
      cookies: cookieNames(config.cookiePrefix ?? 'payload'),
      // One settings object for both writers: the plugin writes these cookies on the OIDC
      // callback, Payload rewrites the access one on refresh and logout.
      cookieSettings: {
        sameSite: 'Lax',
        secure: options.serverURL.startsWith('https://'),
        ...declaredAuth.cookies,
      },
      internalHosts: options.internalHosts ?? [],
      keycloak: createKeycloak(options),
      loginRoute: config.admin?.routes?.login ?? '/login',
      messages: { ...DEFAULT_MESSAGES, ...options.messages },
      permissionsClaim: options.permissionsClaim ?? 'permissions',
      serverURL: options.serverURL,
      usersSlug,
    }

    return {
      ...config,
      // Every *Url serverProp is app-relative: components rendering an anchor prepend basePath themselves.
      admin: {
        ...config.admin,
        components: {
          ...config.admin?.components,
          beforeLogin: [
            ...(config.admin?.components?.beforeLogin ?? []),
            {
              exportName: 'LoginRedirect',
              path: RSC,
              serverProps: {
                basePath: ctx.basePath,
                loginUrl: `${ctx.apiRoute}/auth/login`,
                messages: ctx.messages,
              },
            },
          ],
          logout: {
            Button: {
              exportName: 'LogoutButton',
              path: RSC,
              serverProps: {
                basePath: ctx.basePath,
                label: ctx.messages.signOut,
                logoutUrl: `${ctx.apiRoute}/auth/logout`,
              },
            },
          },
        },
      },
      collections: config.collections!.map((collection) =>
        collection === users ? withKeycloakUsers(collection, ctx) : collection,
      ),
      endpoints: [...(config.endpoints ?? []), ...createEndpoints(ctx)],
    }
  }

/**
 * Names already taken in the collection's own field namespace. A named field owns its sub-fields,
 * so only presentational containers — rows, collapsibles, unnamed tabs — are walked into.
 */
function declaredNames(fields: Field[], into: Set<string> = new Set()): Set<string> {
  for (const field of fields) {
    if ('name' in field && field.name) {
      into.add(field.name)
    } else if ('fields' in field && Array.isArray(field.fields)) {
      declaredNames(field.fields, into)
    } else if ('tabs' in field) {
      for (const tab of field.tabs) {
        if (!('name' in tab)) {
          declaredNames(tab.fields, into)
        }
      }
    }
  }
  return into
}

function withKeycloakUsers(collection: CollectionConfig, ctx: PluginContext): CollectionConfig {
  const auth = typeof collection.auth === 'object' ? collection.auth : {}
  const declared = declaredNames(collection.fields)
  return {
    ...collection,
    auth: {
      ...auth,
      cookies: ctx.cookieSettings,
      disableLocalStrategy: true,
      // The access token is a Keycloak credential, not a Payload-issued JWT: it belongs in the
      // httpOnly cookie only, never in the `me` / `refresh-token` JSON body.
      removeTokenFromResponses: true,
      strategies: [
        ...(auth.strategies ?? []),
        createStrategy(ctx),
        ...(ctx.internalHosts.length ? [createInternalStrategy(ctx)] : []),
      ],
      tokenExpiration: auth.tokenExpiration ?? COOKIE_LIFETIME_SECONDS,
    },
    fields: [
      ...USER_FIELDS.filter((field) => 'name' in field && !declared.has(field.name)),
      ...collection.fields,
    ],
    hooks: {
      ...collection.hooks,
      afterLogout: [...(collection.hooks?.afterLogout ?? []), createAfterLogoutHook(ctx)],
      me: [...(collection.hooks?.me ?? []), createMeHook(ctx)],
      refresh: [...(collection.hooks?.refresh ?? []), createRefreshHook(ctx)],
    },
  }
}
