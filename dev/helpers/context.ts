import type { JWTVerifyGetKey } from 'jose'

import type { PluginContext } from '../../src/types.js'

import { cookieNames } from '../../src/cookies.js'
import { createKeycloak } from '../../src/keycloak.js'
import { KC } from './keycloak.js'

export const COOKIE = cookieNames('payload')

/** A PluginContext wired to the fake IdP, carrying the defaults the plugin itself applies. */
export const testContext = (
  getKey: JWTVerifyGetKey,
  overrides: Partial<PluginContext> = {},
): PluginContext => ({
  adminRoute: '/admin',
  allowedOrigins: ['http://localhost:3000'],
  apiRoute: '/api',
  basePath: '',
  cookies: COOKIE,
  cookieSettings: { sameSite: 'Lax', secure: false },
  internalHosts: [],
  keycloak: createKeycloak({ ...KC, getKey }),
  loginRoute: '/login',
  messages: { signIn: '', signInFailed: '', signOut: '' },
  permissionsClaim: 'permissions',
  serverURL: 'http://localhost:3000',
  usersSlug: 'users',
  ...overrides,
})
