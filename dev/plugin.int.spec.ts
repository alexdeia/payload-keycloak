import type { CollectionConfig, Config } from 'payload'

import { isValidElement, type ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import type { KeycloakAuthMessages, KeycloakAuthOptions } from '../src/types.js'

import { LoginRedirect } from '../src/components/LoginRedirect.js'
import { LogoutButton } from '../src/components/LogoutButton.js'
import { keycloakAuth } from '../src/index.js'
import { INTERNAL_STRATEGY_NAME, STRATEGY_NAME } from '../src/strategy.js'

// The @payloadcms/ui barrel pulls in .css, which the ESM loader cannot handle under node.
vi.mock('@payloadcms/ui', () => ({ LogOutIcon: () => null }))

const BASE = '/sub-path'
const API = '/api'

const messages: KeycloakAuthMessages = {
  signIn: 'Sign in with Keycloak',
  signInFailed: 'Sign-in failed',
  signOut: 'Log out',
}

const OPTIONS: KeycloakAuthOptions = {
  clientId: 'payload-test',
  realm: 'test',
  serverURL: 'https://app.test',
  url: 'http://keycloak.test/auth',
}

const users: CollectionConfig = { slug: 'users', auth: true, fields: [] }

const build = (options: Partial<KeycloakAuthOptions> = {}, config: Partial<Config> = {}) =>
  keycloakAuth({ ...OPTIONS, ...options })({
    collections: [users],
    ...config,
  } as Config) as Config

const authOf = (config: Config) => {
  const collection = config.collections!.find((entry) => entry.slug === 'users')!
  return typeof collection.auth === 'object' ? collection.auth : {}
}

/** No renderer needed: the components are plain functions returning elements. */
function findHref(node: ReactNode): string | undefined {
  if (!isValidElement(node)) {
    return undefined
  }
  const props = node.props as { children?: ReactNode; href?: string }
  if (node.type === 'a' && typeof props.href === 'string') {
    return props.href
  }
  const children = Array.isArray(props.children) ? props.children : [props.children]
  for (const child of children) {
    const found = findHref(child as ReactNode)
    if (found !== undefined) {
      return found
    }
  }
  return undefined
}

const loginHref = () =>
  findHref(
    LoginRedirect({
      basePath: BASE,
      loginUrl: `${API}/auth/login`,
      messages,
      searchParams: { error: 'x' },
    } as never),
  )

const logoutHref = () =>
  findHref(
    LogoutButton({
      basePath: BASE,
      label: messages.signOut,
      logoutUrl: `${API}/auth/logout`,
    } as never),
  )

describe('options', () => {
  it('a missing required option throws at config build', () => {
    for (const key of ['url', 'realm', 'clientId', 'serverURL'] as const) {
      expect(() => build({ [key]: '' })).toThrow(`option "${key}" is required`)
    }
  })

  it('a missing auth collection throws', () => {
    expect(() => build({ usersSlug: 'staff' })).toThrow('auth collection "staff" not found')
  })

  it('enabled: false hands the config back untouched', () => {
    const incoming = { collections: [users] } as Config
    expect(keycloakAuth({ ...OPTIONS, enabled: false })(incoming)).toBe(incoming)
  })
})

describe('auth collection', () => {
  it('disables the local strategy, adds the fields, strategy and hooks', () => {
    const config = build()
    const auth = authOf(config)

    expect(auth.disableLocalStrategy).toBe(true)
    expect(auth.strategies?.map((strategy) => strategy.name)).toEqual([STRATEGY_NAME])
    expect(auth.cookies).toMatchObject({ sameSite: 'Lax', secure: true })

    const collection = config.collections!.find((entry) => entry.slug === 'users')!
    expect(collection.fields.map((field) => 'name' in field && field.name)).toEqual([
      'email',
      'keycloakSub',
      'name',
    ])
    expect(collection.hooks?.me).toHaveLength(1)
    expect(collection.hooks?.refresh).toHaveLength(1)
    expect(collection.hooks?.afterLogout).toHaveLength(1)
  })

  it('the internal strategy is only added when internalHosts is set', () => {
    expect(
      authOf(build({ internalHosts: ['app-svc.internal:3000'] })).strategies?.map((s) => s.name),
    ).toEqual([STRATEGY_NAME, INTERNAL_STRATEGY_NAME])
  })

  it('strips the Keycloak token from me / refresh-token responses', () => {
    expect(authOf(build()).removeTokenFromResponses).toBe(true)
  })

  it('cookie settings are shared with Payload, host overrides win', () => {
    const config = build({}, {
      collections: [
        { ...users, auth: { cookies: { domain: '.example.com', sameSite: 'None' as const } } },
      ],
    } as Partial<Config>)
    // The same object the plugin writes its own cookies with, so both writers agree.
    expect(authOf(config).cookies).toEqual({
      domain: '.example.com',
      sameSite: 'None',
      secure: true,
    })
  })

  it('a field the collection already declares is not added twice', () => {
    const config = build({}, {
      collections: [{ ...users, fields: [{ name: 'name', type: 'textarea' }] }],
    } as Partial<Config>)
    const fields = config.collections![0].fields.filter(
      (field) => 'name' in field && field.name === 'name',
    )
    expect(fields).toHaveLength(1)
    expect(fields[0].type).toBe('textarea')
  })
})

describe('endpoints', () => {
  it('adds the three auth routes and keeps the existing ones', () => {
    const existing = { handler: () => new Response(), method: 'get' as const, path: '/health' }
    const config = build({}, { endpoints: [existing] })
    expect(config.endpoints?.map((endpoint) => endpoint.path)).toEqual([
      '/health',
      '/auth/login',
      '/auth/callback',
      '/auth/logout',
    ])
  })
})

/*
 * Plugin invariant: every *Url serverProp is a path without basePath, and the component adds the
 * prefix (next/navigation does it for redirect()). Breaking it is invisible when basePath is
 * empty, since a doubled empty prefix is the same string — so this pins it with a non-empty one.
 */
describe('admin components: basePath in links', () => {
  it('LogoutButton prepends basePath to the href', () => {
    expect(logoutHref()).toBe(`${BASE}${API}/auth/logout`)
  })

  it('LoginRedirect with an error renders markup instead of redirecting and prepends basePath', () => {
    expect(loginHref()).toBe(`${BASE}${API}/auth/login`)
  })

  it('no link gets basePath twice', () => {
    for (const href of [loginHref(), logoutHref()]) {
      expect(href, href).not.toContain(`${BASE}${BASE}`)
    }
  })
})

describe('built config: *Url serverProps carry no basePath', () => {
  const config = build({ basePath: BASE })

  const propsOf = (component: unknown) =>
    (component as { serverProps: Record<string, string> }).serverProps

  it('loginUrl starts with apiRoute and carries no basePath', () => {
    const entries = config.admin!.components!.beforeLogin as unknown as { path: string }[]
    const props = propsOf(entries[0])

    expect(props.loginUrl).toBe(`${API}/auth/login`)
    expect(props.loginUrl.startsWith(BASE)).toBe(false)
    expect(props.basePath).toBe(BASE)
  })

  it('logoutUrl starts with apiRoute and carries no basePath', () => {
    const props = propsOf(config.admin!.components!.logout!.Button)

    expect(props.logoutUrl).toBe(`${API}/auth/logout`)
    expect(props.logoutUrl.startsWith(BASE)).toBe(false)
    expect(props.basePath).toBe(BASE)
  })

  it('both components resolve through the package rsc export', () => {
    const entries = config.admin!.components!.beforeLogin as unknown as {
      exportName: string
      path: string
    }[]
    expect(entries[0]).toMatchObject({ exportName: 'LoginRedirect', path: 'payload-keycloak/rsc' })
    expect(config.admin!.components!.logout!.Button).toMatchObject({
      exportName: 'LogoutButton',
      path: 'payload-keycloak/rsc',
    })
  })
})
