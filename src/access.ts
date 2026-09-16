import type { Access, CollectionConfig, GlobalConfig, PayloadHandler } from 'payload'

import { headersWithCors } from 'payload'

import type { Permissions } from './types.js'

type AccessMap = Record<string, Access | undefined>

export type AccessRules = { read: Access; write: Access }

export const permissionsOf = (user: unknown): Permissions =>
  (user as { permissions?: Permissions } | null | undefined)?.permissions ?? {}

export const authenticated: Access = ({ req }) => Boolean(req.user)

/** `can('posts.edit')` passes when the permissions claim carries `posts.edit === true`. */
export const can = (permission: string): Access => {
  const [subject, action] = permission.split('.')
  return ({ req }) => Boolean(req.user) && permissionsOf(req.user)[subject]?.[action] === true
}

/** Both must pass; two `Where` results are intersected rather than one being dropped. */
const both =
  (existing: Access | undefined, rule: Access): Access =>
  async (args) => {
    const left = existing ? await existing(args) : true
    if (left === false) {
      return false
    }
    const right = await rule(args)
    if (right === false) {
      return false
    }
    if (left === true) {
      return right
    }
    if (right === true) {
      return left
    }
    return { and: [left, right] }
  }

function compose(
  access: AccessMap,
  rules: AccessRules,
  readOps: string[],
  writeOps: string[],
): AccessMap {
  const next: AccessMap = { ...access }
  for (const op of readOps) {
    next[op] = both(access[op], rules.read)
  }
  for (const op of writeOps) {
    next[op] = both(access[op], rules.write)
  }
  return next
}

/** Adds `rules` on top of whatever each collection already declares. `skip` leaves a collection untouched. */
export function withKeycloakAccess(
  collections: CollectionConfig[],
  rules: AccessRules,
  skip: string[] = [],
): CollectionConfig[] {
  return collections.map((collection) =>
    skip.includes(collection.slug)
      ? collection
      : {
          ...collection,
          access: compose(
            (collection.access ?? {}) as AccessMap,
            rules,
            ['read', 'readVersions'],
            ['create', 'update', 'delete'],
          ) as CollectionConfig['access'],
        },
  )
}

export function withKeycloakGlobalAccess(
  globals: GlobalConfig[],
  rules: AccessRules,
): GlobalConfig[] {
  return globals.map((global) => ({
    ...global,
    access: compose(
      (global.access ?? {}) as AccessMap,
      rules,
      ['read', 'readVersions'],
      ['update'],
    ) as GlobalConfig['access'],
  }))
}

/** Guard for custom root endpoints: 401 without a user, 403 when the rule fails. */
export const withAuth =
  (handler: PayloadHandler, rule: Access = authenticated): PayloadHandler =>
  async (req) => {
    if (await rule({ req })) {
      return handler(req)
    }
    const headers = headersWithCors({ headers: new Headers(), req })
    return req.user
      ? Response.json({ error: 'Forbidden' }, { headers, status: 403 })
      : Response.json({ error: 'Unauthorized' }, { headers, status: 401 })
  }
