import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { lexicalEditor } from '@payloadcms/richtext-lexical'
import path from 'path'
import { buildConfig } from 'payload'
import { authenticated, can, keycloakAuth, withKeycloakAccess } from 'payload-keycloak'
import sharp from 'sharp'
import { fileURLToPath } from 'url'

import { testEmailAdapter } from './helpers/testEmailAdapter.js'

const filename = fileURLToPath(import.meta.url)
const dirname = path.dirname(filename)

if (!process.env.ROOT_DIR) {
  process.env.ROOT_DIR = dirname
}

/** Rules applied to every collection but `users`, which keeps the ones it declares itself. */
const rules = { read: authenticated, write: can('posts.edit') }

export default buildConfig({
  admin: {
    importMap: {
      baseDir: path.resolve(dirname),
    },
    user: 'users',
  },
  collections: withKeycloakAccess(
    [
      {
        slug: 'users',
        access: {
          admin: ({ req }) => Boolean(req.user),
          create: () => false,
          delete: () => false,
          read: authenticated,
          update: () => false,
        },
        // Rows are created by the keycloak strategy on first sign-in; the plugin adds the fields.
        auth: true,
        fields: [],
      },
      {
        slug: 'posts',
        fields: [{ name: 'title', type: 'text' }],
      },
      {
        slug: 'media',
        fields: [],
        upload: {
          staticDir: path.resolve(dirname, 'media'),
        },
      },
    ],
    rules,
    ['users'],
  ),
  db: mongooseAdapter({
    ensureIndexes: true,
    url: process.env.DATABASE_URL || '',
  }),
  editor: lexicalEditor(),
  email: testEmailAdapter,
  plugins: [
    keycloakAuth({
      basePath: process.env.BASE_PATH || '',
      clientId: process.env.KEYCLOAK_CLIENT_ID || 'payload',
      permissionsClaim: process.env.KEYCLOAK_PERMISSIONS_CLAIM || 'permissions',
      realm: process.env.KEYCLOAK_REALM || 'payload',
      serverURL: process.env.SERVER_URL || 'http://localhost:3000',
      url: process.env.KEYCLOAK_URL || 'http://localhost:8080',
    }),
  ],
  secret: process.env.PAYLOAD_SECRET || 'test-secret_key',
  sharp,
  typescript: {
    outputFile: path.resolve(dirname, 'payload-types.ts'),
  },
})
