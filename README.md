# payload-keycloak

SSO-only authentication for [Payload CMS](https://payloadcms.com) 3 against Keycloak. No local
users, no passwords, no extra auth framework — one dependency (`jose`) on top of the standard OIDC
endpoints.

> [!IMPORTANT]
> 🤖 This package is largely AI-generated.

## What it does

- **Auth strategy `keycloak`** — verifies a Keycloak access token (JWKS + issuer) taken from
  `Authorization: Bearer …` or from the httpOnly session cookie, fetches `/userinfo` (cached per
  token) and attaches its permissions claim to `req.user`. Users are created on first sight by
  `sub`; `keycloakSub`, `email` and `name` are added to your auth collection unless it already
  declares them. A lost first-login create race is retried as a lookup, so parallel first requests
  do not turn into a silent 403.
- **Admin login** via Authorization Code + PKCE (S256) for a public client:
  `GET /api/auth/login` → Keycloak → `GET /api/auth/callback` → cookies → back to `/admin`. The
  `/admin/login` view redirects straight to Keycloak through a `beforeLogin` component.
- **Silent refresh** — an expired access token in the cookie is refreshed with the refresh-token
  cookie. `/api/users/me` reports the refresh token's `exp`, so Payload's inactivity timers follow
  the Keycloak SSO session; `POST /api/users/refresh-token` and `/api/users/logout` are wired up
  too. Bearer requests are never refreshed — the caller owns its own token.
- **Logout** — the logout button goes to `GET /api/auth/logout`, which clears the cookies and hands
  off to the Keycloak end-session endpoint with `id_token_hint`.
- **Access helpers** — `authenticated`, `can('posts.edit')`, `withKeycloakAccess`,
  `withKeycloakGlobalAccess`, `withAuth`, plus `permissionsOf(user)` for ad-hoc checks.

## Install

```bash
pnpm add payload-keycloak
```

## Usage

```ts
import { buildConfig } from 'payload'
import {
  authenticated,
  can,
  keycloakAuth,
  withAuth,
  withKeycloakAccess,
} from 'payload-keycloak'

const rules = { read: authenticated, write: can('posts.edit') }

export default buildConfig({
  admin: { user: 'users' },
  collections: withKeycloakAccess([Users, Posts], rules, ['users']),
  endpoints: [{ path: '/report', method: 'get', handler: withAuth(reportHandler) }],
  plugins: [
    keycloakAuth({
      url: process.env.KEYCLOAK_URL,           // https://sso.example.com
      realm: process.env.KEYCLOAK_REALM,
      clientId: process.env.KEYCLOAK_CLIENT_ID, // public client, PKCE S256
      serverURL: process.env.SERVER_URL,        // https://app.example.com
      basePath: process.env.BASE_PATH,          // '' | '/sub-path'
    }),
  ],
})
```

The auth collection keeps its own `access`; the plugin only sets `auth.disableLocalStrategy`, adds
the fields, the strategy and the `me` / `refresh` / `afterLogout` hooks.

Run `payload generate:importmap` after adding the plugin — the admin login and logout components are
resolved through your app's import map.

### Keycloak client

Public client, Standard flow, PKCE `S256`, with:

- redirect URI `{serverURL}{basePath}/api/auth/callback`
- post-logout redirect URI `{serverURL}{basePath}/admin`

**Revoke Refresh Token must be OFF** — see [Limits](#limits-by-design).

### Permissions

Permissions are read from a userinfo claim as nested booleans:

```json
{ "permissions": { "posts": { "edit": true } } }
```

`can('posts.edit')` passes when that path is exactly `true`. Point `permissionsClaim` at whatever
claim your realm populates; a user whose userinfo cannot be reached stays authenticated with empty
permissions.

## Options

| Option | Default | |
|---|---|---|
| `url`, `realm`, `clientId`, `serverURL` | required | missing one throws at config build |
| `basePath` | `''` | Next.js `basePath` |
| `usersSlug` | `'users'` | auth collection |
| `scope` | `'openid'` | |
| `allowedOrigins` | — | extra origins allowed to send the session cookie; `serverURL` is always allowed |
| `permissionsClaim` | `'permissions'` | userinfo claim holding nested boolean permissions |
| `userInfoTtl` | `300` | seconds |
| `internalHosts` | — | `Host` values of trusted in-network callers that read without a token as a shared user with no permissions; requires the ingress to route by its public host only |
| `messages` | English | admin UI texts |
| `getKey` | remote JWKS | `JWTVerifyGetKey` override for tests |
| `enabled` | `true` | |

Cookie names follow Payload's `cookiePrefix`: `{prefix}-token` (access, the cookie Payload itself
owns), `{prefix}-refresh`, `{prefix}-id-token`, and `{prefix}-oidc-login` during the login redirect.
Their `domain` / `sameSite` / `secure` attributes come from the auth collection's `auth.cookies`, so
the cookies this plugin writes and the ones Payload rewrites carry identical scope. `secure`
defaults to whether `serverURL` is https.

The plugin also forces `auth.removeTokenFromResponses`: the access token is a Keycloak credential
for the whole realm, so it stays in the httpOnly cookie and never reaches the `me` or
`refresh-token` JSON body.

## Timeouts and caching

- `/userinfo` runs on every authenticated request and is aborted after 5 s; the token endpoint
  (login, refresh) after 10 s.
- A successful `/userinfo` is cached per token for `userInfoTtl`, capped by the token's own `exp`.
- A failed `/userinfo` is cached for 15 s, but only a transport failure or a `5xx`. A `401` is never
  cached, so a revoked session loses its permissions on the very next request. It does not lose the
  session itself: verification is offline (JWKS, no introspection), so the access token keeps
  verifying until its own `exp` and the `401` is swallowed exactly like an outage — still
  authenticated, no permissions. Reads survive until the token expires and the refresh then fails.
- Repeated refreshes with the same refresh token share one in-flight request for 60 s, which keeps
  refresh-token rotation from invalidating a token two parallel requests are both spending.

## Limits (by design)

- `aud` is not validated; gate access with permissions instead.
- The userinfo cache (positive and negative) and refresh coalescing live in process memory — fine
  for one replica.
- Keycloak's **Revoke Refresh Token must be OFF**. Admin pages are server-rendered without
  `canSetHeaders`, so a refresh that happens there cannot write the rotated cookies back and the
  browser keeps re-sending the original refresh token; with rotation on, once the 60 s coalescing
  window lapses the next render replays a spent token and bounces the user through Keycloak and
  back — a flicker with lost form state, not a clean auth error. The coalescing window is
  per-process, which is the other thing rotation would break at more than one replica.
- Errors from the token endpoint surface with Keycloak's own HTTP status (`400` on an expired or
  revoked refresh token). Payload returns the error `message` to the client for any status other
  than `500`, so `message` carries the status only; Keycloak's response body is attached to
  `KeycloakError.body` instead, which stays server-side and reaches the log.
- A transport-level failure or timeout against the token endpoint carries no status and surfaces
  as a plain `500`.
- Every `*Url` serverProp the plugin passes to an admin component is **app-relative, without
  `basePath`** — the component prepends it. `redirect()` from `next/navigation` prepends `basePath`
  on its own, so only components rendering a plain anchor add it explicitly. Prepending it in both
  places gives a doubled prefix that is invisible when `basePath` is empty; `dev/plugin.int.spec.ts`
  pins the rule against a non-empty one.

## Development

The `dev/` folder is a Payload app that loads the plugin from `src/`.

```bash
cp dev/.env.example dev/.env
pnpm install
pnpm dev            # http://localhost:3000/admin
pnpm test:int       # vitest, against an in-memory MongoDB and a fake IdP
pnpm test:e2e       # playwright
```

`pnpm generate:importmap` regenerates `dev/app/(payload)/admin/importMap.js` after a component is
added or renamed.

## License

MIT
