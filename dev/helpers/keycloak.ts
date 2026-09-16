import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose'
import { vi } from 'vitest'

export const KC = { clientId: 'payload-test', realm: 'test', url: 'http://keycloak.test/auth' }
export const ISSUER = `${KC.url}/realms/${KC.realm}`
export const OIDC = `${ISSUER}/protocol/openid-connect`

type UserInfoResolver = (token: string) => null | Record<string, unknown>
type SignOptions = { expiresIn?: number; issuer?: string }

export type FakeKeycloak = Awaited<ReturnType<typeof fakeKeycloak>>

/**
 * An RSA key plus a stub of the global fetch for /userinfo and /token. JWKS is served in-process
 * through `getKey`: jose resolves remote keys with http.get rather than fetch, so a fetch stub
 * would not intercept it. `fake.userInfo` and `fake.tokens` can be reassigned between cases.
 */
export async function fakeKeycloak(
  options: { tokens?: Record<string, unknown>; userInfo?: UserInfoResolver } = {},
) {
  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const jwk = { ...(await exportJWK(publicKey)), alg: 'RS256', kid: 'test', use: 'sig' }
  const calls: { body?: string; url: string }[] = []

  async function sign(
    claims: Record<string, unknown>,
    { expiresIn = 300, issuer = ISSUER }: SignOptions = {},
  ): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .setIssuer(issuer)
      .setIssuedAt()
      .setSubject((claims.sub as string | undefined) ?? 'sub-1')
      .setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn)
      .sign(privateKey)
  }

  // Mutable state: cases reassign fake.userInfo / fake.tokens and fetchMock reads them per call.
  const state: { tokens: null | Record<string, unknown>; userInfo: UserInfoResolver } = {
    tokens: options.tokens ?? null,
    userInfo: options.userInfo ?? (() => null),
  }

  const fetchMock = vi.fn(
    async (input: Request | string | URL, init?: RequestInit): Promise<Response> => {
      const url = input instanceof Request ? input.url : input.toString()
      const body =
        init?.body instanceof URLSearchParams
          ? init.body.toString()
          : (init?.body as string | undefined)
      calls.push({ body, url })
      if (url === `${OIDC}/userinfo`) {
        const token = new Headers(init?.headers).get('authorization')?.slice('Bearer '.length) ?? ''
        const info = state.userInfo(token)
        return info ? Response.json(info) : new Response('unauthorized', { status: 401 })
      }
      if (url === `${OIDC}/token`) {
        const tokens = state.tokens ?? {
          access_token: await sign({ sub: 'sub-1' }),
          expires_in: 300,
          id_token: 'id-1',
          refresh_expires_in: 1800,
          refresh_token: await sign({ sub: 'sub-1', typ: 'Refresh' }, { expiresIn: 1800 }),
        }
        return Response.json(tokens)
      }
      return new Response('not found', { status: 404 })
    },
  )
  vi.stubGlobal('fetch', fetchMock)

  return Object.assign(state, {
    calls,
    fetchMock,
    getKey: createLocalJWKSet({ keys: [jwk] }),
    restore: () => vi.unstubAllGlobals(),
    sign,
  })
}
