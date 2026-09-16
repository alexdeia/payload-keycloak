import { expect, test } from '@playwright/test'

/*
 * No real Keycloak in CI, so the authorization redirect is asserted on the response rather than by
 * following it in the browser: a navigation would try to reach the IdP for real.
 */
test('the admin panel sends an anonymous visitor to Keycloak with PKCE', async ({ page }) => {
  await page.goto('/admin')
  await page.waitForURL('**/admin/login**')

  const response = await page.request.get('/api/auth/login', { maxRedirects: 0 })
  expect(response.status()).toBe(302)

  const url = new URL(response.headers().location)
  expect(url.pathname).toContain('/protocol/openid-connect/auth')
  expect(url.searchParams.get('response_type')).toBe('code')
  expect(url.searchParams.get('code_challenge_method')).toBe('S256')
  expect(url.searchParams.get('code_challenge')).toBeTruthy()
  expect(url.searchParams.get('redirect_uri')).toContain('/api/auth/callback')
})

test('the login view shows the sign-in link instead of a password form when Keycloak fails', async ({
  page,
}) => {
  await page.goto('/admin/login?error=access_denied')

  await expect(page.locator('#field-password')).toHaveCount(0)
  await expect(page.locator('.login__form a')).toBeVisible()
})
