import type { ServerProps } from 'payload'

import { redirect } from 'next/navigation.js'
import React from 'react'

import type { KeycloakAuthMessages } from '../types.js'

type Props = { basePath: string; loginUrl: string; messages: KeycloakAuthMessages } & ServerProps

/** Replaces the password form on the admin login view: go straight to Keycloak, stay only to show an error. */
export function LoginRedirect({ basePath, loginUrl, messages, searchParams }: Props) {
  const error = typeof searchParams?.error === 'string' ? searchParams.error : undefined
  const back = typeof searchParams?.redirect === 'string' ? searchParams.redirect : undefined
  const href = back ? `${loginUrl}?redirect=${encodeURIComponent(back)}` : loginUrl

  if (!error) {
    // next/navigation prepends basePath to this path; the anchor below gets it explicitly.
    redirect(href)
  }

  return (
    <div className="login__form">
      <p>
        {messages.signInFailed}: {error}
      </p>
      <a className="btn btn--style-primary btn--size-large" href={`${basePath}${href}`}>
        {messages.signIn}
      </a>
    </div>
  )
}
