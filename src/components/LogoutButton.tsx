import type { ServerProps } from 'payload'

import { LogOutIcon } from '@payloadcms/ui'
import React from 'react'

type Props = { basePath: string; label: string; logoutUrl: string } & ServerProps

/** Same markup as Payload's Logout element, but a plain link: the session ends in Keycloak. */
export function LogoutButton({ basePath, label, logoutUrl }: Props) {
  return (
    <a aria-label={label} className="nav__log-out" href={`${basePath}${logoutUrl}`} title={label}>
      <LogOutIcon />
    </a>
  )
}
