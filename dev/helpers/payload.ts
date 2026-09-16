import config from '@payload-config'
import { type BasePayload, createLocalReq, getPayload, type PayloadRequest } from 'payload'

let instance: BasePayload | null = null

/** One Payload instance per run: getPayload() brings up the schema and that is expensive. */
export async function getTestPayload(): Promise<BasePayload> {
  if (!instance) {
    instance = await getPayload({ config })
  }
  return instance
}

/**
 * A complete PayloadRequest for local calls. `{ payload } as PayloadRequest` is not enough:
 * operations need i18n, t, payloadDataLoader, locale and the URL properties. createLocalReq
 * fills those in while keeping the headers and routeParams passed here.
 */
export async function makeTestReq(
  overrides: Partial<PayloadRequest> = {},
): Promise<PayloadRequest> {
  const payload = await getTestPayload()
  return createLocalReq({ req: overrides }, payload)
}
