import { JwksClient, Options } from '../JwksClient.js'
import { retrieveSigningKeys } from '../utils.js'
import type jose from 'jose'

/**
 * Uses getKeysInterceptor to allow users to retrieve keys from a file,
 * external cache, or provided object before falling back to the jwksUri endpoint
 */
export default function getKeysInterceptor(
  client: JwksClient,
  { getKeysInterceptor }: Options
) {
  const getSigningKey = client.getSigningKey.bind(client)

  if (!getKeysInterceptor) {
    throw new Error('getKeysInterceptor must be provided')
  }

  return async (kid: string) => {
    const keys = await getKeysInterceptor()

    let signingKeys
    if (keys && keys.length) {
      signingKeys = await retrieveSigningKeys(keys as jose.JWK[])
    }

    if (signingKeys && signingKeys.length) {
      const key = signingKeys.find((k) => !kid || k.kid === kid)

      if (key) {
        return key
      }
    }

    return getSigningKey(kid)
  }
}
