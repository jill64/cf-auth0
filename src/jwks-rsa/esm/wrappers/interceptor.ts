import { JWK } from 'jose'
import { JwksClient } from '../JwksClient.js'
import { retrieveSigningKeys } from '../utils.js'

/**
 * Uses getKeysInterceptor to allow users to retrieve keys from a file,
 * external cache, or provided object before falling back to the jwksUri endpoint
 */
export default function getKeysInterceptor(
  client: JwksClient,
  { getKeysInterceptor }: { getKeysInterceptor: () => Promise<JWK[]> }
) {
  const getSigningKey = client.getSigningKey.bind(client)

  return async (kid: unknown) => {
    const keys = await getKeysInterceptor()

    let signingKeys
    if (keys && keys.length) {
      signingKeys = await retrieveSigningKeys(keys)
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
