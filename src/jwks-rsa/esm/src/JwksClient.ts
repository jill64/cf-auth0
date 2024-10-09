import JwksError from './errors/JwksError.js'
import SigningKeyNotFoundError from './errors/SigningKeyNotFoundError.js'
import { retrieveSigningKeys } from './utils.js'

export const JwksClient = (jwksUri: string) => {
  const getKeys = async () => {
    const resp = await fetch(jwksUri)

    if (!resp.ok) {
      const errorMsg =
        (await resp.text()) ?? resp.statusText ?? `Http Error ${resp.status}`

      throw new Error(errorMsg)
    }

    const res = await resp.json()

    return res.keys
  }

  const getSigningKeys = async () => {
    const keys = await getKeys()

    if (!keys || !keys.length) {
      throw new JwksError('The JWKS endpoint did not contain any keys')
    }

    const signingKeys = await retrieveSigningKeys(keys)

    if (!signingKeys.length) {
      throw new JwksError('The JWKS endpoint did not contain any signing keys')
    }

    return signingKeys
  }

  const getSigningKey = async (kid?: string) => {
    const keys = await getSigningKeys()

    const kidDefined = kid !== undefined && kid !== null
    if (!kidDefined && keys.length > 1) {
      throw new SigningKeyNotFoundError(
        'No KID specified and JWKS endpoint returned more than 1 key'
      )
    }

    const key = keys.find((k) => !kidDefined || k.kid === kid)
    if (key) {
      return key
    } else {
      throw new SigningKeyNotFoundError(
        `Unable to find a signing key that matches '${kid}'`
      )
    }
  }

  return {
    getSigningKey,
    getSigningKeys
  }
}
