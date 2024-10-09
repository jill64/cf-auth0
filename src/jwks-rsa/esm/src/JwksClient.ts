import JwksError from './errors/JwksError.js'
import SigningKeyNotFoundError from './errors/SigningKeyNotFoundError.js'
import { retrieveSigningKeys } from './utils.js'

export const JwksClient = (jwksUri: string) => {
  const getKeys = async () => {
    console.log(`Fetching keys from '${jwksUri}'`)

    const resp = await fetch(jwksUri)

    if (!resp.ok) {
      const errorMsg =
        (await resp.text()) ?? resp.statusText ?? `Http Error ${resp.status}`

      throw new Error(errorMsg)
    }

    const res = await resp.json()

    console.log('Keys:', res.keys)

    return res.keys
  }

  const getSigningKeys = async () => {
    const keys = await getKeys()

    if (!keys || !keys.length) {
      throw new JwksError('The JWKS endpoint did not contain any keys')
    }

    console.log('Keys2:', keys)

    const signingKeys = await retrieveSigningKeys(keys)

    console.log('Signing Keys:', signingKeys)

    if (!signingKeys.length) {
      throw new JwksError('The JWKS endpoint did not contain any signing keys')
    }

    console.log('Signing Keys:', signingKeys)
    return signingKeys
  }

  const getSigningKey = async (kid: string) => {
    console.log(`Fetching signing key for '${kid}'`)

    const keys = await getSigningKeys()

    console.log('Keys:', keys)

    const kidDefined = kid !== undefined && kid !== null
    if (!kidDefined && keys.length > 1) {
      console.log('No KID specified and JWKS endpoint returned more than 1 key')
      throw new SigningKeyNotFoundError(
        'No KID specified and JWKS endpoint returned more than 1 key'
      )
    }

    const key = keys.find((k) => !kidDefined || k.kid === kid)
    if (key) {
      console.log('Determined Key:', key)

      return key
    } else {
      console.log(`Unable to find a signing key that matches '${kid}'`)
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
