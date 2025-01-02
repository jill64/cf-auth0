import type { JWK } from 'jws'
import { retrieveSigningKeys } from './utils'
import { cacheSigningKey, callbackSupport, request } from './wrappers'

class JwksClient {
  options

  constructor(options: {
    jwksUri: string
    rateLimit?: boolean
    cache?: boolean
    timeout?: number
    cacheMaxEntries?: number
    cacheMaxAge?: number
  }) {
    this.options = {
      rateLimit: false,
      cache: true,
      timeout: 30000,
      ...options
    }

    if (this.options.cache) {
      // @ts-expect-error TODO: fix this
      this.getSigningKey = cacheSigningKey(this, options)
    }

    // @ts-expect-error TODO: fix this
    this.getSigningKey = callbackSupport(this, options)
  }

  async getKeys() {
    const res = (await request(this.options.jwksUri)) as { keys: JWK[] }
    return res.keys
  }

  async getSigningKeys() {
    const keys = await this.getKeys()

    if (!keys || !keys.length) {
      throw new Error('[JwksError]: The JWKS endpoint did not contain any keys')
    }

    const signingKeys = await retrieveSigningKeys(keys)

    if (!signingKeys.length) {
      throw new Error(
        '[JwksError]: The JWKS endpoint did not contain any signing keys'
      )
    }

    return signingKeys
  }

  async getSigningKey(kid?: string) {
    const keys = await this.getSigningKeys()

    const kidDefined = kid !== undefined && kid !== null

    if (!kidDefined && keys.length > 1) {
      throw new Error(
        '[SigningKeyNotFoundError]: No KID specified and JWKS endpoint returned more than 1 key'
      )
    }

    const key = keys.find((k) => !kidDefined || k.kid === kid)

    if (key) {
      return key
    }

    throw new Error(
      `[SigningKeyNotFoundError]: Unable to find a signing key that matches '${kid}'`
    )
  }
}

export { JwksClient }
