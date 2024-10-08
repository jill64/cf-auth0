import debug from 'debug'
import JwksError from './errors/JwksError.js'
import SigningKeyNotFoundError from './errors/SigningKeyNotFoundError.js'
import { retrieveSigningKeys } from './utils.js'
import {
  cacheSigningKey,
  callbackSupport,
  getKeysInterceptor,
  rateLimitSigningKey,
  request
} from './wrappers/index.js'

const logger = debug('jwks')

class JwksClient {
  // @ts-expect-error TODO
  constructor(options) {
    this.options = {
      rateLimit: false,
      cache: true,
      timeout: 30000,
      ...options
    }

    // Initialize wrappers.
    if (this.options.getKeysInterceptor) {
      this.getSigningKey = getKeysInterceptor(this, options)
    }

    if (this.options.rateLimit) {
      this.getSigningKey = rateLimitSigningKey(this, options)
    }
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options)
    }

    // @ts-expect-error TODO
    this.getSigningKey = callbackSupport(this, options)
  }

  async getKeys() {
    logger(`Fetching keys from '${this.options.jwksUri}'`)

    try {
      const res = await request({
        uri: this.options.jwksUri,
        headers: this.options.requestHeaders
      })

      logger('Keys:', res.keys)
      return res.keys
    } catch (err) {
      // @ts-expect-error TODO
      const { errorMsg } = err
      logger('Failure:', errorMsg || err)
      throw errorMsg ? new JwksError(errorMsg) : err
    }
  }

  async getSigningKeys() {
    const keys = await this.getKeys()

    if (!keys || !keys.length) {
      throw new JwksError('The JWKS endpoint did not contain any keys')
    }

    const signingKeys = await retrieveSigningKeys(keys)

    if (!signingKeys.length) {
      throw new JwksError('The JWKS endpoint did not contain any signing keys')
    }

    logger('Signing Keys:', signingKeys)
    return signingKeys
  }

  // @ts-expect-error TODO
  async getSigningKey(kid) {
    logger(`Fetching signing key for '${kid}'`)

    const keys = await this.getSigningKeys()

    const kidDefined = kid !== undefined && kid !== null
    if (!kidDefined && keys.length > 1) {
      logger('No KID specified and JWKS endpoint returned more than 1 key')
      throw new SigningKeyNotFoundError(
        'No KID specified and JWKS endpoint returned more than 1 key'
      )
    }

    const key = keys.find((k) => !kidDefined || k.kid === kid)
    if (key) {
      // eslint-disable-next-line no-undef
      console.log('Determined Key:', key)

      // Wait 1sec
      // eslint-disable-next-line no-undef
      await new Promise((resolve) => setTimeout(resolve, 1000))

      return key
    } else {
      logger(`Unable to find a signing key that matches '${kid}'`)
      throw new SigningKeyNotFoundError(
        `Unable to find a signing key that matches '${kid}'`
      )
    }
  }
}

export { JwksClient }
