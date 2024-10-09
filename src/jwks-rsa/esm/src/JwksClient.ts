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
    // @ts-expect-error TODO
    this.options = {
      rateLimit: false,
      cache: true,
      timeout: 30000,
      ...options
    }

    // Initialize wrappers.
    // @ts-expect-error TODO
    if (this.options.getKeysInterceptor) {
      this.getSigningKey = getKeysInterceptor(this, options)
    }

    // @ts-expect-error TODO
    if (this.options.rateLimit) {
      this.getSigningKey = rateLimitSigningKey(this, options)
    }
    // @ts-expect-error TODO
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options)
    }

    // @ts-expect-error TODO
    this.getSigningKey = callbackSupport(this, options)
  }

  async getKeys() {
    // @ts-expect-error TODO
    logger(`Fetching keys from '${this.options.jwksUri}'`)

    try {
      const res = await request({
        // @ts-expect-error TODO
        uri: this.options.jwksUri,
        // @ts-expect-error TODO
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

    // eslint-disable-next-line no-undef
    console.log('Keys2:', keys)

    const signingKeys = await retrieveSigningKeys(keys)

    // eslint-disable-next-line no-undef
    console.log('Signing Keys:', signingKeys)

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

    // eslint-disable-next-line no-undef
    console.log('Keys:', keys)

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
