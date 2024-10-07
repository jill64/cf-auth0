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

export interface Options {
  jwksUri: string
  rateLimit?: boolean
  cache?: boolean
  cacheMaxEntries?: number
  cacheMaxAge?: number
  jwksRequestsPerMinute?: number
  proxy?: string
  requestHeaders?: Headers
  timeout?: number
  getKeysInterceptor?(): Promise<JsonWebKey[]>
}

export class JwksClient {
  options

  constructor(options: Options) {
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
      // @ts-expect-error WARNING: Unknown type `cacheSigningKey`
      this.getSigningKey = cacheSigningKey(this, options)
    }

    // @ts-expect-error WARNING: Unknown type
    this.getSigningKey = callbackSupport(this, options)
  }

  async getKeys() {
    logger(`Fetching keys from '${this.options.jwksUri}'`)

    try {
      const res = await request({
        uri: this.options.jwksUri,
        // @ts-expect-error WARNING: Unknown type
        headers: this.options.requestHeaders
      })

      logger('Keys:', res.keys)
      return res.keys
    } catch (err) {
      logger('Failure:', err)
      throw err instanceof Error ? new JwksError(err.message) : err
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

  async getSigningKey(kid: string) {
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
      return key
    } else {
      logger(`Unable to find a signing key that matches '${kid}'`)
      throw new SigningKeyNotFoundError(
        `Unable to find a signing key that matches '${kid}'`
      )
    }
  }
}
