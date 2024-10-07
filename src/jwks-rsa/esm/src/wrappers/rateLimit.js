import debug from 'debug'
import { RateLimiter } from '../../../../limitter/esm/src/index.js'
import JwksRateLimitError from '../errors/JwksRateLimitError.js'

const logger = debug('jwks')

// @ts-expect-error TODO
function rateLimitWrapper(client, { jwksRequestsPerMinute = 10 }) {
  const getSigningKey = client.getSigningKey.bind(client)

  // @ts-expect-error TODO
  const limiter = new RateLimiter(jwksRequestsPerMinute, 'minute', true)
  logger(
    `Configured rate limiting to JWKS endpoint at ${jwksRequestsPerMinute}/minute`
  )

  // @ts-expect-error TODO
  return async (kid) =>
    await new Promise((resolve, reject) => {
      // @ts-expect-error TODO
      limiter.removeTokens(1, async (err, remaining) => {
        if (err) {
          reject(err)
        }

        logger(
          'Requests to the JWKS endpoint available for the next minute:',
          remaining
        )
        if (remaining < 0) {
          logger('Too many requests to the JWKS endpoint')
          reject(
            new JwksRateLimitError('Too many requests to the JWKS endpoint')
          )
        } else {
          try {
            const key = await getSigningKey(kid)
            resolve(key)
          } catch (error) {
            reject(error)
          }
        }
      })
    })
}

export default rateLimitWrapper
