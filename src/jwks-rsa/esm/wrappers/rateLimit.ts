import debug from 'debug'
import limitter from 'limiter'
import JwksRateLimitError from '../errors/JwksRateLimitError.js'
import { JwksClient } from '../JwksClient.js'

const { RateLimiter } = limitter

const logger = debug('jwks')

export default function rateLimitWrapper(
  client: JwksClient,
  { jwksRequestsPerMinute = 10 }
) {
  const getSigningKey = client.getSigningKey.bind(client)

  // const limiter = new RateLimiter(jwksRequestsPerMinute, 'minute', true)
  // WARNING: There may be a bug in this line
  const limiter = new RateLimiter({
    tokensPerInterval: jwksRequestsPerMinute,
    interval: 'minute',
    fireImmediately: true
  })

  logger(
    `Configured rate limiting to JWKS endpoint at ${jwksRequestsPerMinute}/minute`
  )

  return async (kid?: string) => {
    const remaining = await limiter.removeTokens(1)

    logger(
      'Requests to the JWKS endpoint available for the next minute:',
      remaining
    )

    if (remaining < 0) {
      logger('Too many requests to the JWKS endpoint')
      throw new JwksRateLimitError('Too many requests to the JWKS endpoint')
    } else {
      const key = await getSigningKey(kid)
      return key
    }
  }
}
