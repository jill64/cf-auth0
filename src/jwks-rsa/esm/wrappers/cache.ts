import debug from 'debug'
import { callbackify, promisify } from 'node:util'
import memoizer from '../../../lru-memoizer/esm/index.js'
import { JwksClient } from '../JwksClient.js'

const logger = debug('jwks')

export default function cacheWrapper(
  client: JwksClient,
  { cacheMaxEntries = 5, cacheMaxAge = 600000 }
) {
  logger(
    `Configured caching of signing keys. Max: ${cacheMaxEntries} / Age: ${cacheMaxAge}`
  )
  return promisify(
    memoizer({
      // @ts-expect-error WARNING: Unknown type `kid`
      hash: (kid: unknown) => kid,
      // @ts-expect-error WARNING: Unknown type
      load: callbackify(client.getSigningKey.bind(client)),
      maxAge: cacheMaxAge,
      max: cacheMaxEntries
    })
  )
}
