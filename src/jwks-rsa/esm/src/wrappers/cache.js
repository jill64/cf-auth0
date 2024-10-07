import { callbackify, promisify } from 'node:util'
import memoizer from '../../../../lru-memoizer/esm/src/index.js'

import debug from 'debug'
const logger = debug('jwks')

function cacheWrapper(client, { cacheMaxEntries = 5, cacheMaxAge = 600000 }) {
  logger(
    `Configured caching of signing keys. Max: ${cacheMaxEntries} / Age: ${cacheMaxAge}`
  )
  return promisify(
    memoizer({
      hash: (kid) => kid,
      load: callbackify(client.getSigningKey.bind(client)),
      maxAge: cacheMaxAge,
      max: cacheMaxEntries
    })
  )
}

export default cacheWrapper
