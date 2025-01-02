import { callbackify, promisify } from 'node:util'
import { JwksClient } from '../JwksClient'
import memoizer from './lru-memoizer'

const cacheWrapper = (
  client: JwksClient,
  { cacheMaxEntries = 5, cacheMaxAge = 600000 }
) =>
  promisify(
    memoizer({
      hash: (kid: string) => kid,
      // @ts-expect-error TODO: fix this
      load: callbackify(client.getSigningKey.bind(client)),
      maxAge: cacheMaxAge,
      max: cacheMaxEntries
    })
  )

export default cacheWrapper
