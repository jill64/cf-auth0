import { callbackify } from 'node:util'
import { JwksClient } from '../JwksClient.js'

const callbackSupport = (client: JwksClient) => {
  const getSigningKey = client.getSigningKey.bind(client)

  return (kid: unknown, cb: (err: Error | null, key: unknown) => void) => {
    if (cb) {
      const callbackFunc = callbackify(getSigningKey)
      return callbackFunc(kid, cb)
    }

    return getSigningKey(kid)
  }
}

export default callbackSupport
