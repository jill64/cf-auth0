import { callbackify } from 'node:util'
import { JwksClient } from '../JwksClient'

const callbackSupport = (client: JwksClient) => {
  const getSigningKey = client.getSigningKey.bind(client)

  return (kid: string, cb: unknown) => {
    if (cb) {
      const callbackFunc = callbackify(getSigningKey)
      // @ts-expect-error TODO: fix this
      return callbackFunc(kid, cb)
    }

    return getSigningKey(kid)
  }
}

export default callbackSupport
