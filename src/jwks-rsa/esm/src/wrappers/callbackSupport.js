import { callbackify } from 'node:util'

// @ts-expect-error TODO
const callbackSupport = (client) => {
  const getSigningKey = client.getSigningKey.bind(client)

  // @ts-expect-error TODO
  return (kid, cb) => {
    if (cb) {
      const callbackFunc = callbackify(getSigningKey)
      // @ts-expect-error TODO
      return callbackFunc(kid, cb)
    }

    return getSigningKey(kid)
  }
}

export default callbackSupport
