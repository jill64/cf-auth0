import * as jws from '../../jws/esm/index.js'
import { JwtPayload } from './index.js'

export default (jwt: string) => {
  const decoded = jws.decode(jwt)

  if (!decoded) {
    return null
  }

  const { header, payload, signature } = decoded

  let payload2

  //try parse the payload
  if (typeof payload === 'string') {
    const obj = JSON.parse(payload) as JwtPayload

    if (obj !== null && typeof obj === 'object') {
      payload2 = obj
    }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  return {
    header,
    payload: payload2,
    signature
  }
}
