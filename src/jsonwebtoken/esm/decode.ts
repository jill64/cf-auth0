import jws from '../../jws/esm/index.js'
import { DecodeOptions, Jwt, JwtPayload } from './index.js'

export default function (
  jwt: string,
  options?: DecodeOptions & {
    complete?: true
    json?: true
  }
): null | Jwt | JwtPayload | string {
  options = options || {}
  var decoded = jws.decode(jwt, options)
  if (!decoded) {
    return null
  }
  var payload = decoded.payload

  //try parse the payload
  if (typeof payload === 'string') {
    try {
      var obj = JSON.parse(payload)
      if (obj !== null && typeof obj === 'object') {
        payload = obj
      }
    } catch {}
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    }
  }
  return payload
}
