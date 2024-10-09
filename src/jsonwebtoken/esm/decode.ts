import { decode } from '../../jws/esm/index.js'
import { Jwt, JwtPayload } from './index.js'

export default (
  jwt: string,
  options: Parameters<typeof decode>[1] & {
    complete?: boolean
  } = {}
): string | JwtPayload | null | Jwt => {
  const decoded = decode(jwt, options)

  if (!decoded) {
    return null
  }

  let payload = decoded.payload

  //try parse the payload
  if (typeof payload === 'string') {
    try {
      const obj = JSON.parse(payload)
      if (obj !== null && typeof obj === 'object') {
        payload = obj
      }
      // eslint-disable-next-line no-empty
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
