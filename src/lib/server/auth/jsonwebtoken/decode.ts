import type { JWTHeaderParameters, JWTPayload } from 'jose'
import { jwsDecode } from './jws/lib/jwsDecode'

export function decode(
  jwt: string,
  options?: {
    encoding?: Parameters<typeof JSON.parse>[1]
    json?: boolean
  }
): JWTPayload

export function decode(
  jwt: string,
  options?: {
    encoding?: Parameters<typeof JSON.parse>[1]
    json?: boolean
    complete: true
  }
): {
  header: JWTHeaderParameters
  payload: JWTPayload
  signature: string
}

export function decode(
  jwt: string,
  options: {
    encoding?: Parameters<typeof JSON.parse>[1]
    json?: boolean
    complete?: true
  } = {}
) {
  const decoded = jwsDecode(jwt, options)

  const { header, signature } = decoded
  let { payload } = decoded

  //try parse the payload
  if (typeof payload === 'string') {
    const obj = JSON.parse(payload)
    if (obj !== null && typeof obj === 'object') {
      payload = obj
    }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options.complete === true) {
    return {
      header,
      payload: payload,
      signature
    }
  }

  return payload
}
