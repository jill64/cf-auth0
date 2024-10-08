import isObject from '../lib/is_object.js'
import { decode as decodeBase64URL } from '../runtime/browser/base64url.js'
import asKeyObject from '../runtime/browser/jwk_to_key.js'
import type { JWK } from '../types.d.ts'
import { JOSENotSupported } from '../util/errors.js'

export interface PEMImportOptions {
  /**
   * (Only effective in Web Crypto API runtimes) The value to use as {@link !SubtleCrypto.importKey}
   * `extractable` argument. Default is false.
   */
  extractable?: boolean
}

export const importJWK = async (jwk: JWK, alg?: string) => {
  if (!isObject(jwk)) {
    throw new TypeError('JWK must be an object')
  }

  alg ||= jwk.alg

  switch (jwk.kty) {
    case 'oct':
      if (typeof jwk.k !== 'string' || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value')
      }

      return decodeBase64URL(jwk.k)
    case 'RSA':
      if (jwk.oth !== undefined) {
        throw new JOSENotSupported(
          'RSA JWK "oth" (Other Primes Info) Parameter value is not supported'
        )
      }
    case 'EC':
    case 'OKP':
      return asKeyObject({ ...jwk, alg })
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value')
  }
}
