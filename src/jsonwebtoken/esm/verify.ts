import { Buffer } from 'node:buffer'
import { KeyObject, createPublicKey, createSecretKey } from 'node:crypto'
import * as jws from '../../jws/esm/index.js'
import decode from './decode.js'
import JsonWebTokenError from './lib/JsonWebTokenError.js'
import NotBeforeError from './lib/NotBeforeError.js'
import PS_SUPPORTED from './lib/psSupported.js'
import TokenExpiredError from './lib/TokenExpiredError.js'
import validateAsymmetricKey from './lib/validateAsymmetricKey.js'

const PUB_KEY_ALGS = ['RS256', 'RS384', 'RS512']
const EC_KEY_ALGS = ['ES256', 'ES384', 'ES512']
const RSA_KEY_ALGS = ['RS256', 'RS384', 'RS512']
const HS_ALGS = ['HS256', 'HS384', 'HS512']

if (PS_SUPPORTED) {
  PUB_KEY_ALGS.splice(PUB_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512')
  RSA_KEY_ALGS.splice(RSA_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512')
}

export default async function (
  // @ts-expect-error TODO
  jwtString,
  // @ts-expect-error TODO
  secretOrPublicKey
) {
  const clockTimestamp = Math.floor(Date.now() / 1000)

  if (!jwtString) {
    throw new JsonWebTokenError('jwt must be provided')
  }

  if (typeof jwtString !== 'string') {
    throw new JsonWebTokenError('jwt must be a string')
  }

  const parts = jwtString.split('.')

  if (parts.length !== 3) {
    throw new JsonWebTokenError('jwt malformed')
  }

  const decodedToken = decode(jwtString, { complete: true })

  if (!decodedToken) {
    throw new JsonWebTokenError('invalid token')
  }

  // @ts-expect-error TODO
  const header = decodedToken.header
  const getSecret =
    typeof secretOrPublicKey === 'function'
      ? secretOrPublicKey
      : // @ts-expect-error TODO
        function (header, secretCallback) {
          return secretCallback(null, secretOrPublicKey)
        }

  // @ts-expect-error TODO
  return await getSecret(header, function (err, secretOrPublicKey) {
    // eslint-disable-next-line no-undef
    console.log('getSecret', err, secretOrPublicKey)

    if (err) {
      throw new JsonWebTokenError(
        'error in secret or public key callback: ' + err.message
      )
    }

    const hasSignature = parts[2].trim() !== ''

    if (!hasSignature && secretOrPublicKey) {
      throw new JsonWebTokenError('jwt signature is required')
    }

    if (hasSignature && !secretOrPublicKey) {
      throw new JsonWebTokenError('secret or public key must be provided')
    }

    if (!hasSignature) {
      throw new JsonWebTokenError(
        'please specify "none" in "algorithms" to verify unsigned tokens'
      )
    }

    if (
      secretOrPublicKey != null &&
      !(secretOrPublicKey instanceof KeyObject)
    ) {
      try {
        secretOrPublicKey = createPublicKey(secretOrPublicKey)
      } catch {
        try {
          secretOrPublicKey = createSecretKey(
            typeof secretOrPublicKey === 'string'
              ? Buffer.from(secretOrPublicKey)
              : secretOrPublicKey
          )
        } catch {
          throw new JsonWebTokenError(
            'secretOrPublicKey is not valid key material'
          )
        }
      }
    }

    let options: {
      algorithms: string[]
    } = {
      algorithms: []
    }

    if (secretOrPublicKey.type === 'secret') {
      options.algorithms = HS_ALGS
    } else if (
      ['rsa', 'rsa-pss'].includes(secretOrPublicKey.asymmetricKeyType)
    ) {
      options.algorithms = RSA_KEY_ALGS
    } else if (secretOrPublicKey.asymmetricKeyType === 'ec') {
      options.algorithms = EC_KEY_ALGS
    } else {
      options.algorithms = PUB_KEY_ALGS
    }

    // @ts-expect-error TODO
    if (options.algorithms.indexOf(decodedToken.header.alg) === -1) {
      throw new JsonWebTokenError('invalid algorithm')
    }

    if (header.alg.startsWith('HS') && secretOrPublicKey.type !== 'secret') {
      throw new JsonWebTokenError(
        `secretOrPublicKey must be a symmetric key when using ${header.alg}`
      )
    } else if (
      /^(?:RS|PS|ES)/.test(header.alg) &&
      secretOrPublicKey.type !== 'public'
    ) {
      throw new JsonWebTokenError(
        `secretOrPublicKey must be an asymmetric key when using ${header.alg}`
      )
    }

    validateAsymmetricKey(header.alg, secretOrPublicKey)

    const valid = jws.verify(
      jwtString,
      // @ts-expect-error TODO
      decodedToken.header.alg,
      secretOrPublicKey
    )

    if (!valid) {
      throw new JsonWebTokenError('invalid signature')
    }

    // @ts-expect-error TODO
    const payload = decodedToken.payload

    if (typeof payload.nbf !== 'undefined') {
      if (typeof payload.nbf !== 'number') {
        throw new JsonWebTokenError('invalid nbf value')
      }
      if (payload.nbf > clockTimestamp) {
        throw new NotBeforeError('jwt not active', new Date(payload.nbf * 1000))
      }
    }

    if (typeof payload.exp !== 'undefined') {
      if (typeof payload.exp !== 'number') {
        throw new JsonWebTokenError('invalid exp value')
      }
      if (clockTimestamp >= payload.exp) {
        throw new TokenExpiredError('jwt expired', new Date(payload.exp * 1000))
      }
    }

    return payload
  })
}
