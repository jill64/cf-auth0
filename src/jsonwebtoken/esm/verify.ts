import { KeyObject, createPublicKey, createSecretKey } from 'node:crypto'
import jws from '../../jws/esm/index.js'
import decode from './decode.js'
import {
  GetPublicKeyOrSecret,
  Jwt,
  JwtPayload,
  PublicKey,
  Secret,
  VerifyCallback,
  VerifyOptions
} from './index.js'
import JsonWebTokenError from './lib/JsonWebTokenError.js'
import NotBeforeError from './lib/NotBeforeError.js'
import PS_SUPPORTED from './lib/psSupported.js'
import timespan from './lib/timespan.js'
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

export default function (
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options:
    | (VerifyOptions & { complete?: boolean })
    | VerifyCallback<JwtPayload | string>,
  callback?: VerifyCallback<Jwt | JwtPayload | string> | VerifyCallback
) {
  if (typeof options === 'function' && !callback) {
    callback = options as VerifyCallback<Jwt | JwtPayload | string>
    options = {}
  }

  if (!options) {
    options = {}
  }

  //clone this object since we are going to mutate it.
  options = Object.assign({}, options)

  let done

  if (callback) {
    done = callback
  } else {
    done = function (err: unknown, data?: Jwt | JwtPayload | string) {
      if (err) throw err
      return data
    }
  }

  if (
    typeof options === 'object' &&
    options.clockTimestamp &&
    typeof options.clockTimestamp !== 'number'
  ) {
    return done(new JsonWebTokenError('clockTimestamp must be a number'))
  }

  if (
    typeof options === 'object' &&
    options.nonce !== undefined &&
    (typeof options.nonce !== 'string' || options.nonce.trim() === '')
  ) {
    return done(new JsonWebTokenError('nonce must be a non-empty string'))
  }

  if (
    typeof options === 'object' &&
    options.allowInvalidAsymmetricKeyTypes !== undefined &&
    typeof options.allowInvalidAsymmetricKeyTypes !== 'boolean'
  ) {
    return done(
      new JsonWebTokenError('allowInvalidAsymmetricKeyTypes must be a boolean')
    )
  }

  const clockTimestamp =
    (typeof options === 'object' && options.clockTimestamp) ||
    Math.floor(Date.now() / 1000)

  if (!jwtString) {
    return done(new JsonWebTokenError('jwt must be provided'))
  }

  if (typeof jwtString !== 'string') {
    return done(new JsonWebTokenError('jwt must be a string'))
  }

  const parts = jwtString.split('.')

  if (parts.length !== 3) {
    return done(new JsonWebTokenError('jwt malformed'))
  }

  let decodedToken

  try {
    decodedToken = decode(jwtString, { complete: true })
  } catch (err) {
    return done(err as TokenExpiredError)
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'))
  }

  // @ts-expect-error WARING: Unknown property
  const header = decodedToken.header
  let getSecret

  if (typeof secretOrPublicKey === 'function') {
    if (!callback) {
      return done(
        new JsonWebTokenError(
          'verify must be called asynchronous if secret or public key is provided as a callback'
        )
      )
    }

    getSecret = secretOrPublicKey
  } else {
    getSecret = function (header, secretCallback) {
      return secretCallback(null, secretOrPublicKey)
    } satisfies GetPublicKeyOrSecret
  }

  return getSecret(header, function (err, secretOrPublicKey) {
    if (err) {
      return done(
        new JsonWebTokenError(
          'error in secret or public key callback: ' + err.message
        )
      )
    }

    const hasSignature = parts[2].trim() !== ''

    if (!hasSignature && secretOrPublicKey) {
      return done(new JsonWebTokenError('jwt signature is required'))
    }

    if (hasSignature && !secretOrPublicKey) {
      return done(
        new JsonWebTokenError('secret or public key must be provided')
      )
    }

    if (!hasSignature && (typeof options !== 'object' || !options.algorithms)) {
      return done(
        new JsonWebTokenError(
          'please specify "none" in "algorithms" to verify unsigned tokens'
        )
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
            // @ts-expect-error WARING: Unknown property
            typeof secretOrPublicKey === 'string'
              ? Buffer.from(secretOrPublicKey)
              : secretOrPublicKey
          )
        } catch {
          return done(
            new JsonWebTokenError('secretOrPublicKey is not valid key material')
          )
        }
      }
    }

    if (typeof options !== 'object' || !options.algorithms) {
      if (secretOrPublicKey?.type === 'secret') {
        // @ts-expect-error WARING: Unknown property
        options.algorithms = HS_ALGS
      } else if (
        ['rsa', 'rsa-pss'].includes(secretOrPublicKey?.asymmetricKeyType || '')
      ) {
        // @ts-expect-error WARING: Unknown property
        options.algorithms = RSA_KEY_ALGS
      } else if (secretOrPublicKey?.asymmetricKeyType === 'ec') {
        // @ts-expect-error WARING: Unknown property
        options.algorithms = EC_KEY_ALGS
      } else {
        // @ts-expect-error WARING: Unknown property
        options.algorithms = PUB_KEY_ALGS
      }
    }

    if (
      typeof options === 'object' &&
      // @ts-expect-error WARING: Unknown property
      options.algorithms?.indexOf(decodedToken.header.alg) === -1
    ) {
      return done(new JsonWebTokenError('invalid algorithm'))
    }

    if (header.alg.startsWith('HS') && secretOrPublicKey?.type !== 'secret') {
      return done(
        new JsonWebTokenError(
          `secretOrPublicKey must be a symmetric key when using ${header.alg}`
        )
      )
    } else if (
      /^(?:RS|PS|ES)/.test(header.alg) &&
      secretOrPublicKey?.type !== 'public'
    ) {
      return done(
        new JsonWebTokenError(
          `secretOrPublicKey must be an asymmetric key when using ${header.alg}`
        )
      )
    }

    if (
      typeof options !== 'object' ||
      !options.allowInvalidAsymmetricKeyTypes
    ) {
      try {
        validateAsymmetricKey(header.alg, secretOrPublicKey!)
      } catch (e) {
        return done(e as JsonWebTokenError)
      }
    }

    let valid

    try {
      // @ts-expect-error WARING: Unknown property
      valid = jws.verify(jwtString, decodedToken.header.alg, secretOrPublicKey)
    } catch (e) {
      return done(e as JsonWebTokenError)
    }

    if (!valid) {
      return done(new JsonWebTokenError('invalid signature'))
    }

    // @ts-expect-error WARING: Unknown property
    const payload = decodedToken.payload

    // @ts-expect-error WARING: Unknown property
    if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
      if (typeof payload.nbf !== 'number') {
        return done(new JsonWebTokenError('invalid nbf value'))
      }
      // @ts-expect-error WARING: Unknown property
      if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
        return done(
          new NotBeforeError('jwt not active', new Date(payload.nbf * 1000))
        )
      }
    }

    // @ts-expect-error WARING: Unknown property
    if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
      if (typeof payload.exp !== 'number') {
        return done(new JsonWebTokenError('invalid exp value'))
      }
      // @ts-expect-error WARING: Unknown property
      if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
        return done(
          new TokenExpiredError('jwt expired', new Date(payload.exp * 1000))
        )
      }
    }

    if (typeof options === 'object' && options.audience) {
      const audiences = Array.isArray(options.audience)
        ? options.audience
        : [options.audience]
      const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud]

      const match = target.some(function (targetAudience: string) {
        return audiences.some(function (audience: string | RegExp) {
          return audience instanceof RegExp
            ? audience.test(targetAudience)
            : audience === targetAudience
        })
      })

      if (!match) {
        return done(
          new JsonWebTokenError(
            'jwt audience invalid. expected: ' + audiences.join(' or ')
          )
        )
      }
    }

    if (typeof options === 'object' && options.issuer) {
      const invalid_issuer =
        (typeof options.issuer === 'string' &&
          payload.iss !== options.issuer) ||
        (Array.isArray(options.issuer) &&
          options.issuer.indexOf(payload.iss) === -1)

      if (invalid_issuer) {
        return done(
          new JsonWebTokenError(
            'jwt issuer invalid. expected: ' + options.issuer
          )
        )
      }
    }

    if (typeof options === 'object' && options.subject) {
      if (payload.sub !== options.subject) {
        return done(
          new JsonWebTokenError(
            'jwt subject invalid. expected: ' + options.subject
          )
        )
      }
    }

    if (typeof options === 'object' && options.jwtid) {
      if (payload.jti !== options.jwtid) {
        return done(
          new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid)
        )
      }
    }

    if (typeof options === 'object' && options.nonce) {
      if (payload.nonce !== options.nonce) {
        return done(
          new JsonWebTokenError('jwt nonce invalid. expected: ' + options.nonce)
        )
      }
    }

    if (typeof options === 'object' && options.maxAge) {
      if (typeof payload.iat !== 'number') {
        return done(
          new JsonWebTokenError('iat required when maxAge is specified')
        )
      }

      const maxAgeTimestamp = timespan(options.maxAge, payload.iat)
      if (typeof maxAgeTimestamp === 'undefined') {
        return done(
          new JsonWebTokenError(
            '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
          )
        )
      }
      if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
        return done(
          new TokenExpiredError(
            'maxAge exceeded',
            new Date(maxAgeTimestamp * 1000)
          )
        )
      }
    }

    if (typeof options === 'object' && options.complete === true) {
      // @ts-expect-error WARING: Unknown property
      const signature = decodedToken.signature

      return done(null, {
        header: header,
        payload: payload,
        signature: signature
      })
    }

    return done(null, payload)
  })
}
