import type { JWTHeaderParameters } from 'jose'
import crypto from 'node:crypto'
import { decode } from './decode'
import { jwsVerify } from './jws/lib/jwsVerify'
import { createPublicKey } from './lib/createPublicKey'
import PS_SUPPORTED from './lib/psSupported'
import validateAsymmetricKey from './lib/validateAsymmetricKey'

const PUB_KEY_ALGS = ['RS256', 'RS384', 'RS512']
const EC_KEY_ALGS = ['ES256', 'ES384', 'ES512']
const RSA_KEY_ALGS = ['RS256', 'RS384', 'RS512']
const HS_ALGS = ['HS256', 'HS384', 'HS512']

if (PS_SUPPORTED) {
  PUB_KEY_ALGS.splice(PUB_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512')
  RSA_KEY_ALGS.splice(RSA_KEY_ALGS.length, 0, 'PS256', 'PS384', 'PS512')
}

export const verify = async (
  jwtString: string,
  secretOrPublicKey:
    | string
    | ((jwtHeader: JWTHeaderParameters) => Promise<string>)
) => {
  const options: {
    algorithms?: string[]
  } = {}

  const clockTimestamp = Math.floor(Date.now() / 1000)

  if (!jwtString) {
    throw new Error('[JsonWebTokenError]: jwt must be provided')
  }

  if (typeof jwtString !== 'string') {
    throw new Error('[JsonWebTokenError]: jwt must be a string')
  }

  const parts = jwtString.split('.')

  if (parts.length !== 3) {
    throw new Error('[JsonWebTokenError]: jwt malformed')
  }

  const decodedToken = decode(jwtString, { complete: true })

  if (!decodedToken) {
    throw new Error('[JsonWebTokenError]: invalid token')
  }

  const header = decodedToken.header

  const getSecret =
    typeof secretOrPublicKey === 'function'
      ? secretOrPublicKey
      : async () => secretOrPublicKey

  const secretOrPublicKey2 = await getSecret(header)

  const hasSignature = parts[2].trim() !== ''

  if (!hasSignature && secretOrPublicKey2) {
    throw new Error('[JsonWebTokenError]: jwt signature is required')
  }

  if (hasSignature && !secretOrPublicKey2) {
    throw new Error(
      '[JsonWebTokenError]: secret or public key must be provided'
    )
  }

  if (!hasSignature) {
    throw new Error(
      '[JsonWebTokenError]: please specify "none" in "algorithms" to verify unsigned tokens'
    )
  }

  let secretOrPublicKey3

  if (secretOrPublicKey2 != null) {
    try {
      secretOrPublicKey3 = await createPublicKey(secretOrPublicKey2)
    } catch {
      try {
        secretOrPublicKey3 = crypto.createSecretKey(
          typeof secretOrPublicKey2 === 'string'
            ? Buffer.from(secretOrPublicKey2)
            : secretOrPublicKey2
        )
      } catch {
        throw new Error(
          '[JsonWebTokenError]: secretOrPublicKey2 is not valid key material'
        )
      }
    }
  }

  if (!secretOrPublicKey3) {
    throw new Error(
      '[JsonWebTokenError]: secret or public key must be provided'
    )
  }

  if (secretOrPublicKey3.type === 'secret') {
    options.algorithms = HS_ALGS
  } else if (
    'asymmetricKeyType' in secretOrPublicKey3 &&
    secretOrPublicKey3.asymmetricKeyType &&
    ['rsa', 'rsa-pss'].includes(secretOrPublicKey3.asymmetricKeyType)
  ) {
    options.algorithms = RSA_KEY_ALGS
  } else if (
    'asymmetricKeyType' in secretOrPublicKey3 &&
    secretOrPublicKey3.asymmetricKeyType === 'ec'
  ) {
    options.algorithms = EC_KEY_ALGS
  } else {
    options.algorithms = PUB_KEY_ALGS
  }

  if (options.algorithms.indexOf(decodedToken.header.alg) === -1) {
    throw new Error('[JsonWebTokenError]: invalid algorithm')
  }

  if (header.alg.startsWith('HS') && secretOrPublicKey3.type !== 'secret') {
    throw new Error(
      `[JsonWebTokenError]: secretOrPublicKey3 must be a symmetric key when using ${header.alg}`
    )
  } else if (
    /^(?:RS|PS|ES)/.test(header.alg) &&
    secretOrPublicKey3.type !== 'public'
  ) {
    throw new Error(
      `[JsonWebTokenError]: secretOrPublicKey3 must be an asymmetric key when using ${header.alg}`
    )
  }

  validateAsymmetricKey(header.alg, secretOrPublicKey3)

  const valid = await jwsVerify(
    jwtString,
    decodedToken.header.alg,
    secretOrPublicKey3
  )

  if (!valid) {
    throw new Error('[JsonWebTokenError]: invalid signature')
  }

  const { payload } = decodedToken

  if (typeof payload.nbf !== 'undefined') {
    if (typeof payload.nbf !== 'number') {
      throw new Error('[JsonWebTokenError]: invalid nbf value')
    }
    if (payload.nbf > clockTimestamp) {
      throw new Error(
        `[NotBeforeError]: jwt not active ${new Date(payload.nbf * 1000)}`
      )
    }
  }

  if (typeof payload.exp !== 'undefined') {
    if (typeof payload.exp !== 'number') {
      throw new Error('[JsonWebTokenError]: invalid exp value')
    }
    if (clockTimestamp >= payload.exp) {
      throw new Error(
        `[TokenExpiredError]: jwt expired ${new Date(payload.exp * 1000)}`
      )
    }
  }

  return payload
}
