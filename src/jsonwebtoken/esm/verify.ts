import { createPublicKey, createSecretKey } from 'node:crypto'
import * as jws from '../../jws/esm/index.js'
import decode from './decode.js'
import { JwtHeader, JwtPayload, PublicKey, Secret } from './index.js'
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
  jwtString: string,
  secretOrPublicKey:
    | ((header: JwtHeader) => Promise<Secret | PublicKey>)
    | string
): Promise<JwtPayload> {
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

  const hasSignature = parts[2].trim() !== ''

  if (!hasSignature) {
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

  let secretOrPublicKey2

  const sig =
    typeof secretOrPublicKey === 'string'
      ? secretOrPublicKey
      : await secretOrPublicKey(header)

  if (!sig) {
    throw new JsonWebTokenError('sig must be provided')
  }

  try {
    secretOrPublicKey2 = createPublicKey(sig)
  } catch (e) {
    console.error('createPublicKey Error:', e)
    try {
      // @ts-expect-error TODO
      secretOrPublicKey2 = createSecretKey(sig)
    } catch (e) {
      console.error('createSecretKey Error:', e)
      throw new JsonWebTokenError('secretOrPublicKey is not valid key material')
    }
  }

  // if (secretOrPublicKey2.asymmetricKeyType !== undefined) {
  //   throw new JsonWebTokenError('invalid key')
  // }

  const secretOrPublicKey3 = secretOrPublicKey2 as unknown as {
    asymmetricKeyType: 'rsa' | 'rsa-pss' | 'ec'
    asymmetricKeyDetails: {
      namedCurve: string
      hashAlgorithm: string
      mgf1HashAlgorithm: string
      saltLength: number
    }
  }

  let options: {
    algorithms: string[]
  } = {
    algorithms: []
  }

  if (secretOrPublicKey2.type === 'secret') {
    options.algorithms = HS_ALGS
  } else if (
    ['rsa', 'rsa-pss'].includes(secretOrPublicKey3.asymmetricKeyType)
  ) {
    options.algorithms = RSA_KEY_ALGS
  } else if (secretOrPublicKey2.asymmetricKeyType === 'ec') {
    options.algorithms = EC_KEY_ALGS
  } else {
    options.algorithms = PUB_KEY_ALGS
  }

  console.log('sig', sig)
  console.log('secretOrPublicKey2', secretOrPublicKey2)
  console.log('options', options)
  console.log('decodedToken', decodedToken)

  // @ts-expect-error TODO
  if (options.algorithms.indexOf(decodedToken.header.alg) === -1) {
    throw new JsonWebTokenError('invalid algorithm')
  }

  if (header.alg.startsWith('HS') && secretOrPublicKey2.type !== 'secret') {
    throw new JsonWebTokenError(
      `secretOrPublicKey must be a symmetric key when using ${header.alg}`
    )
  } else if (
    /^(?:RS|PS|ES)/.test(header.alg) &&
    secretOrPublicKey2.type !== 'public'
  ) {
    throw new JsonWebTokenError(
      `secretOrPublicKey must be an asymmetric key when using ${header.alg}`
    )
  }

  validateAsymmetricKey(header.alg, secretOrPublicKey3)

  const valid = jws.verify(
    jwtString,
    // @ts-expect-error TODO
    decodedToken.header.alg,
    secretOrPublicKey3
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
}
