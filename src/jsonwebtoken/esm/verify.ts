import * as jws from '../../jws/esm/index.js'
import { createPublicKey, createSecretKey } from '../../lib/crypto/index.js'
import decode from './decode.js'
import { Jwt, JwtHeader, JwtPayload, PublicKey, Secret } from './index.js'
import JsonWebTokenError from './lib/JsonWebTokenError.js'
import NotBeforeError from './lib/NotBeforeError.js'
import TokenExpiredError from './lib/TokenExpiredError.js'

// const PUB_KEY_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
// const RSA_KEY_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']

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

  if (typeof decodedToken === 'string') {
    throw new JsonWebTokenError('decodedToken must be an object')
  }

  if (
    !(decodedToken.header && decodedToken.payload && decodedToken.signature)
  ) {
    throw new JsonWebTokenError('invalid decodedToken')
  }

  const { header, payload } = decodedToken as Jwt

  if (typeof payload === 'string') {
    throw new JsonWebTokenError('decodedToken.payload must be an object')
  }

  const hasSignature = parts[2].trim() !== ''

  if (!hasSignature) {
    throw new JsonWebTokenError('jwt signature is required')
  }

  if (hasSignature && !secretOrPublicKey) {
    throw new JsonWebTokenError('secret or public key must be provided')
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
    secretOrPublicKey2 = await createPublicKey(sig)
  } catch (err) {
    console.error('[CreatePublicKey Error]: ', err)
    try {
      secretOrPublicKey2 = createSecretKey(sig as NodeJS.ArrayBufferView)
    } catch {
      throw new JsonWebTokenError('secretOrPublicKey is not valid key material')
    }
  }

  // if (secretOrPublicKey2.asymmetricKeyType !== undefined) {
  //   throw new JsonWebTokenError('invalid key')
  // }

  // const secretOrPublicKey3 = secretOrPublicKey2 as unknown as {
  //   asymmetricKeyType: 'rsa' | 'rsa-pss' | 'ec'
  //   asymmetricKeyDetails: {
  //     namedCurve: string
  //     hashAlgorithm: string
  //     mgf1HashAlgorithm: string
  //     saltLength: number
  //   }
  // }

  // let options: {
  //   algorithms: string[]
  // } = {
  //   algorithms: []
  // }

  // if (secretOrPublicKey2.type === 'secret') {
  //   console.log('USE HS_ALGS')
  //   options.algorithms = HS_ALGS
  // } else if (
  //   ['rsa', 'rsa-pss'].includes(secretOrPublicKey3.asymmetricKeyType)
  // ) {
  //   console.log('USE RSA_KEY_ALGS')
  //   options.algorithms = RSA_KEY_ALGS
  // } else if (secretOrPublicKey2.asymmetricKeyType === 'ec') {
  //   console.log('USE EC_KEY_ALGS')
  //   options.algorithms = EC_KEY_ALGS
  // } else {
  //   console.log('USE PUB_KEY_ALGS')
  //   options.algorithms = PUB_KEY_ALGS
  // }

  console.log('sig', sig)
  console.log('decodedToken', decodedToken)
  console.log('secretOrPublicKey2', secretOrPublicKey2)
  console.log('secretOrPublicKey2.type', secretOrPublicKey2.type)

  // if (options.algorithms.includes(decodedToken.header.alg)) {
  //   throw new JsonWebTokenError('invalid algorithm')
  // }

  // if (header.alg.startsWith('HS') && secretOrPublicKey2.type !== 'secret') {
  //   throw new JsonWebTokenError(
  //     `secretOrPublicKey must be a symmetric key when using ${header.alg}`
  //   )
  // } else if (
  //   /^(?:RS|PS|ES)/.test(header.alg) &&
  //   secretOrPublicKey2.type !== 'public'
  // ) {
  //   throw new JsonWebTokenError(
  //     `secretOrPublicKey must be an asymmetric key when using ${header.alg}`
  //   )
  // }

  // validateAsymmetricKey(header.alg, secretOrPublicKey3)

  const valid = jws.verify(jwtString, header.alg, {
    key: secretOrPublicKey2.export({
      format: 'pem',
      type: 'spki'
    }),
    ...secretOrPublicKey2
  })

  if (!valid) {
    throw new JsonWebTokenError('invalid signature')
  }

  if (typeof payload !== 'string') {
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
  }

  return payload
}
