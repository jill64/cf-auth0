import { JWK } from '../../../jose/esm/src/types.js'
import { KIC } from './utils/KIC.js'
import { validateObject } from './utils/validateObject.js'
import { validateOneOf } from './utils/validateOneOf.js'
import { validateString } from './utils/validateString.js'

const kKeyTypePublic = 1
const kKeyTypePrivate = 2

export const getKeyObjectHandleFromJwk = (key: JsonWebKey, ctx: KIC) => {
  validateObject(key, 'key')
  validateOneOf(key.kty, 'key.kty', ['RSA', 'EC', 'OKP'])

  const isPublic = ctx === 'kConsumePublic' || ctx === 'kCreatePublic'

  if (key.kty === 'OKP') {
    validateString(key.crv, 'key.crv')
    validateOneOf(key.crv, 'key.crv', ['Ed25519', 'Ed448', 'X25519', 'X448'])
    validateString(key.x, 'key.x')

    if (!isPublic) validateString(key.d, 'key.d')

    if (!key.x && isPublic) {
      throw new Error('ERR_CRYPTO_INVALID_JWK')
    }

    if (!key.d && !isPublic) {
      throw new Error('ERR_CRYPTO_INVALID_JWK')
    }

    const keyData = isPublic
      ? Buffer.from(key.x!, 'base64')
      : Buffer.from(key.d!, 'base64')

    switch (key.crv) {
      case 'Ed25519':
      case 'X25519':
        if (keyData.byteLength !== 32) {
          throw new Error('ERR_CRYPTO_INVALID_JWK')
        }
        break
      case 'Ed448':
        if (keyData.byteLength !== 57) {
          throw new Error('ERR_CRYPTO_INVALID_JWK')
        }
        break
      case 'X448':
        if (keyData.byteLength !== 56) {
          throw new Error('ERR_CRYPTO_INVALID_JWK')
        }
        break
    }

    const keyType = isPublic ? kKeyTypePublic : kKeyTypePrivate

    return {
      type: 'OKP',
      key,
      keyData,
      keyType
    }
  }

  if (key.kty === 'EC') {
    validateString(key.crv, 'key.crv')
    validateOneOf(key.crv, 'key.crv', ['P-256', 'secp256k1', 'P-384', 'P-521'])
    validateString(key.x, 'key.x')
    validateString(key.y, 'key.y')

    const jwk: JWK = {
      kty: key.kty,
      crv: key.crv,
      x: key.x,
      y: key.y
    }

    if (!isPublic) {
      validateString(key.d, 'key.d')
      jwk.d = key.d
    }

    return {
      type: 'EC',
      key
    }
  }

  // RSA
  validateString(key.n, 'key.n')
  validateString(key.e, 'key.e')

  if (!key.kty) {
    throw new Error('ERR_CRYPTO_INVALID_JWK')
  }

  const jwk: JWK = {
    kty: key.kty,
    n: key.n,
    e: key.e
  }

  if (!isPublic) {
    validateString(key.d, 'key.d')
    validateString(key.p, 'key.p')
    validateString(key.q, 'key.q')
    validateString(key.dp, 'key.dp')
    validateString(key.dq, 'key.dq')
    validateString(key.qi, 'key.qi')
    jwk.d = key.d
    jwk.p = key.p
    jwk.q = key.q
    jwk.dp = key.dp
    jwk.dq = key.dq
    jwk.qi = key.qi
  }

  return {
    type: 'RSA',
    key
  }
}
