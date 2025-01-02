import { attempt } from '@jill64/attempt'
import type { JWTPayload } from 'jose'
import isNumber from 'lodash.isnumber'
import isPlainObject from 'lodash.isplainobject'
import crypto from 'node:crypto'
import { jwsSign } from './jws/lib/jwsSign'
import PS_SUPPORTED from './lib/psSupported'
import validateAsymmetricKey from './lib/validateAsymmetricKey'

const SUPPORTED_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'HS256',
  'HS384',
  'HS512',
  'none'
]
if (PS_SUPPORTED) {
  SUPPORTED_ALGS.splice(3, 0, 'PS256', 'PS384', 'PS512')
}

const registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
}

const validate = (
  schema: {
    [key: string]: { isValid: (value: unknown) => boolean; message: string }
  },
  allowUnknown: boolean,
  object: object,
  parameterName: string
) => {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.')
  }
  Object.keys(object).forEach((key) => {
    const validator = schema[key]
    if (!validator) {
      if (!allowUnknown) {
        throw new Error(
          '"' + key + '" is not allowed in "' + parameterName + '"'
        )
      }
      return
    }

    // @ts-expect-error - we know that the key is in the schema
    if (!validator.isValid(object[key])) {
      throw new Error(validator.message)
    }
  })
}

const validatePayload = (payload: JWTPayload) =>
  validate(registered_claims_schema, true, payload, 'payload')

export const sign = async (payload: JWTPayload, secretOrPrivateKey: string) => {
  const header = Object.assign(
    {
      alg: 'HS256',
      typ: 'JWT',
      kid: undefined
    },
    {}
  )

  if (!secretOrPrivateKey) {
    throw new Error('secretOrPrivateKey must have a value')
  }

  const secretOrPrivateKey2 =
    secretOrPrivateKey != null
      ? attempt(
          () => crypto.createPrivateKey(secretOrPrivateKey),
          attempt(
            () =>
              crypto.createSecretKey(
                typeof secretOrPrivateKey === 'string'
                  ? Buffer.from(secretOrPrivateKey)
                  : secretOrPrivateKey
              ),
            () => {
              throw new Error('secretOrPrivateKey is not valid key material')
            }
          )
        )
      : secretOrPrivateKey

  if (header.alg.startsWith('HS') && secretOrPrivateKey2.type !== 'secret') {
    throw new Error(
      `secretOrPrivateKey must be a symmetric key when using ${header.alg}`
    )
  } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
    if (secretOrPrivateKey2.type !== 'private') {
      throw new Error(
        `secretOrPrivateKey must be an asymmetric key when using ${header.alg}`
      )
    }
    if (
      !header.alg.startsWith('ES') &&
      secretOrPrivateKey2.asymmetricKeyDetails !== undefined && //KeyObject.asymmetricKeyDetails is supported in Node 15+
      // @ts-expect-error - we know that asymmetricKeyDetails is defined
      secretOrPrivateKey2.asymmetricKeyDetails.modulusLength < 2048
    ) {
      throw new Error(
        `secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`
      )
    }
  }

  validatePayload(payload)

  validateAsymmetricKey(header.alg, secretOrPrivateKey2)

  const timestamp = payload.iat || Math.floor(Date.now() / 1000)

  payload.iat = timestamp

  const signature = jwsSign({
    header,
    payload,
    secret: secretOrPrivateKey,
    encoding: 'utf8'
  })

  // TODO: Remove in favor of the modulus length check before signing once node 15+ is the minimum supported version
  if (/^(?:RS|PS)/.test(header.alg) && signature.length < 256) {
    throw new Error(
      `secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`
    )
  }

  return signature
}
