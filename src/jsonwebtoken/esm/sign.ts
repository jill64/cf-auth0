import includes from 'lodash.includes'
import isBoolean from 'lodash.isboolean'
import isInteger from 'lodash.isinteger'
import isNumber from 'lodash.isnumber'
import isPlainObject from 'lodash.isplainobject'
import isString from 'lodash.isstring'
import once from 'lodash.once'
import { KeyObject, createPrivateKey, createSecretKey } from 'node:crypto'
import jws from '../../jws/esm/index.js'
import { PrivateKey, Secret, SignCallback, SignOptions } from './index.js'
import PS_SUPPORTED from './lib/psSupported.js'
import timespan from './lib/timespan.js'
import validateAsymmetricKey from './lib/validateAsymmetricKey.js'

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

const sign_options_schema = {
  expiresIn: {
    isValid: function (value: unknown) {
      return isInteger(value) || (isString(value) && value)
    },
    message:
      '"expiresIn" should be a number of seconds or string representing a timespan'
  },
  notBefore: {
    isValid: function (value: unknown) {
      return isInteger(value) || (isString(value) && value)
    },
    message:
      '"notBefore" should be a number of seconds or string representing a timespan'
  },
  audience: {
    isValid: function (value: unknown) {
      return isString(value) || Array.isArray(value)
    },
    message: '"audience" must be a string or array'
  },
  algorithm: {
    isValid: includes.bind(null, SUPPORTED_ALGS),
    message: '"algorithm" must be a valid string enum value'
  },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: {
    isValid: isBoolean,
    message: '"noTimestamp" must be a boolean'
  },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  mutatePayload: {
    isValid: isBoolean,
    message: '"mutatePayload" must be a boolean'
  },
  allowInsecureKeySizes: {
    isValid: isBoolean,
    message: '"allowInsecureKeySizes" must be a boolean'
  },
  allowInvalidAsymmetricKeyTypes: {
    isValid: isBoolean,
    message: '"allowInvalidAsymmetricKeyTypes" must be a boolean'
  }
}

const registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
}

function validate(
  schema: typeof sign_options_schema | typeof registered_claims_schema,
  allowUnknown: boolean,
  object: string | object | Buffer,
  parameterName: string
) {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.')
  }
  Object.keys(object).forEach(function (key) {
    const validator = schema[key as keyof typeof schema]
    if (!validator) {
      if (!allowUnknown) {
        throw new Error(
          '"' + key + '" is not allowed in "' + parameterName + '"'
        )
      }
      return
    }
    // @ts-expect-error Unknown type for object
    if (!validator.isValid(object[key as keyof typeof object])) {
      // @ts-expect-error Unknown type for object
      throw new Error(validator.message)
    }
  })
}

function validateOptions(options: string | object | Buffer) {
  return validate(sign_options_schema, false, options, 'options')
}

function validatePayload(payload: string | object | Buffer) {
  return validate(registered_claims_schema, true, payload, 'payload')
}

const options_to_payload = {
  audience: 'aud',
  issuer: 'iss',
  subject: 'sub',
  jwtid: 'jti'
}

const options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid'
]

export default function (
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret | PrivateKey | null,
  options:
    | (SignOptions & {
        algorithm?: 'none'
      })
    | SignCallback,
  callback?: SignCallback
) {
  if (typeof options === 'function') {
    callback = options
    options = {}
  } else {
    options = options || {}
  }

  const isObjectPayload =
    typeof payload === 'object' && !Buffer.isBuffer(payload)

  const header = Object.assign(
    {
      alg: options.algorithm || 'HS256',
      typ: isObjectPayload ? 'JWT' : undefined,
      kid: options.keyid
    },
    options.header
  )

  function failure(err: unknown) {
    if (callback) {
      return callback(err as Error, undefined)
    }
    throw err
  }

  if (!secretOrPrivateKey && options.algorithm !== 'none') {
    return failure(new Error('secretOrPrivateKey must have a value'))
  }

  if (
    secretOrPrivateKey != null &&
    !(secretOrPrivateKey instanceof KeyObject)
  ) {
    try {
      secretOrPrivateKey = createPrivateKey(secretOrPrivateKey)
    } catch {
      try {
        secretOrPrivateKey = createSecretKey(
          // @ts-expect-error Unknown type for secretOrPrivateKey
          typeof secretOrPrivateKey === 'string'
            ? Buffer.from(secretOrPrivateKey)
            : secretOrPrivateKey
        )
      } catch {
        return failure(
          new Error('secretOrPrivateKey is not valid key material')
        )
      }
    }
  }

  if (header.alg.startsWith('HS') && secretOrPrivateKey?.type !== 'secret') {
    return failure(
      new Error(
        `secretOrPrivateKey must be a symmetric key when using ${header.alg}`
      )
    )
  } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
    if (secretOrPrivateKey?.type !== 'private') {
      return failure(
        new Error(
          `secretOrPrivateKey must be an asymmetric key when using ${header.alg}`
        )
      )
    }
    if (
      !options.allowInsecureKeySizes &&
      !header.alg.startsWith('ES') &&
      secretOrPrivateKey.asymmetricKeyDetails !== undefined && //KeyObject.asymmetricKeyDetails is supported in Node 15+
      (secretOrPrivateKey.asymmetricKeyDetails.modulusLength ?? 0) < 2048
    ) {
      return failure(
        new Error(
          `secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`
        )
      )
    }
  }

  if (typeof payload === 'undefined') {
    return failure(new Error('payload is required'))
  } else if (isObjectPayload) {
    try {
      validatePayload(payload)
    } catch (error) {
      return failure(error)
    }
    if (!options.mutatePayload) {
      payload = Object.assign({}, payload)
    }
  } else {
    const invalid_options = options_for_objects.filter(function (opt) {
      return typeof options[opt as keyof typeof options] !== 'undefined'
    })

    if (invalid_options.length > 0) {
      return failure(
        new Error(
          'invalid ' +
            invalid_options.join(',') +
            ' option for ' +
            typeof payload +
            ' payload'
        )
      )
    }
  }

  if (
    typeof payload === 'object' &&
    'exp' in payload &&
    typeof payload.exp !== 'undefined' &&
    typeof options.expiresIn !== 'undefined'
  ) {
    return failure(
      new Error(
        'Bad "options.expiresIn" option the payload already has an "exp" property.'
      )
    )
  }

  if (
    typeof payload === 'object' &&
    'nbf' in payload &&
    typeof payload.nbf !== 'undefined' &&
    typeof options.notBefore !== 'undefined'
  ) {
    return failure(
      new Error(
        'Bad "options.notBefore" option the payload already has an "nbf" property.'
      )
    )
  }

  try {
    validateOptions(options)
  } catch (error) {
    return failure(error)
  }

  if (!options.allowInvalidAsymmetricKeyTypes) {
    try {
      validateAsymmetricKey(
        header.alg as 'ES256' | 'ES384' | 'ES512',
        secretOrPrivateKey!
      )
    } catch (error) {
      return failure(error)
    }
  }

  const timestamp =
    typeof payload === 'object' &&
    'iat' in payload &&
    typeof payload.iat === 'number'
      ? payload.iat
      : Math.floor(Date.now() / 1000)

  if (options.noTimestamp && typeof payload === 'object' && 'iat' in payload) {
    delete payload.iat
  } else if (
    isObjectPayload &&
    typeof payload === 'object' &&
    'iat' in payload
  ) {
    payload.iat = timestamp
  }

  if (
    typeof options.notBefore !== 'undefined' &&
    typeof payload === 'object' &&
    'nbf' in payload
  ) {
    try {
      payload.nbf = timespan(options.notBefore, timestamp)
    } catch (err) {
      return failure(err)
    }
    if (typeof payload.nbf === 'undefined') {
      return failure(
        new Error(
          '"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        )
      )
    }
  }

  if (
    typeof options.expiresIn !== 'undefined' &&
    typeof payload === 'object' &&
    'exp' in payload
  ) {
    try {
      payload.exp = timespan(options.expiresIn, timestamp)
    } catch (err) {
      return failure(err)
    }
    if (typeof payload.exp === 'undefined') {
      return failure(
        new Error(
          '"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        )
      )
    }
  }

  Object.keys(options_to_payload).forEach(function (key) {
    const claim = options_to_payload[key as keyof typeof options_to_payload]
    if (
      typeof options[key as keyof typeof options_to_payload] !== 'undefined'
    ) {
      if (typeof payload[claim as keyof typeof payload] !== 'undefined') {
        return failure(
          new Error(
            'Bad "options.' +
              key +
              '" option. The payload already has an "' +
              claim +
              '" property.'
          )
        )
      }

      if (typeof payload === 'object') {
        // @ts-expect-error payload is an object
        payload[claim as keyof typeof payload] =
          options[key as keyof typeof options]
      }
    }
  })

  const encoding = options.encoding || 'utf8'

  if (typeof callback === 'function') {
    callback = callback && once(callback)

    jws
      .createSign({
        header: header,
        privateKey: secretOrPrivateKey,
        payload: payload,
        encoding: encoding
      })
      .once('error', callback)
      .once('done', function (signature: string) {
        // TODO: Remove in favor of the modulus length check before signing once node 15+ is the minimum supported version
        if (
          !options.allowInsecureKeySizes &&
          /^(?:RS|PS)/.test(header.alg) &&
          signature.length < 256
        ) {
          return callback?.(
            new Error(
              `secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`
            ),
            undefined
          )
        }
        callback?.(null, signature)
      })
  } else {
    let signature = jws.sign({
      header: header,
      payload: payload,
      secret: secretOrPrivateKey,
      encoding: encoding
    })
    // TODO: Remove in favor of the modulus length check before signing once node 15+ is the minimum supported version
    if (
      !options.allowInsecureKeySizes &&
      /^(?:RS|PS)/.test(header.alg) &&
      signature.length < 256
    ) {
      throw new Error(
        `secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`
      )
    }
    return signature
  }
}
