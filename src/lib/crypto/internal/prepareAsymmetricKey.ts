import type { createPrivateKey, createPublicKey } from 'node:crypto'
import { isAnyArrayBuffer, isArrayBufferView } from 'node:util/types'
import { isCryptoKey } from '../isCryptoKey.js'
import { isKeyObjectLike } from '../isKeyObjectLike.js'
import { KeyObjectLike } from '../KeyObjectLike.js'
import { getArrayBufferOrView } from './getArrayBufferOrView.js'
import { getKeyObjectHandle } from './getKeyObjectHandle.js'
import { getKeyObjectHandleFromJwk } from './getKeyObjectHandleFromJwk.js'
import { getKeyTypes } from './getKeyTypes.js'
import { KEYS } from './Keys.js'
import { KIC } from './KIC.js'
import { parseKeyEncoding } from './parseKeyEncoding.js'
import { validateObject } from './validateObject.js'

const isStringOrBuffer = (val: unknown) =>
  typeof val === 'string' || isArrayBufferView(val) || isAnyArrayBuffer(val)

const kKeyObject = Symbol('kKeyObject')

export const prepareAsymmetricKey = (
  key:
    | Parameters<typeof createPrivateKey>[0]
    | Parameters<typeof createPublicKey>[0]
    | KeyObjectLike,
  ctx: KIC
) => {
  if (isKeyObjectLike(key)) {
    // Best case: A key object, as simple as that.
    return { data: getKeyObjectHandle(key, ctx) }
  } else if (isCryptoKey(key)) {
    // @ts-expect-error TODO
    return { data: getKeyObjectHandle(key[kKeyObject], ctx) }
  } else if (isStringOrBuffer(key)) {
    // Expect PEM by default, mostly for backward compatibility.
    return {
      format: KEYS.kKeyFormatPEM,
      data: getArrayBufferOrView(key, 'key')
    }
  } else if (typeof key === 'object') {
    // @ts-expect-error TODO
    const { key: data, encoding, format } = key

    // The 'key' property can be a KeyObject as well to allow specifying
    // additional options such as padding along with the key.
    if (isKeyObjectLike(data)) return { data: getKeyObjectHandle(data, ctx) }
    else if (isCryptoKey(data))
      // @ts-expect-error TODO
      return { data: getKeyObjectHandle(data[kKeyObject], ctx) }
    else if (format === 'jwk') {
      validateObject(data, 'key.key')
      return { data: getKeyObjectHandleFromJwk(data, ctx), format: 'jwk' }
    }

    // Either PEM or DER using PKCS#1 or SPKI.
    if (!isStringOrBuffer(data)) {
      throw new Error(
        `ERR_INVALID_ARG_TYPE: key.key ${getKeyTypes(
          ctx !== 'kCreatePrivate'
        )} but ${data}`
      )
    }

    const isPublic =
      ctx === 'kConsumePrivate' || ctx === 'kCreatePrivate' ? false : undefined

    return {
      data: getArrayBufferOrView(data, 'key', encoding),
      ...parseKeyEncoding(key, undefined, isPublic)
    }
  }

  throw new Error(
    `ERR_INVALID_ARG_TYPE: key ${getKeyTypes(
      ctx !== 'kCreatePrivate'
    )} but ${key}`
  )
}
