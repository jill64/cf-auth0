import type { createPrivateKey, createPublicKey } from 'node:crypto'
import { isAnyArrayBuffer, isArrayBufferView } from 'node:util/types'
import { isCryptoKey } from '../../isCryptoKey.js'
import { isKeyObject } from '../../isKeyObject.js'
import { KIC } from '../utils/KIC.js'
import { getArrayBufferOrView } from '../utils/parseKeyEncoding/getArrayBufferOrView.js'
import { parseKeyEncoding } from '../utils/parseKeyEncoding/index.js'
import { validateObject } from '../utils/validateObject.js'
import { getKeyObjectHandle } from './getKeyObjectHandle.js'
import { getKeyObjectHandleFromJwk } from './getKeyObjectHandleFromJwk.js'
import { getKeyTypes } from './getKeyTypes.js'

const isStringOrBuffer = (val: unknown) =>
  typeof val === 'string' || isArrayBufferView(val) || isAnyArrayBuffer(val)

const kKeyObject = Symbol('kKeyObject')

function pemToArrayBuffer(pem: string) {
  const b64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\n/g, '')
  const binary = atob(b64)
  const len = binary.length
  const buffer = new ArrayBuffer(len)
  const view = new Uint8Array(buffer)
  for (let i = 0; i < len; i++) {
    view[i] = binary.charCodeAt(i)
  }
  return buffer
}

export const prepareAsymmetricKey = (
  key:
    | Parameters<typeof createPrivateKey>[0]
    | Parameters<typeof createPublicKey>[0],
  ctx: KIC
) => {
  if (isKeyObject(key)) {
    // Best case: A key object, as simple as that.
    return { data: getKeyObjectHandle(key, ctx) }
  } else if (isCryptoKey(key)) {
    // @ts-expect-error TODO
    return { data: getKeyObjectHandle(key[kKeyObject], ctx) }
  } else if (isStringOrBuffer(key)) {
    // Expect PEM by default, mostly for backward compatibility.
    console.log('key:', key)
    console.log('data', typeof key === 'string' ? pemToArrayBuffer(key) : key)
    return {
      format: 'spki' as const,
      data: typeof key === 'string' ? pemToArrayBuffer(key) : key
    }
  } else if (typeof key === 'object') {
    const data = 'key' in key ? key.key : null
    const encoding = 'encoding' in key ? key.encoding : null
    const format = 'format' in key ? key.format : null

    // The 'key' property can be a KeyObject as well to allow specifying
    // additional options such as padding along with the key.
    if (isKeyObject(data)) {
      return { data: getKeyObjectHandle(data, ctx) }
    } else if (isCryptoKey(data)) {
      // @ts-expect-error TODO
      return { data: getKeyObjectHandle(data[kKeyObject], ctx) }
    } else if (format === 'jwk') {
      validateObject(data, 'key.key')
      return {
        data: getKeyObjectHandleFromJwk(data as JsonWebKey, ctx),
        format: 'jwk' as const
      }
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
      data: getArrayBufferOrView(data, 'key', encoding as BufferEncoding),
      ...parseKeyEncoding(key, undefined, isPublic)
    }
  }

  throw new Error(
    `ERR_INVALID_ARG_TYPE: key ${getKeyTypes(
      ctx !== 'kCreatePrivate'
    )} but ${key}`
  )
}
