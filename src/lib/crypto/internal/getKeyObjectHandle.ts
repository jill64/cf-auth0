import type { KeyObject } from 'node:crypto'
import { KIC } from './utils/KIC.js'

export const getKeyObjectHandle = (key: KeyObject, ctx: KIC) => {
  if (ctx === 'kCreatePrivate') {
    throw new Error(
      `ERR_INVALID_ARG_TYPE: key must be ['string', 'ArrayBuffer', 'Buffer', 'TypedArray', 'DataView'] but ${key}`
    )
  }

  if (key.type !== 'private') {
    if (ctx === 'kConsumePrivate' || ctx === 'kCreatePublic')
      throw new Error(`ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE: ${key.type} private`)
    if (key.type !== 'public') {
      throw new Error(
        `ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE: ${key.type} private or public`
      )
    }
  }

  return key
}
