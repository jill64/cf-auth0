import { isCryptoKey } from '../../../../../lib/crypto/index.js'
import { isKeyObject } from '../../../../../lib/crypto/isKeyObject.js'
import type { KeyLike } from '../../types.d.ts'

export default (key: unknown): key is KeyLike => {
  if (isCryptoKey(key)) {
    return true
  }

  return isKeyObject(key)
}

export const types = ['CryptoKey']
