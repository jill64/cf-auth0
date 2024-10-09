import { isCryptoKey } from '../../../../../lib/crypto/index.js'
import type { KeyLike } from '../../types.d.ts'

export default (key: unknown): key is KeyLike => {
  if (isCryptoKey(key)) {
    return true
  }

  // @ts-expect-error TODO
  return key?.[Symbol.toStringTag] === 'KeyObject'
}

export const types = ['CryptoKey']
