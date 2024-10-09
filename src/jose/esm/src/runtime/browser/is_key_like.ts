import type { KeyLike } from '../../types.d.ts'
import { isCryptoKey } from '../../../../../lib/crypto.js'

export default (key: unknown): key is KeyLike => {
  if (isCryptoKey(key)) {
    return true
  }

  // @ts-expect-error TODO
  return key?.[Symbol.toStringTag] === 'KeyObject'
}

export const types = ['CryptoKey']
