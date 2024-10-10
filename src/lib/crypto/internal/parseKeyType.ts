import type { KeyObjectType } from 'node:crypto'
import { KEYS } from './utils/KEYS.js'

export const parseKeyType = (
  typeStr: 'pkcs1' | 'spki' | KeyObjectType | 'pkcs8' | 'sec1' | undefined,
  required: boolean,
  keyType?: string,
  isPublic?: boolean,
  optionName?: string
) => {
  if (typeStr === undefined && !required) {
    return undefined
  } else if (typeStr === 'pkcs1') {
    if (keyType !== undefined && keyType !== 'rsa') {
      throw new Error(
        `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS: ${typeStr} can only be used for RSA keys`
      )
    }
    return KEYS.kKeyEncodingPKCS1
  } else if (typeStr === 'spki' && isPublic !== false) {
    return KEYS.kKeyEncodingSPKI
  } else if (typeStr === 'pkcs8' && isPublic !== true) {
    return KEYS.kKeyEncodingPKCS8
  } else if (typeStr === 'sec1' && isPublic !== true) {
    if (keyType !== undefined && keyType !== 'ec') {
      throw new Error(
        `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS: ${typeStr} can only be used for EC keys`
      )
    }

    return KEYS.kKeyEncodingSEC1
  }

  throw new Error(`ERR_INVALID_ARG_VALUE: ${optionName} ${typeStr}`)
}
