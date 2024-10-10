import type {
  JsonWebKeyInput,
  KeyObject,
  PrivateKeyInput,
  PublicKeyInput
} from 'node:crypto'
import { getArrayBufferOrView } from './getArrayBufferOrView.js'
import { parseKeyFormatAndType } from './parseKeyFormatAndType.js'
import { isStringOrBuffer } from './utils/isStringOrBuffer.js'
import { KEYS } from './utils/KEYS.js'
import { option } from './utils/option.js'
import { validateObject } from './utils/validateObject.js'

const encodingNames = {
  [KEYS.kKeyEncodingPKCS1]: 'pkcs1',
  [KEYS.kKeyEncodingPKCS8]: 'pkcs8',
  [KEYS.kKeyEncodingSPKI]: 'spki',
  [KEYS.kKeyEncodingSEC1]: 'sec1'
}

export const parseKeyEncoding = (
  enc: PrivateKeyInput | JsonWebKeyInput | PublicKeyInput | KeyObject,
  keyType?: string,
  isPublic?: boolean,
  objName?: string
) => {
  validateObject(enc, 'options')

  const isInput = keyType === undefined

  const { format, type } = parseKeyFormatAndType(
    enc,
    keyType,
    isPublic,
    objName
  )

  let cipher, passphrase, encoding
  if (isPublic !== true) {
    // @ts-expect-error TODO
    ;({ cipher, passphrase, encoding } = enc)

    if (!isInput) {
      if (cipher != null) {
        if (typeof cipher !== 'string')
          throw new Error(
            `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS: ${option(
              'cipher',
              objName
            )} ${cipher}`
          )
        if (
          format === KEYS.kKeyFormatDER &&
          (type === KEYS.kKeyEncodingPKCS1 || type === KEYS.kKeyEncodingSEC1)
        ) {
          throw new Error(
            `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS: ${encodingNames[type]} does not support encryption`
          )
        }
      } else if (passphrase !== undefined) {
        throw new Error(
          `ERR_CRYPTO_INCOMPATIBLE_KEY_OPTIONS: ${option(
            'cipher',
            objName
          )} ${cipher}`
        )
      }
    }

    if (
      (isInput && passphrase !== undefined && !isStringOrBuffer(passphrase)) ||
      (!isInput && cipher != null && !isStringOrBuffer(passphrase))
    ) {
      throw new Error(
        `ERR_INVALID_ARG_VALUE: ${option('passphrase', objName)} ${passphrase}`
      )
    }
  }

  if (passphrase !== undefined)
    passphrase = getArrayBufferOrView(passphrase, 'key.passphrase', encoding)

  return { format, type, cipher, passphrase }
}
