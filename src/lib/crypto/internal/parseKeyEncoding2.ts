import { parsePrivateKeyEncoding } from './parsePrivateKeyEncoding.js'
import { parsePublicKeyEncoding } from './parsePublicKeyEncoding.js'
import { kEmptyObject } from './utils/kEmptyObject.js'

export const parseKeyEncoding2 = (
  keyType: Parameters<typeof parsePublicKeyEncoding>[1],
  options:
    | typeof kEmptyObject
    | {
        publicKeyEncoding?: Parameters<typeof parsePublicKeyEncoding>[0]
        privateKeyEncoding?: Parameters<typeof parsePrivateKeyEncoding>[0]
      } = kEmptyObject
) => {
  const publicKeyEncoding =
    'publicKeyEncoding' in options ? options.publicKeyEncoding : null
  const privateKeyEncoding =
    'privateKeyEncoding' in options ? options.privateKeyEncoding : null

  let publicFormat
  let publicType

  if (publicKeyEncoding == null) {
    publicFormat = publicType = undefined
  } else if (typeof publicKeyEncoding === 'object') {
    ;({ format: publicFormat, type: publicType } = parsePublicKeyEncoding(
      publicKeyEncoding,
      keyType,
      'publicKeyEncoding'
    ))
  } else {
    throw new Error(
      `ERR_INVALID_ARG_VALUE: options.publicKeyEncoding ${publicKeyEncoding}`
    )
  }

  let privateFormat
  let privateType
  let cipher
  let passphrase

  if (privateKeyEncoding == null) {
    privateFormat = undefined
    privateType = undefined
  } else if (typeof privateKeyEncoding === 'object') {
    ;({
      format: privateFormat,
      type: privateType,
      cipher,
      passphrase
    } = parsePrivateKeyEncoding(
      privateKeyEncoding,
      keyType,
      'privateKeyEncoding'
    ))
  } else {
    throw new Error(
      `ERR_INVALID_ARG_VALUE: options.privateKeyEncoding ${privateKeyEncoding}`
    )
  }

  return [
    publicFormat,
    publicType,
    privateFormat,
    privateType,
    cipher,
    passphrase
  ]
}
