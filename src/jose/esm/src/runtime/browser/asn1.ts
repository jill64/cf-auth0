import { isCryptoKey, subtle } from '../../../../../lib/crypto/index.js'
import formatPEM from '../../lib/format_pem.js'
import invalidKeyInput from '../../lib/invalid_key_input.js'
import type { PEMExportFunction } from '../interfaces.d.ts'
import { encodeBase64 } from './base64url.js'
import { types } from './is_key_like.js'

const genericExport = async (
  keyType: 'private' | 'public',
  keyFormat: 'spki' | 'pkcs8',
  key: unknown
) => {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, ...types))
  }

  if (!key.extractable) {
    throw new TypeError('CryptoKey is not extractable')
  }

  if (key.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`)
  }

  return formatPEM(
    encodeBase64(new Uint8Array(await subtle.exportKey(keyFormat, key))),
    `${keyType.toUpperCase()} KEY`
  )
}

export const toSPKI: PEMExportFunction = (key) => {
  return genericExport('public', 'spki', key)
}
