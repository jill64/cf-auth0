import type {
  createPrivateKey as CreatePrivateKey,
  KeyObject as KeyObjectType
} from 'node:crypto'
import { subtle } from './index.js'
import { prepareAsymmetricKey } from './internal/prepareAsymmetricKey.js'
import { KeyObject } from './KeyObject.js'

export const createPrivateKey = async (
  key: Parameters<typeof CreatePrivateKey>[0]
): Promise<KeyObjectType> => {
  const result = prepareAsymmetricKey(key, 'kCreatePrivate')

  const { format, data } = result
  const jwk = 'jwk' in data ? data.jwk : null

  if (format === 'jwk') {
    if (jwk === null) {
      throw new TypeError('ERR_MISSING_VALUE: key.jwk')
    }

    if (!jwk.alg) {
      throw new TypeError('ERR_MISSING_ARG: key.jwk.alg')
    }

    const key = await subtle.importKey(
      'jwk',
      jwk,
      jwk.alg,
      true,
      (jwk.key_ops as KeyUsage[]) ?? []
    )

    return KeyObject.from(key) as KeyObjectType
  }

  throw new TypeError('Unsupported key format')
}
