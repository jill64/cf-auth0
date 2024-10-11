import type {
  createPublicKey as CreatePublicKey,
  KeyObject as KeyObjectType
} from 'node:crypto'
import { subtle } from './index.js'
import { prepareAsymmetricKey } from './internal/prepareAsymmetricKey/index.js'
import { KeyObject } from './KeyObject.js'

export const createPublicKey = async (
  key: Parameters<typeof CreatePublicKey>[0]
): Promise<KeyObjectType> => {
  const result = prepareAsymmetricKey(key, 'kCreatePublic')

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
      (jwk.key_ops ?? []) as KeyUsage[]
    )

    return KeyObject.from(key) as KeyObjectType
  }

  if (format === 'spki') {
    const key = await subtle.importKey(
      'spki',
      data,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['verify']
    )

    return KeyObject.from(key) as KeyObjectType
  }

  throw new TypeError('Unsupported key format')
}
