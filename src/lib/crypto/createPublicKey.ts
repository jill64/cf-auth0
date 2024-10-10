import type { createPublicKey as CreatePublicKey } from 'node:crypto'
import { KeyObjectLike } from './KeyObjectLike.js'
import { subtle } from './index.js'
import { prepareAsymmetricKey } from './internal/prepareAsymmetricKey.js'

export const createPublicKey = async (
  key: Parameters<typeof CreatePublicKey>[0] | KeyObjectLike
): Promise<KeyObjectLike> => {
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
      (jwk.key_ops as KeyUsage[]) ?? []
    )

    return KeyObjectLike.from(key)
  }

  throw new TypeError('Unsupported key format')
}
