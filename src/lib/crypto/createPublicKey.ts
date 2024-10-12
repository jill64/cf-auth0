import { Buffer } from 'node:buffer'
import type {
  createPublicKey as CreatePublicKey,
  KeyObject as KeyObjectType
} from 'node:crypto'
import { base64UrlDecode } from './base64UrlDecode.js'
import { subtle } from './index.js'
import { prepareAsymmetricKey } from './internal/prepareAsymmetricKey/index.js'
import { isAsymmetricKeyType } from './isAsymmetricKeyType.js'
import { KeyObject } from './KeyObject.js'

export const createPublicKey = async (
  key: Parameters<typeof CreatePublicKey>[0]
): Promise<KeyObjectType> => {
  const result = prepareAsymmetricKey(key, 'kCreatePublic')

  const { format, data } = result
  const jwk = 'jwk' in data ? data.jwk : null

  if (format === 'jwk') {
    console.log(`format: jwk;`)

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

    const asymmetricKeyType = jwk.kty?.toLowerCase()

    if (!isAsymmetricKeyType(asymmetricKeyType)) {
      throw new TypeError('ERR_INVALID_ARG_VALUE: key.jwk.kty')
    }

    const spki = await subtle.exportKey('spki', key)
    const asymmetricKeySize = spki.byteLength

    if (!jwk.n) {
      throw new TypeError('ERR_MISSING_ARG: key.jwk.n')
    }

    const res = KeyObject.from(key, {
      asymmetricKeyType,
      asymmetricKeySize,
      asymmetricKeyDetails: {
        modulusLength: jwk.n.length * 8,
        publicExponent: BigInt(base64UrlDecode(jwk.e ?? ''))
      },
      preExportedKeys: {
        pkcs1: {
          pem: '',
          der: Buffer.alloc(0)
        },
        spki: {
          pem: Buffer.from(spki),
          der: Buffer.from(spki)
        },
        pkcs8: {
          pem: '',
          der: Buffer.from('')
        },
        sec1: {
          pem: '',
          der: Buffer.alloc(0)
        },
        jwk
      }
    })

    // @ts-expect-error TODO
    return res
  }

  if (format === 'spki') {
    console.log(`format: spki; data: ${data};`)
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
    const spki = await subtle.exportKey('spki', key)
    const jwk = await subtle.exportKey('jwk', key)

    const res = KeyObject.from(key, {
      asymmetricKeyType: 'rsa',
      asymmetricKeySize: spki.byteLength,
      asymmetricKeyDetails: {
        modulusLength: 2048,
        publicExponent: BigInt(65537)
      },
      preExportedKeys: {
        pkcs1: {
          pem: '',
          der: Buffer.alloc(0)
        },
        spki: {
          pem: Buffer.from(spki),
          der: Buffer.from(spki)
        },
        pkcs8: {
          pem: '',
          der: Buffer.from('')
        },
        sec1: {
          pem: '',
          der: Buffer.alloc(0)
        },
        jwk
      }
    })

    // @ts-expect-error TODO
    return res
  }

  throw new TypeError('Unsupported key format')
}
