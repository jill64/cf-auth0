import type {
  JwkKeyExportOptions,
  KeyExportOptions,
  KeyObject as KeyObjectType
} from 'node:crypto'
import type { AsymmetricKeyDetails } from './AsymmetricKeyDetails.js'
import type { AsymmetricKeyType } from './AsymmetricKeyType.js'

type KeyObjectParams = (
  | {
      asymmetricKeyType: AsymmetricKeyType
      asymmetricKeySize: KeyObjectType['asymmetricKeySize']
      asymmetricKeyDetails: AsymmetricKeyDetails
    }
  | {
      symmetricKeySize: KeyObjectType['symmetricKeySize']
    }
) & {
  preExportedKeys: {
    pkcs1: {
      pem: string | Buffer
      der: Buffer
    }
    spki: {
      pem: string | Buffer
      der: Buffer
    }
    pkcs8: {
      pem: string | Buffer
      der: Buffer
    }
    sec1: {
      pem: string | Buffer
      der: Buffer
    }
    jwk: JsonWebKey
  }
}

const kKeyType = Symbol('kKeyType')
const kHandle = Symbol('kHandle')

class KeyObject implements KeyObjectType {
  type: KeyType
  asymmetricKeyType?: AsymmetricKeyType
  asymmetricKeySize?: KeyObjectType['asymmetricKeySize']
  asymmetricKeyDetails?: KeyObjectType['asymmetricKeyDetails']
  symmetricKeySize?: KeyObjectType['symmetricKeySize']
  private params

  private constructor(key: CryptoKey, params: KeyObjectParams) {
    this.type = key.type
    this.params = params

    // @ts-expect-error TODO
    this[kKeyType] = key.type

    if ('asymmetricKeyType' in params) {
      this.asymmetricKeyType = params.asymmetricKeyType
      this.asymmetricKeySize = params.asymmetricKeySize
      this.asymmetricKeyDetails = params.asymmetricKeyDetails
    } else {
      this.symmetricKeySize = params.symmetricKeySize
    }

    console.log('CryptoKey key: ', key)
    console.log('KeyObject params: ', params)

    Object.defineProperty(this, kHandle, {
      // @ts-expect-error TODO
      __proto__: null,
      value: null,
      // TODO
      // value: handle,
      enumerable: false,
      configurable: false,
      writable: false
    })
  }

  static from = (key: CryptoKey, params: KeyObjectParams) =>
    new KeyObject(key, params)

  equals(otherKeyObject: KeyObjectType) {
    try {
      Object.keys(otherKeyObject).forEach((key) => {
        // @ts-expect-error TODO
        if (this[key] !== otherKeyObject[key]) {
          throw new Error('KeyObjects are not equal')
        }
      })

      return true
    } catch {
      return false
    }
  }

  // @ts-expect-error TODO
  export(options: KeyExportOptions<'pem'>): string | Buffer
  // @ts-expect-error TODO
  export(options?: KeyExportOptions<'der'>): Buffer
  // @ts-expect-error TODO
  export(options?: JwkKeyExportOptions): JsonWebKey

  // @ts-expect-error TODO
  export(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    options?:
      | KeyExportOptions<'pem'>
      | KeyExportOptions<'der'>
      | JwkKeyExportOptions
  ): string | Buffer | JsonWebKey {
    if (options?.format === 'jwk' && this.params) {
      return this.params.preExportedKeys.jwk
    }

    if (options?.format === 'pem') {
      switch (options.type) {
        case 'spki':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.spki.pem
          }
          break
        case 'pkcs8':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.pkcs8.pem
          }
          break
        case 'sec1':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.sec1.pem
          }
          break
        case 'pkcs1':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.pkcs1.pem
          }
        default:
          throw new Error('Unsupported export type')
      }
    }

    if (options?.format === 'der') {
      switch (options.type) {
        case 'spki':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.spki.der
          }
          break
        case 'pkcs8':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.pkcs8.der
          }
          break
        case 'sec1':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.sec1.der
          }
          break
        case 'pkcs1':
          if (this.params.preExportedKeys) {
            return this.params.preExportedKeys.pkcs1.der
          }
        default:
          throw new Error('Unsupported export type')
      }
    }

    throw new Error('Unsupported export format')
  }
}

Object.defineProperties(KeyObject.prototype, {
  [Symbol.toStringTag]: {
    // @ts-expect-error TODO
    __proto__: null,
    configurable: true,
    value: 'KeyObject'
  }
})

export { KeyObject }
