import type {
  AsymmetricKeyDetails,
  JwkKeyExportOptions,
  KeyExportOptions
} from 'node:crypto'

class KeyObject {
  asymmetricKeyType?: KeyType
  asymmetricKeySize?: number
  asymmetricKeyDetails?: AsymmetricKeyDetails
  symmetricKeySize?: number

  private _key

  private constructor(key: CryptoKey) {
    this._key = key
  }

  get type() {
    return this._key.type
  }

  static from = (key: CryptoKey) => new KeyObject(key)

  equals(otherKeyObject: KeyObject) {
    try {
      Object.keys(otherKeyObject).forEach((key) => {
        // @ts-expect-error TODO
        if (this[key] !== otherKeyObject[key]) {
          throw new Error('Key objects are not equal')
        }
      })

      return true
    } catch {
      return false
    }
  }

  export(options: KeyExportOptions<'pem'>): string | Buffer
  export(options?: KeyExportOptions<'der'>): Buffer
  export(options?: JwkKeyExportOptions): JsonWebKey

  export(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    options?:
      | KeyExportOptions<'pem'>
      | KeyExportOptions<'der'>
      | JwkKeyExportOptions
  ): string | Buffer | JsonWebKey {
    // TODO
    return ''
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
