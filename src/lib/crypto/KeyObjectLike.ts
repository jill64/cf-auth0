import type {
  AsymmetricKeyDetails,
  JwkKeyExportOptions,
  KeyExportOptions
} from 'node:crypto'

const kKeyType = Symbol('kKeyType')
const kHandle = Symbol('kHandle')

class KeyObjectLike {
  asymmetricKeyType?: KeyType
  asymmetricKeySize?: number
  asymmetricKeyDetails?: AsymmetricKeyDetails
  symmetricKeySize?: number

  private constructor(key: CryptoKey) {
    const { type } = key

    if (type !== 'secret' && type !== 'public' && type !== 'private')
      throw new Error(`ERR_INVALID_ARG_VALUE: type ${type}`)

    // @ts-expect-error TODO
    this[kKeyType] = type

    Object.defineProperty(this, kHandle, {
      // @ts-expect-error TODO
      __proto__: null,
      // TODO
      value: null,
      // value: handle
      enumerable: false,
      configurable: false,
      writable: false
    })
  }

  get type() {
    // @ts-expect-error TODO
    return this[kKeyType]
  }

  static from = (key: CryptoKey) => new KeyObjectLike(key)

  equals(otherKeyObject: KeyObjectLike) {
    try {
      Object.keys(otherKeyObject).forEach((key) => {
        // @ts-expect-error TODO
        if (this[key] !== otherKeyObject[key]) {
          throw new Error('Key objects are not equal')
        }
      })

      return (
        otherKeyObject.type === this.type &&
        // @ts-expect-error TODO
        this[kHandle].equals(otherKeyObject[kHandle])
      )
    } catch {
      return false
    }
  }

  exports(options: KeyExportOptions<'pem'>): string | Buffer
  exports(options?: KeyExportOptions<'der'>): Buffer
  exports(options?: JwkKeyExportOptions): JsonWebKey

  exports(
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

Object.defineProperties(KeyObjectLike.prototype, {
  [Symbol.toStringTag]: {
    // @ts-expect-error TODO
    __proto__: null,
    configurable: true,
    value: 'KeyObject'
  }
})

export { KeyObjectLike }
