// import type {
//   JwkKeyExportOptions,
//   KeyExportOptions,
//   KeyObject as KeyObjectType
// } from 'node:crypto'

// const kHandle = Symbol('kHandle')

// class KeyObject {
//   type: KeyType
//   asymmetricKeyType?: KeyObjectType['asymmetricKeyType']
//   asymmetricKeySize?: KeyObjectType['asymmetricKeySize']
//   asymmetricKeyDetails?: KeyObjectType['asymmetricKeyDetails']
//   symmetricKeySize?: KeyObjectType['symmetricKeySize']

//   private constructor(key: CryptoKey) {
//     const { type } = key

//     if (type !== 'secret' && type !== 'public' && type !== 'private')
//       throw new Error(`ERR_INVALID_ARG_VALUE: type ${type}`)

//     this.type = type

//     Object.defineProperty(this, kHandle, {
//       // @ts-expect-error TODO
//       __proto__: null,
//       // TODO
//       value: null,
//       // value: handle
//       enumerable: false,
//       configurable: false,
//       writable: false
//     })
//   }

//   static from = (key: CryptoKey) => new KeyObject(key)

//   equals(otherKeyObject: KeyObjectType) {
//     try {
//       Object.keys(otherKeyObject).forEach((key) => {
//         // @ts-expect-error TODO
//         if (this[key] !== otherKeyObject[key]) {
//           throw new Error('Key objects are not equal')
//         }
//       })

//       return (
//         otherKeyObject.type === this.type &&
//         // @ts-expect-error TODO
//         this[kHandle].equals(otherKeyObject[kHandle])
//       )
//     } catch {
//       return false
//     }
//   }

//   export(options: KeyExportOptions<'pem'>): string | Buffer
//   export(options?: KeyExportOptions<'der'>): Buffer
//   export(options?: JwkKeyExportOptions): JsonWebKey

//   export(
//     // eslint-disable-next-line @typescript-eslint/no-unused-vars
//     options?:
//       | KeyExportOptions<'pem'>
//       | KeyExportOptions<'der'>
//       | JwkKeyExportOptions
//   ): string | Buffer | JsonWebKey {
//     // TODO
//     return ''
//   }
// }

// Object.defineProperties(KeyObject.prototype, {
//   [Symbol.toStringTag]: {
//     // @ts-expect-error TODO
//     __proto__: null,
//     configurable: true,
//     value: 'KeyObject'
//   }
// })

// export { KeyObject }

export { KeyObject } from 'node:crypto'
