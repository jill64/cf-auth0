import type {
  AsymmetricKeyDetails,
  KeyObjectType,
  KeyExportOptions,
  JwkKeyExportOptions
} from 'node:crypto'

export class KeyObject {
  type: KeyObjectType
  asymmetricKeyType?: KeyType | undefined
  asymmetricKeySize?: number | undefined
  asymmetricKeyDetails?: AsymmetricKeyDetails | undefined
  symmetricKeySize?: number | undefined

  static from(key: CryptoKey): KeyObject

  export(options: KeyExportOptions<'pem'>): string | Buffer
  export(options?: KeyExportOptions<'der'>): Buffer
  export(options?: JwkKeyExportOptions): JsonWebKey

  equals(otherKeyObject: KeyObject): boolean
}
