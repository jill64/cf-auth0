import type {
  AsymmetricKeyDetails,
  JwkKeyExportOptions,
  KeyExportOptions
} from 'node:crypto'
import { KeyObject } from './KeyObject.js'

export type KeyObjectLike = {
  asymmetricKeyType?: KeyType
  asymmetricKeySize?: number
  asymmetricKeyDetails?: AsymmetricKeyDetails
  symmetricKeySize?: number
  type: KeyType
  from: (key: CryptoKey) => KeyObject
  equals(otherKeyObject: KeyObject): boolean
  export(options: KeyExportOptions<'pem'>): string | Buffer
  export(options?: KeyExportOptions<'der'>): Buffer
  export(options?: JwkKeyExportOptions): JsonWebKey
}
