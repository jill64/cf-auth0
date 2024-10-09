import crypto from 'node:crypto'

export default crypto.webcrypto

export const isCryptoKey = (key: unknown): key is CryptoKey =>
  key instanceof CryptoKey
