import crypto from 'node:crypto'

export const isCryptoKey = (key: unknown): key is CryptoKey =>
  key instanceof CryptoKey

const { createSecretKey, subtle, createHmac } = crypto

export { createSecretKey, subtle, createHmac }
