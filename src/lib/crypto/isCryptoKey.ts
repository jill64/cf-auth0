export const isCryptoKey = (key: unknown): key is CryptoKey =>
  // @ts-expect-error TODO
  key instanceof CryptoKey
