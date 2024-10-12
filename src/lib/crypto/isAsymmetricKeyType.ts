import { AsymmetricKeyType } from './AsymmetricKeyType.js'

export const isAsymmetricKeyType = (val: unknown): val is AsymmetricKeyType =>
  typeof val === 'string' &&
  [
    'rsa',
    'rsa-pss',
    'dsa',
    'ec',
    'ed25519',
    'ed448',
    'x25519',
    'x448'
  ].includes(val)
