import SignStream from './lib/sign-stream.js'
export { verify, decode, isValid } from './lib/verify-stream.js'

export const ALGORITHMS = [
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512'
]

export const sign = SignStream.sign
// @ts-expect-error TODO
export const createSign = function createSign(opts) {
  // @ts-expect-error TODO
  return new SignStream(opts)
}
