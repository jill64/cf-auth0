import SignStream from './lib/sign-stream.js'
import VerifyStream from './lib/verify-stream.js'

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
export const verify = VerifyStream.verify
export const decode = VerifyStream.decode
export const isValid = VerifyStream.isValid
// @ts-expect-error TODO
export const createSign = function createSign(opts) {
  // @ts-expect-error TODO
  return new SignStream(opts)
}
// @ts-expect-error TODO
export const createVerify = function createVerify(opts) {
  // @ts-expect-error TODO
  return new VerifyStream(opts)
}
