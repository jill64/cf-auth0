import SignStream from './lib/sign-stream.js'
import VerifyStream from './lib/verify-stream.js'

const ALGORITHMS = [
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

const sign = SignStream.sign
const verify = VerifyStream.verify
const decode = VerifyStream.decode
const isValid = VerifyStream.isValid

// @ts-expect-error WARNING: Unknown type
const createSign = function createSign(opts) {
  // @ts-expect-error WARNING: Unknown type
  return new SignStream(opts)
}

// @ts-expect-error WARNING: Unknown type
const createVerify = function createVerify(opts) {
  // @ts-expect-error WARNING: Unknown type
  return new VerifyStream(opts)
}

export default {
  ALGORITHMS,
  createSign,
  createVerify,
  decode,
  isValid,
  sign,
  verify
}
