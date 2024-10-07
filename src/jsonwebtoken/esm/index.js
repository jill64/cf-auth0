import decode from './decode.js'
import verify from './verify.js'
import sign from './sign.js'
import JsonWebTokenError from './lib/JsonWebTokenError.js'
import NotBeforeError from './lib/NotBeforeError.js'
import TokenExpiredError from './lib/TokenExpiredError.js'

export default {
  decode,
  verify,
  sign,
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError
}
