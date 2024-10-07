import JsonWebTokenError from './JsonWebTokenError.js'

// @ts-expect-error TODO
function TokenExpiredError(message, expiredAt) {
  JsonWebTokenError.call(this, message)
  this.name = 'TokenExpiredError'
  this.expiredAt = expiredAt
}

TokenExpiredError.prototype = Object.create(JsonWebTokenError.prototype)

TokenExpiredError.prototype.constructor = TokenExpiredError

export default TokenExpiredError
