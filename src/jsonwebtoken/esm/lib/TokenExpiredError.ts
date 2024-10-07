import JsonWebTokenError from './JsonWebTokenError.js'

export default class TokenExpiredError extends JsonWebTokenError {
  expiredAt

  constructor(message: string, expiredAt: Date) {
    super(message)
    JsonWebTokenError.call(this, message)
    this.name = 'TokenExpiredError'
    this.expiredAt = expiredAt
  }
}
