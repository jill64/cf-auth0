import JsonWebTokenError from './JsonWebTokenError.js'

export class TokenExpiredError extends JsonWebTokenError {
  expiredAt

  constructor(message: string, expiredAt: Date) {
    super(message)
    this.name = 'TokenExpiredError'
    this.expiredAt = expiredAt
  }
}

export default TokenExpiredError
