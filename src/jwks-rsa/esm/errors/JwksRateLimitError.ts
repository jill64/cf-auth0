export default class JwksRateLimitError extends Error {
  constructor(message: string) {
    super()
    Error.call(this, message)
    Error.captureStackTrace(this, this.constructor)
    this.name = 'JwksRateLimitError'
    this.message = message
  }
}
