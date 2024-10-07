export default class SigningKeyNotFoundError extends Error {
  constructor(message: string) {
    super()
    Error.call(this, message)
    Error.captureStackTrace(this, this.constructor)
    this.name = 'SigningKeyNotFoundError'
    this.message = message
  }
}
