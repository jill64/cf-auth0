export default class ArgumentError extends Error {
  constructor(message: string) {
    super()
    Error.call(this, message)
    Error.captureStackTrace(this, this.constructor)
    this.name = 'ArgumentError'
    this.message = message
  }
}
