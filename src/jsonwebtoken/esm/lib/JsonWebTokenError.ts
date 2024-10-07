export default class JsonWebTokenError extends Error {
  inner

  constructor(message: string, error?: Error) {
    super()
    Error.call(this, message)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
    this.name = 'JsonWebTokenError'
    this.message = message
    if (error) {
      this.inner = error
    }
  }
}
