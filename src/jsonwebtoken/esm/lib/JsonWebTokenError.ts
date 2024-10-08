export default class JsonWebTokenError extends Error {
  inner

  constructor(message: string, error?: Error) {
    super(message)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor)
    }
    this.name = 'JsonWebTokenError'
    this.message = message
    this.inner = error
  }
}
