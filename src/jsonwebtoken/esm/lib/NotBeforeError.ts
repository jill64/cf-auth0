import JsonWebTokenError from './JsonWebTokenError.js'

export default class NotBeforeError extends JsonWebTokenError {
  date

  constructor(message: string, date: Date) {
    super(message)
    this.name = 'NotBeforeError'
    this.date = date
  }
}
