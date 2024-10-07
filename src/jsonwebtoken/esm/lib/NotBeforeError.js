import JsonWebTokenError from './JsonWebTokenError.js'

// @ts-expect-error TODO
function NotBeforeError(message, date) {
  JsonWebTokenError.call(this, message)
  this.name = 'NotBeforeError'
  this.date = date
}

NotBeforeError.prototype = Object.create(JsonWebTokenError.prototype)

NotBeforeError.prototype.constructor = NotBeforeError

export default NotBeforeError
