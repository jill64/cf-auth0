import { JwksClient } from './JwksClient.js'
import errors from './errors/index.js'

export default (options) => {
  return new JwksClient(options)
}

export { JwksClient }

export const ArgumentError = errors.ArgumentError
export const JwksError = errors.JwksError
export const JwksRateLimitError = errors.JwksRateLimitError
export const SigningKeyNotFoundError = errors.SigningKeyNotFoundError
