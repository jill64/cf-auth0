import { JwksClient } from './JwksClient.js'
import errors from './errors/index.js'

export default JwksClient

export { JwksClient }

export const ArgumentError = errors.ArgumentError
export const JwksError = errors.JwksError
export const JwksRateLimitError = errors.JwksRateLimitError
export const SigningKeyNotFoundError = errors.SigningKeyNotFoundError
