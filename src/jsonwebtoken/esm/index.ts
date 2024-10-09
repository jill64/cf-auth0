import type { createPrivateKey, createPublicKey, KeyObject } from 'node:crypto'
import decode from './decode.js'
import JsonWebTokenError from './lib/JsonWebTokenError.js'
import NotBeforeError from './lib/NotBeforeError.js'
import TokenExpiredError from './lib/TokenExpiredError.js'
import sign from './sign.js'
import verify from './verify.js'

export interface SignOptions {
  /**
   * Signature algorithm. Could be one of these values :
   * - HS256:    HMAC using SHA-256 hash algorithm (default)
   * - HS384:    HMAC using SHA-384 hash algorithm
   * - HS512:    HMAC using SHA-512 hash algorithm
   * - RS256:    RSASSA using SHA-256 hash algorithm
   * - RS384:    RSASSA using SHA-384 hash algorithm
   * - RS512:    RSASSA using SHA-512 hash algorithm
   * - ES256:    ECDSA using P-256 curve and SHA-256 hash algorithm
   * - ES384:    ECDSA using P-384 curve and SHA-384 hash algorithm
   * - ES512:    ECDSA using P-521 curve and SHA-512 hash algorithm
   * - none:     No digital signature or MAC value included
   */
  algorithm?: Algorithm | undefined
  keyid?: string | undefined
  /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, "2 days", "10h", "7d" */
  expiresIn?: string | number
  /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, "2 days", "10h", "7d" */
  notBefore?: string | number | undefined
  audience?: string | string[] | undefined
  subject?: string | undefined
  issuer?: string | undefined
  jwtid?: string | undefined
  mutatePayload?: boolean | undefined
  noTimestamp?: boolean | undefined
  header?: JwtHeader | undefined
  encoding?: string | undefined
  allowInsecureKeySizes?: boolean | undefined
  allowInvalidAsymmetricKeyTypes?: boolean | undefined
}

export interface VerifyOptions {
  algorithms?: Algorithm[] | undefined
  audience?: string | RegExp | Array<string | RegExp> | undefined
  clockTimestamp?: number | undefined
  clockTolerance?: number | undefined
  /** return an object with the decoded `{ payload, header, signature }` instead of only the usual content of the payload. */
  complete?: boolean | undefined
  issuer?: string | string[] | undefined
  ignoreExpiration?: boolean | undefined
  ignoreNotBefore?: boolean | undefined
  jwtid?: string | undefined
  /**
   * If you want to check `nonce` claim, provide a string value here.
   * It is used on Open ID for the ID Tokens. ([Open ID implementation notes](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes))
   */
  nonce?: string | undefined
  subject?: string | undefined
  maxAge?: string | number | undefined
  allowInvalidAsymmetricKeyTypes?: boolean | undefined
}

export interface DecodeOptions {
  complete?: boolean | undefined
  json?: boolean | undefined
}
export type VerifyErrors =
  | JsonWebTokenError
  | NotBeforeError
  | TokenExpiredError
export type VerifyCallback<T = Jwt | JwtPayload | string> = (
  error: VerifyErrors | null,
  decoded: T | undefined
) => void

export type SignCallback = (
  error: Error | null,
  encoded: string | undefined
) => void

// standard names https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1
export interface JwtHeader {
  alg: string | Algorithm
  typ?: string | undefined
  cty?: string | undefined
  crit?: Array<string | Exclude<keyof JwtHeader, 'crit'>> | undefined
  kid?: string | undefined
  jku?: string | undefined
  x5u?: string | string[] | undefined
  'x5t#S256'?: string | undefined
  x5t?: string | undefined
  x5c?: string | string[] | undefined
}

// standard claims https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
export interface JwtPayload {
  [key: string]: unknown
  iss?: string | undefined
  sub?: string | undefined
  aud?: string | string[] | undefined
  exp?: number | undefined
  nbf?: number | undefined
  iat?: number | undefined
  jti?: string | undefined
}

export interface Jwt {
  header: JwtHeader
  payload: JwtPayload | string
  signature: string
}

// https://github.com/auth0/node-jsonwebtoken#algorithms-supported
export type Algorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'none'

export type SigningKeyCallback = (
  error: Error | null,
  signingKey?: Secret | PublicKey
) => void

export type GetPublicKeyOrSecret = (
  header: JwtHeader,
  callback: SigningKeyCallback
) => void

export type PublicKey = Parameters<typeof createPublicKey>[0]

export type PrivateKey = Parameters<typeof createPrivateKey>[0]

export type Secret =
  | string
  | Buffer
  | KeyObject
  | { key: string | Buffer; passphrase: string }

export {
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
  decode,
  sign,
  verify
}
