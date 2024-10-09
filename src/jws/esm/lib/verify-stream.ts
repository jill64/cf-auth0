import { Buffer } from 'node:buffer'
import { KeyObject } from 'node:crypto'
import { JwtHeader, JwtPayload } from '../../../jsonwebtoken/esm/index.js'
import jwa from '../../../jwa/esm/index.js'
import toString from './tostring.js'

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

const isObject = (thing: unknown) =>
  Object.prototype.toString.call(thing) === '[object Object]'

const safeJsonParse = <T>(thing: string): T | undefined => {
  if (isObject(thing)) return thing as T
  try {
    return JSON.parse(thing)
  } catch {
    return undefined
  }
}

const headerFromJWS = (jwsSig: string) => {
  const encodedHeader = jwsSig.split('.', 1)[0]
  return safeJsonParse<JwtHeader>(
    Buffer.from(encodedHeader, 'base64').toString('binary')
  )
}

const securedInputFromJWS = (jwsSig: string) => jwsSig.split('.', 2).join('.')

const signatureFromJWS = (jwsSig: string) => jwsSig.split('.')[2]

const payloadFromJWS = (jwsSig: string, encoding: BufferEncoding = 'utf8') => {
  const payload = jwsSig.split('.')[1]
  return Buffer.from(payload, 'base64').toString(encoding)
}

export const isValid = (string: string) =>
  JWS_REGEX.test(string) && !!headerFromJWS(string)

export const verify = (
  jwsSig: string,
  algorithm: Parameters<typeof jwa>[0],
  secretOrKey: KeyObject
) => {
  if (!algorithm) {
    throw new Error('MISSING_ALGORITHM: parameter for jws.verify')
  }

  const jwsSig2 = toString(jwsSig)

  const signature = signatureFromJWS(jwsSig2)
  const securedInput = securedInputFromJWS(jwsSig2)
  const algo = jwa(algorithm)

  return algo.verify(securedInput, signature, secretOrKey)
}

export const decode = (
  jwsSig: string,
  opts?: {
    json?: boolean
    encoding?: Parameters<JSON['parse']>[1]
  }
) => {
  const jwsSig2 = toString(jwsSig)

  if (!isValid(jwsSig2)) return null

  const header = headerFromJWS(jwsSig2)

  if (!header) return null

  const payload = payloadFromJWS(jwsSig2)

  const payload2 =
    header.typ === 'JWT' || opts?.json
      ? (JSON.parse(payload, opts?.encoding) as JwtPayload)
      : payload

  return {
    header,
    payload: payload2,
    signature: signatureFromJWS(jwsSig)
  }
}
