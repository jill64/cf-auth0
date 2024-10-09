import { Buffer } from 'node:buffer'
import jwa from '../../../jwa/esm/index.js'
import toString from './tostring.js'

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

// @ts-expect-error TODO
function isObject(thing) {
  return Object.prototype.toString.call(thing) === '[object Object]'
}

// @ts-expect-error TODO
function safeJsonParse(thing) {
  if (isObject(thing)) return thing
  try {
    return JSON.parse(thing)
  } catch {
    return undefined
  }
}

const headerFromJWS = (jwsSig: string) => {
  const encodedHeader = jwsSig.split('.', 1)[0]
  return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'))
}

// @ts-expect-error TODO
function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.')
}

const signatureFromJWS = (jwsSig: string) => jwsSig.split('.')[2]

const payloadFromJWS = (jwsSig: string, encoding: BufferEncoding = 'utf8') => {
  const payload = jwsSig.split('.')[1]
  return Buffer.from(payload, 'base64').toString(encoding)
}

const isValidJws = (string: string) =>
  JWS_REGEX.test(string) && !!headerFromJWS(string)

// @ts-expect-error TODO
function jwsVerify(jwsSig, algorithm, secretOrKey) {
  if (!algorithm) {
    var err = new Error('Missing algorithm parameter for jws.verify')
    // @ts-expect-error TODO
    err.code = 'MISSING_ALGORITHM'
    throw err
  }
  jwsSig = toString(jwsSig)
  var signature = signatureFromJWS(jwsSig)
  var securedInput = securedInputFromJWS(jwsSig)
  var algo = jwa(algorithm)
  return algo.verify(securedInput, signature, secretOrKey)
}

export const decode = (
  jwsSig: string,
  opts?: {
    json?: boolean
    encoding?: Parameters<JSON['parse']>[1]
  }
) => {
  jwsSig = toString(jwsSig)

  if (!isValidJws(jwsSig)) return null

  const header = headerFromJWS(jwsSig)

  if (!header) return null

  let payload = payloadFromJWS(jwsSig)

  if (header.typ === 'JWT' || opts?.json) {
    payload = JSON.parse(payload, opts?.encoding)
  }

  return {
    header,
    payload,
    signature: signatureFromJWS(jwsSig)
  }
}

export const isValid = isValidJws
export const verify = jwsVerify
