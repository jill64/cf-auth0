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

// @ts-expect-error TODO
function headerFromJWS(jwsSig) {
  var encodedHeader = jwsSig.split('.', 1)[0]
  return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'))
}

// @ts-expect-error TODO
function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.')
}

// @ts-expect-error TODO
function signatureFromJWS(jwsSig) {
  return jwsSig.split('.')[2]
}

// @ts-expect-error TODO
function payloadFromJWS(jwsSig, encoding) {
  encoding = encoding || 'utf8'
  var payload = jwsSig.split('.')[1]
  return Buffer.from(payload, 'base64').toString(encoding)
}

// @ts-expect-error TODO
function isValidJws(string) {
  return JWS_REGEX.test(string) && !!headerFromJWS(string)
}

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

// @ts-expect-error TODO
function jwsDecode(jwsSig, opts) {
  opts = opts || {}
  jwsSig = toString(jwsSig)

  if (!isValidJws(jwsSig)) return null

  var header = headerFromJWS(jwsSig)

  if (!header) return null

  // @ts-expect-error TODO
  var payload = payloadFromJWS(jwsSig)
  if (header.typ === 'JWT' || opts.json)
    payload = JSON.parse(payload, opts.encoding)

  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwsSig)
  }
}

export const decode = jwsDecode
export const isValid = isValidJws
export const verify = jwsVerify
