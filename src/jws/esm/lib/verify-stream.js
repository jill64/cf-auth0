import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'
import jwa from '../../../jwa/esm/index.js'
import DataStream from './data-stream.js'
import toString from './tostring.js'
var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

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

  var payload = payloadFromJWS(jwsSig)
  if (header.typ === 'JWT' || opts.json)
    payload = JSON.parse(payload, opts.encoding)

  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwsSig)
  }
}

// @ts-expect-error TODO
function VerifyStream(opts) {
  opts = opts || {}
  var secretOrKey = opts.secret || opts.publicKey || opts.key
  var secretStream = new DataStream(secretOrKey)
  this.readable = true
  this.algorithm = opts.algorithm
  this.encoding = opts.encoding
  this.secret = this.publicKey = this.key = secretStream
  this.signature = new DataStream(opts.signature)
  // @ts-expect-error TODO
  this.secret.once(
    'close',
    function () {
      // @ts-expect-error TODO
      if (!this.signature.writable && this.readable) this.verify()
    }.bind(this)
  )

  // @ts-expect-error TODO
  this.signature.once(
    'close',
    function () {
      // @ts-expect-error TODO
      if (!this.secret.writable && this.readable) this.verify()
    }.bind(this)
  )
}
util.inherits(VerifyStream, Stream)
VerifyStream.prototype.verify = function verify() {
  try {
    var valid = jwsVerify(
      this.signature.buffer,
      this.algorithm,
      this.key.buffer
    )
    var obj = jwsDecode(this.signature.buffer, this.encoding)
    // @ts-expect-error TODO
    this.emit('done', valid, obj)
    // @ts-expect-error TODO
    this.emit('data', valid)
    // @ts-expect-error TODO
    this.emit('end')
    this.readable = false
    return valid
  } catch (e) {
    this.readable = false
    // @ts-expect-error TODO
    this.emit('error', e)
    // @ts-expect-error TODO
    this.emit('close')
  }
}

VerifyStream.decode = jwsDecode
VerifyStream.isValid = isValidJws
VerifyStream.verify = jwsVerify

export default VerifyStream
