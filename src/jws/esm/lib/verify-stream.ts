import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'
import jwa from '../../../jwa/esm/index.js'
import DataStream from './data-stream.js'
import toString from './tostring.js'
const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

function isObject(thing: unknown): thing is object {
  return Object.prototype.toString.call(thing) === '[object Object]'
}

function safeJsonParse(thing: object | string) {
  if (isObject(thing)) return thing
  try {
    return JSON.parse(thing)
  } catch {
    return undefined
  }
}

function headerFromJWS(jwsSig: string) {
  var encodedHeader = jwsSig.split('.', 1)[0]
  return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'))
}

function securedInputFromJWS(jwsSig: string) {
  return jwsSig.split('.', 2).join('.')
}

function signatureFromJWS(jwsSig: string) {
  return jwsSig.split('.')[2]
}

function payloadFromJWS(jwsSig: string, encoding: BufferEncoding) {
  encoding = encoding || 'utf8'
  var payload = jwsSig.split('.')[1]
  return Buffer.from(payload, 'base64').toString(encoding)
}

function isValidJws(string: string) {
  return JWS_REGEX.test(string) && !!headerFromJWS(string)
}

// @ts-expect-error WARNING: Unknown type
function jwsVerify(jwsSig, algorithm, secretOrKey) {
  if (!algorithm) {
    var err = new Error('Missing algorithm parameter for jws.verify')
    // @ts-expect-error WARNING: Unknown type
    err.code = 'MISSING_ALGORITHM'
    throw err
  }
  jwsSig = toString(jwsSig)
  var signature = signatureFromJWS(jwsSig)
  var securedInput = securedInputFromJWS(jwsSig)
  var algo = jwa(algorithm)
  return algo.verify(securedInput, signature, secretOrKey)
}

// @ts-expect-error WARNING: Unknown type
function jwsDecode(jwsSig, opts) {
  opts = opts || {}
  jwsSig = toString(jwsSig)

  if (!isValidJws(jwsSig)) return null

  var header = headerFromJWS(jwsSig)

  if (!header) return null

  // @ts-expect-error WARNING: Unknown type
  var payload = payloadFromJWS(jwsSig)
  if (header.typ === 'JWT' || opts.json)
    payload = JSON.parse(payload, opts.encoding)

  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwsSig)
  }
}

// @ts-expect-error WARNING: Unknown type
function VerifyStream(opts) {
  opts = opts || {}
  var secretOrKey = opts.secret || opts.publicKey || opts.key
  // @ts-expect-error WARNING: Unknown type
  var secretStream = new DataStream(secretOrKey)
  // @ts-expect-error WARNING: Unknown type
  this.readable = true
  // @ts-expect-error WARNING: Unknown type
  this.algorithm = opts.algorithm
  // @ts-expect-error WARNING: Unknown type
  this.encoding = opts.encoding
  // @ts-expect-error WARNING: Unknown type
  this.secret = this.publicKey = this.key = secretStream
  // @ts-expect-error WARNING: Unknown type
  this.signature = new DataStream(opts.signature)
  // @ts-expect-error WARNING: Unknown type
  this.secret.once(
    'close',
    function () {
      // @ts-expect-error WARNING: Unknown type
      if (!this.signature.writable && this.readable) this.verify()
      // @ts-expect-error WARNING: Unknown type
    }.bind(this)
  )

  // @ts-expect-error WARNING: Unknown type
  this.signature.once(
    'close',
    function () {
      // @ts-expect-error WARNING: Unknown type
      if (!this.secret.writable && this.readable) this.verify()
      // @ts-expect-error WARNING: Unknown type
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
    this.emit('done', valid, obj)
    this.emit('data', valid)
    this.emit('end')
    this.readable = false
    return valid
  } catch (e) {
    this.readable = false
    this.emit('error', e)
    this.emit('close')
  }
}

VerifyStream.decode = jwsDecode
VerifyStream.isValid = isValidJws
VerifyStream.verify = jwsVerify

export default VerifyStream
