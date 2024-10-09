import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'
import jwa from '../../../jwa/esm/index.js'
import DataStream from './data-stream.js'
import toString from './tostring.js'

// @ts-expect-error TODO
function base64url(string, encoding) {
  return Buffer.from(string, encoding)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

// @ts-expect-error TODO
function jwsSecuredInput(header, payload, encoding) {
  encoding = encoding || 'utf8'
  var encodedHeader = base64url(toString(header), 'binary')
  var encodedPayload = base64url(toString(payload), encoding)
  return util.format('%s.%s', encodedHeader, encodedPayload)
}

// @ts-expect-error TODO
function jwsSign(opts) {
  var header = opts.header
  var payload = opts.payload
  var secretOrKey = opts.secret || opts.privateKey
  var encoding = opts.encoding
  var algo = jwa(header.alg)
  var securedInput = jwsSecuredInput(header, payload, encoding)
  var signature = algo.sign(securedInput, secretOrKey)
  return util.format('%s.%s', securedInput, signature)
}

// @ts-expect-error TODO
function SignStream(opts) {
  var secret = opts.secret || opts.privateKey || opts.key
  // @ts-expect-error TODO
  var secretStream = new DataStream(secret)
  // @ts-expect-error TODO
  this.readable = true
  // @ts-expect-error TODO
  this.header = opts.header
  // @ts-expect-error TODO
  this.encoding = opts.encoding
  // @ts-expect-error TODO
  this.secret = this.privateKey = this.key = secretStream
  // @ts-expect-error TODO
  this.payload = new DataStream(opts.payload)
  // @ts-expect-error TODO
  this.secret.once(
    'close',
    function () {
      // @ts-expect-error TODO
      if (!this.payload.writable && this.readable) this.sign()
      // @ts-expect-error TODO
    }.bind(this)
  )

  // @ts-expect-error TODO
  this.payload.once(
    'close',
    function () {
      // @ts-expect-error TODO
      if (!this.secret.writable && this.readable) this.sign()
      // @ts-expect-error TODO
    }.bind(this)
  )
}
util.inherits(SignStream, Stream)

SignStream.prototype.sign = function sign() {
  try {
    var signature = jwsSign({
      header: this.header,
      payload: this.payload.buffer,
      secret: this.secret.buffer,
      encoding: this.encoding
    })
    this.emit('done', signature)
    this.emit('data', signature)
    this.emit('end')
    this.readable = false
    return signature
  } catch (e) {
    this.readable = false
    this.emit('error', e)
    this.emit('close')
  }
}

SignStream.sign = jwsSign

export default SignStream
