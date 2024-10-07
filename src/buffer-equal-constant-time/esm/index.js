import { Buffer, SlowBuffer } from 'node:buffer'

export default bufferEq

// @ts-expect-error TODO
function bufferEq(a, b) {
  // shortcutting on type is necessary for correctness
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    return false
  }

  // buffer sizes should be well-known information, so despite this
  // shortcutting, it doesn't leak any information about the *contents* of the
  // buffers.
  if (a.length !== b.length) {
    return false
  }

  var c = 0
  for (var i = 0; i < a.length; i++) {
    /*jshint bitwise:false */
    c |= a[i] ^ b[i] // XOR
  }
  return c === 0
}

bufferEq.install = function () {
  // @ts-expect-error TODO
  Buffer.prototype.equal = SlowBuffer.prototype.equal = function equal(that) {
    return bufferEq(this, that)
  }
}

var origBufEqual = Buffer.prototype.equal
// @ts-expect-error TODO
var origSlowBufEqual = SlowBuffer.prototype.equal
bufferEq.restore = function () {
  Buffer.prototype.equal = origBufEqual
  // @ts-expect-error TODO
  SlowBuffer.prototype.equal = origSlowBufEqual
}
