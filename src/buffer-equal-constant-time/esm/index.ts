import { Buffer } from 'node:buffer'

export default bufferEq

function bufferEq(a: Buffer, b: Buffer) {
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
