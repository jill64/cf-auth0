import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'

// @ts-expect-error WARNING: Unknown type
function DataStream(data) {
  // @ts-expect-error WARNING: Unknown type
  this.buffer = null
  // @ts-expect-error WARNING: Unknown type
  this.writable = true
  // @ts-expect-error WARNING: Unknown type
  this.readable = true

  // No input
  if (!data) {
    // @ts-expect-error WARNING: Unknown type
    this.buffer = Buffer.alloc(0)
    // @ts-expect-error WARNING: Unknown type
    return this
  }

  // Stream
  if (typeof data.pipe === 'function') {
    // @ts-expect-error WARNING: Unknown type
    this.buffer = Buffer.alloc(0)
    // @ts-expect-error WARNING: Unknown type
    data.pipe(this)
    // @ts-expect-error WARNING: Unknown type
    return this
  }

  // Buffer or String
  // or Object (assumedly a passworded key)
  if (data.length || typeof data === 'object') {
    // @ts-expect-error WARNING: Unknown type
    this.buffer = data
    // @ts-expect-error WARNING: Unknown type
    this.writable = false
    process.nextTick(
      function () {
        // @ts-expect-error WARNING: Unknown type
        this.emit('end', data)
        // @ts-expect-error WARNING: Unknown type
        this.readable = false
        // @ts-expect-error WARNING: Unknown type
        this.emit('close')
        // @ts-expect-error WARNING: Unknown type
      }.bind(this)
    )
    // @ts-expect-error WARNING: Unknown type
    return this
  }

  throw new TypeError('Unexpected data type (' + typeof data + ')')
}
util.inherits(DataStream, Stream)

// @ts-expect-error WARNING: Unknown type
DataStream.prototype.write = function write(data) {
  this.buffer = Buffer.concat([this.buffer, Buffer.from(data)])
  this.emit('data', data)
}

// @ts-expect-error WARNING: Unknown type
DataStream.prototype.end = function end(data) {
  if (data) this.write(data)
  this.emit('end', data)
  this.emit('close')
  this.writable = false
  this.readable = false
}

export default DataStream
