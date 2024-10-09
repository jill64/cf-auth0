import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'
import process from 'node:process'

// @ts-expect-error TODO
function DataStream(data) {
  // @ts-expect-error TODO
  this.buffer = null
  // @ts-expect-error TODO
  this.writable = true
  // @ts-expect-error TODO
  this.readable = true

  // No input
  if (!data) {
    // @ts-expect-error TODO
    this.buffer = Buffer.alloc(0)
    // @ts-expect-error TODO
    return this
  }

  // Stream
  if (typeof data.pipe === 'function') {
    // @ts-expect-error TODO
    this.buffer = Buffer.alloc(0)
    // @ts-expect-error TODO
    data.pipe(this)
    // @ts-expect-error TODO
    return this
  }

  // Buffer or String
  // or Object (assumedly a passworded key)
  if (data.length || typeof data === 'object') {
    // @ts-expect-error TODO
    this.buffer = data
    // @ts-expect-error TODO
    this.writable = false
    process.nextTick(
      function () {
        // @ts-expect-error TODO
        this.emit('end', data)
        // @ts-expect-error TODO
        this.readable = false
        // @ts-expect-error TODO
        this.emit('close')
        // @ts-expect-error TODO
      }.bind(this)
    )
    // @ts-expect-error TODO
    return this
  }

  throw new TypeError('Unexpected data type (' + typeof data + ')')
}
util.inherits(DataStream, Stream)

// @ts-expect-error TODO
DataStream.prototype.write = function write(data) {
  this.buffer = Buffer.concat([this.buffer, Buffer.from(data)])
  this.emit('data', data)
}

// @ts-expect-error TODO
DataStream.prototype.end = function end(data) {
  if (data) this.write(data)
  this.emit('end', data)
  this.emit('close')
  this.writable = false
  this.readable = false
}

export default DataStream
