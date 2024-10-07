import { Buffer } from 'node:buffer'
import Stream from 'node:stream'
import util from 'node:util'
import process from 'node:process'

// @ts-expect-error TODO
function DataStream(data) {
  this.buffer = null
  this.writable = true
  this.readable = true

  // No input
  if (!data) {
    this.buffer = Buffer.alloc(0)
    return this
  }

  // Stream
  if (typeof data.pipe === 'function') {
    this.buffer = Buffer.alloc(0)
    data.pipe(this)
    return this
  }

  // Buffer or String
  // or Object (assumedly a passworded key)
  if (data.length || typeof data === 'object') {
    this.buffer = data
    this.writable = false
    process.nextTick(
      function () {
        // @ts-expect-error TODO
        this.emit('end', data)
        this.readable = false
        // @ts-expect-error TODO
        this.emit('close')
      }.bind(this)
    )
    return this
  }

  throw new TypeError('Unexpected data type (' + typeof data + ')')
}
util.inherits(DataStream, Stream)

// @ts-expect-error TODO
DataStream.prototype.write = function write(data) {
  this.buffer = Buffer.concat([this.buffer, Buffer.from(data)])
  // @ts-expect-error TODO
  this.emit('data', data)
}

// @ts-expect-error TODO
DataStream.prototype.end = function end(data) {
  if (data) this.write(data)
  // @ts-expect-error TODO
  this.emit('end', data)
  // @ts-expect-error TODO
  this.emit('close')
  this.writable = false
  this.readable = false
}

export default DataStream
