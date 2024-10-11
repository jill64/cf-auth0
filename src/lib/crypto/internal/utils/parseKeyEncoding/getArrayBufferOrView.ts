import { isAnyArrayBuffer, isArrayBufferView } from 'node:util/types'

export const getArrayBufferOrView = (
  buffer: unknown,
  name: unknown,
  encoding?: BufferEncoding | 'buffer'
) => {
  if (isAnyArrayBuffer(buffer)) {
    return buffer
  }

  if (typeof buffer === 'string') {
    if (encoding === 'buffer') encoding = 'utf8'
    return Buffer.from(buffer, encoding)
  }

  if (!isArrayBufferView(buffer)) {
    throw new Error(
      `ERR_INVALID_ARG_TYPE: ${name} must be ${[
        'string',
        'ArrayBuffer',
        'Buffer',
        'TypedArray',
        'DataView'
      ]} but ${buffer}`
    )
  }

  return buffer
}
