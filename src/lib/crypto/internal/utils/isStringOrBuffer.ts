import { isAnyArrayBuffer, isArrayBufferView } from 'util/types'

export const isStringOrBuffer = (val: unknown) =>
  typeof val === 'string' || isArrayBufferView(val) || isAnyArrayBuffer(val)
