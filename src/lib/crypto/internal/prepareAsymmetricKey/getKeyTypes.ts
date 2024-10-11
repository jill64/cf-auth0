export const getKeyTypes = (allowKeyObject: unknown, bufferOnly = false) => {
  const types = [
    'ArrayBuffer',
    'Buffer',
    'TypedArray',
    'DataView',
    'string', // Only if bufferOnly == false
    'KeyObject', // Only if allowKeyObject == true && bufferOnly == false
    'CryptoKey' // Only if allowKeyObject == true && bufferOnly == false
  ]

  if (bufferOnly) {
    return types.slice(0, 4)
  } else if (!allowKeyObject) {
    return types.slice(0, 5)
  }

  return types
}
