'use strict'

// @ts-expect-error TODO
function getParamSize(keySize) {
  var result = ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1)
  return result
}

var paramBytesForAlg = {
  ES256: getParamSize(256),
  ES384: getParamSize(384),
  ES512: getParamSize(521)
}

// @ts-expect-error TODO
function getParamBytesForAlg(alg) {
  // @ts-expect-error TODO
  var paramBytes = paramBytesForAlg[alg]
  if (paramBytes) {
    return paramBytes
  }

  throw new Error('Unknown algorithm "' + alg + '"')
}

export default getParamBytesForAlg
