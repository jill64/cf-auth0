function getParamSize(keySize: number) {
  var result = ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1)
  return result
}

const paramBytesForAlg = {
  ES256: getParamSize(256),
  ES384: getParamSize(384),
  ES512: getParamSize(521)
}

export default function getParamBytesForAlg(
  alg: keyof typeof paramBytesForAlg
) {
  var paramBytes = paramBytesForAlg[alg]
  if (paramBytes) {
    return paramBytes
  }

  throw new Error('Unknown algorithm "' + alg + '"')
}
