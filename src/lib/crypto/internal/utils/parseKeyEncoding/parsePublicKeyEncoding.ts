import { parseKeyEncoding } from './index.js'

type Params = Parameters<typeof parseKeyEncoding>

export const parsePublicKeyEncoding = (
  enc: Params[0],
  keyType: Params[1],
  objName: Params[3]
) => parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName)
