// Parses the public key encoding based on an object. keyType must be undefined
// when this is used to parse an input encoding and must be a valid key type if
// used to parse an output encoding.

import { parseKeyEncoding } from './parseKeyEncoding.js'

type Params = Parameters<typeof parseKeyEncoding>

export const parsePublicKeyEncoding = (
  enc: Params[0],
  keyType: Params[1],
  objName: Params[3]
) => parseKeyEncoding(enc, keyType, keyType ? true : undefined, objName)
