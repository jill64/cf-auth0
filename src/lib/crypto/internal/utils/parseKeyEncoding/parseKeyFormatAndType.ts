import { parseKeyFormat } from '../../parseKeyFormat.js'
import { parseKeyType } from '../../parseKeyType.js'
import { KEYS } from '../KEYS.js'
import { option } from '../option.js'
import { parseKeyEncoding } from './index.js'

type Params = Parameters<typeof parseKeyEncoding>

export const parseKeyFormatAndType = (
  enc: Params[0],
  keyType: Params[1],
  isPublic: Params[2],
  objName: Params[3]
) => {
  const formatStr = 'format' in enc ? enc.format : undefined
  const typeStr = 'type' in enc ? enc.type : undefined

  const isInput = keyType === undefined
  const format = parseKeyFormat(
    formatStr,
    isInput ? KEYS.kKeyFormatPEM : undefined,
    option('format', objName)
  )

  const isRequired =
    (!isInput || format === KEYS.kKeyFormatDER) && format !== KEYS.kKeyFormatJWK

  const type = parseKeyType(
    typeStr,
    isRequired,
    keyType,
    isPublic,
    option('type', objName)
  )

  return { format, type }
}
