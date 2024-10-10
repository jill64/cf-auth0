import { KEYS } from './Keys.js'

export const parseKeyFormat = (
  formatStr: string | undefined,
  defaultFormat: string | undefined,
  optionName?: string
) => {
  if (formatStr === undefined && defaultFormat !== undefined)
    return defaultFormat
  else if (formatStr === 'pem') return KEYS.kKeyFormatPEM
  else if (formatStr === 'der') return KEYS.kKeyFormatDER
  else if (formatStr === 'jwk') return KEYS.kKeyFormatJWK
  throw Error(`ERR_INVALID_ARG_VALUE: ${optionName} ${formatStr}`)
}
