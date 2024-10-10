const kValidateObjectNone = 0
const kValidateObjectAllowNullable = 1 << 0
const kValidateObjectAllowArray = 1 << 1
const kValidateObjectAllowFunction = 1 << 2

export const validateObject = (
  value: unknown,
  name: unknown,
  options = kValidateObjectNone
) => {
  if (options === kValidateObjectNone) {
    if (value === null || Array.isArray(value)) {
      throw new Error(`ERR_INVALID_ARG_TYPE: ${name} Object ${value}`)
    }

    if (typeof value !== 'object') {
      throw new Error(`ERR_INVALID_ARG_TYPE: ${name} Object ${value}`)
    }
  } else {
    const throwOnNullable = (kValidateObjectAllowNullable & options) === 0

    if (throwOnNullable && value === null) {
      throw new Error(`ERR_INVALID_ARG_TYPE: ${name} Object ${value}`)
    }

    const throwOnArray = (kValidateObjectAllowArray & options) === 0

    if (throwOnArray && Array.isArray(value)) {
      throw new Error(`ERR_INVALID_ARG_TYPE: ${name} Object ${value}`)
    }

    const throwOnFunction = (kValidateObjectAllowFunction & options) === 0
    const typeofValue = typeof value

    if (
      typeofValue !== 'object' &&
      (throwOnFunction || typeofValue !== 'function')
    ) {
      throw new Error(`ERR_INVALID_ARG_TYPE: ${name} Object ${value}`)
    }
  }
}
