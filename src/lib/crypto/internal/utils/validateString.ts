export const validateString = (value: unknown, name: string) => {
  if (typeof value !== 'string')
    throw new Error(`ERR_INVALID_ARG_TYPE: ${name} string ${value}`)
}
