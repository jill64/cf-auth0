export const validateOneOf = <T>(value: T, name: unknown, oneOf: T[]) => {
  if (!oneOf.includes(value)) {
    const allowed = oneOf
      .map((v) => (typeof v === 'string' ? `'${v}'` : String(v)))
      .join(',')

    throw new Error(
      `ERR_INVALID_ARG_VALUE: ${name} ${value} must be one of: ${allowed}`
    )
  }
}
