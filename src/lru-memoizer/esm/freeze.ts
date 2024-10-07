export function deepFreeze(o: unknown) {
  if (o) {
    Object.freeze(o)

    Object.getOwnPropertyNames(o).forEach((prop) => {
      const p = prop as keyof typeof o

      if (
        o.hasOwnProperty(p) &&
        o[p] !== null &&
        (typeof o[p] === 'object' || typeof o[p] === 'function') &&
        'constructor' in o[p] &&
        (
          o[p] as {
            constructor: unknown
          }
        ).constructor !== Buffer &&
        !Object.isFrozen(o[p])
      ) {
        deepFreeze(o[p])
      }
    })
  }

  return o
}
