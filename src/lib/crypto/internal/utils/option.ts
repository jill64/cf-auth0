export const option = (name: string, objName?: string) =>
  objName === undefined ? `options.${name}` : `options.${objName}.${name}`
