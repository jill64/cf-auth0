import type { KeyObjectLike } from './KeyObjectLike.js'

export const isKeyObjectLike = (val: unknown): val is KeyObjectLike =>
  typeof val === 'object' &&
  val !== null &&
  'type' in val &&
  typeof val.type === 'string' &&
  ['private', 'public', 'secret'].includes(val.type) &&
  'from' in val &&
  typeof val.from === 'function' &&
  'equals' in val &&
  typeof val.equals === 'function' &&
  'exports' in val &&
  typeof val.exports === 'function'
