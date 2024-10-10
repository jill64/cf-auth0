import { KeyObject } from 'node:crypto'

export const isKeyObject = (val: unknown): val is KeyObject =>
  typeof val === 'object' &&
  val !== null &&
  'type' in val &&
  typeof val.type === 'string' &&
  ['private', 'public', 'secret'].includes(val.type) &&
  'from' in val &&
  typeof val.from === 'function' &&
  'equals' in val &&
  typeof val.equals === 'function' &&
  'export' in val &&
  typeof val.export === 'function'
