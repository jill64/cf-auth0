import { Buffer } from 'node:buffer'

export const toString = (obj: unknown): string => {
  if (typeof obj === 'string') return obj
  if (typeof obj === 'number' || Buffer.isBuffer(obj)) return obj.toString()
  return JSON.stringify(obj)
}
