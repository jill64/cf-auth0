import { Buffer } from 'node:buffer'

// @ts-expect-error TODO
export default function toString(obj) {
  if (typeof obj === 'string') return obj
  if (typeof obj === 'number' || Buffer.isBuffer(obj)) return obj.toString()
  return JSON.stringify(obj)
}
