import { attempt } from '@jill64/attempt'
import type { JWTPayload } from 'jose'
import type { Encoding } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { toString } from './tostring'

const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

const isObject = (thing: unknown): thing is object =>
  Object.prototype.toString.call(thing) === '[object Object]'

const safeJsonParse = (thing: object | string) =>
  isObject(thing) ? thing : attempt(() => JSON.parse(thing), undefined)

const headerFromJWS = (jwsSig: string) =>
  safeJsonParse(
    Buffer.from(jwsSig.split('.', 1)[0], 'base64').toString('binary')
  )

const signatureFromJWS = (jwsSig: string) => jwsSig.split('.')[2]

const payloadFromJWS = (jwsSig: string, encoding: Encoding = 'utf8') =>
  Buffer.from(jwsSig.split('.')[1], 'base64').toString(encoding)

const isValidJws = (string: string) =>
  JWS_REGEX.test(string) && !!headerFromJWS(string)

export const jwsDecode = (
  jwsSig: string,
  opts: {
    encoding?: Parameters<typeof JSON.parse>[1]
    json?: boolean
  } = {}
) => {
  const jwsSig2 = toString(jwsSig)

  if (!isValidJws(jwsSig2)) {
    throw new Error('[INVALID_SIGNATURE]: Invalid JWS signature')
  }

  const header = headerFromJWS(jwsSig2)

  if (!header) {
    throw new Error('[MISSING_HEADER]: Missing JWS header')
  }

  const raw_payload = payloadFromJWS(jwsSig2)

  const payload =
    header.typ === 'JWT' || opts.json
      ? (JSON.parse(raw_payload, opts.encoding) as JWTPayload)
      : raw_payload

  if (typeof payload !== 'object') {
    throw new Error('[INVALID_PAYLOAD]: Invalid JWS payload')
  }

  const signature = signatureFromJWS(jwsSig2)

  return {
    header,
    payload,
    signature
  }
}
