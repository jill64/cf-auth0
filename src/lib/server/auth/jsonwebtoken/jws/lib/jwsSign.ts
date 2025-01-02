import type { JWTHeaderParameters, JWTPayload } from 'jose'
import type { Encoding } from 'node:crypto'
import util from 'node:util'
import { Buffer } from 'node:buffer'
import { jwa } from '../jwa'
import { toString } from './tostring'

const base64url = (string: string, encoding: Encoding) =>
  Buffer.from(string, encoding)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')

const jwsSecuredInput = (
  header: unknown,
  payload: unknown,
  encoding: Encoding = 'utf8'
) => {
  const encodedHeader = base64url(toString(header), 'binary')
  const encodedPayload = base64url(toString(payload), encoding)
  return util.format('%s.%s', encodedHeader, encodedPayload)
}

export const jwsSign = (opts: {
  header: JWTHeaderParameters
  payload: JWTPayload
  secret: string
  privateKey?: string
  encoding: 'utf8'
}) => {
  const header = opts.header
  const payload = opts.payload
  const secretOrKey = opts.secret || opts.privateKey

  if (!secretOrKey) {
    throw new Error('secretOrPrivateKey must have a value')
  }

  const encoding = opts.encoding
  const algo = jwa(header.alg)
  const securedInput = jwsSecuredInput(header, payload, encoding)
  const signature = algo.sign(securedInput, secretOrKey)
  return util.format('%s.%s', securedInput, signature)
}
