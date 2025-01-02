import type { KeyObject } from 'node:crypto'
import { jwa } from '../jwa'
import { toString } from './tostring'

const securedInputFromJWS = (jwsSig: string) => jwsSig.split('.', 2).join('.')

const signatureFromJWS = (jwsSig: string) => jwsSig.split('.')[2]

export const jwsVerify = async (
  jwsSig: string,
  algorithm: string,
  secretOrKey: CryptoKey | KeyObject | string
) => {
  if (!algorithm) {
    throw new Error(
      '[MISSING_ALGORITHM]: Missing algorithm parameter for jws.verify'
    )
  }

  jwsSig = toString(jwsSig)
  const signature = signatureFromJWS(jwsSig)
  const securedInput = securedInputFromJWS(jwsSig)
  const algo = jwa(algorithm)
  // @ts-expect-error TODO: fix this
  return await algo.verify(securedInput, signature, secretOrKey)
}
