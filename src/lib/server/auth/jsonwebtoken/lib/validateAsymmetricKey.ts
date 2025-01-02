import type { CryptoKey } from '@cloudflare/workers-types'
import type { KeyObject } from 'node:crypto'
import ASYMMETRIC_KEY_DETAILS_SUPPORTED from './asymmetricKeyDetailsSupported'
import RSA_PSS_KEY_DETAILS_SUPPORTED from './rsaPssKeyDetailsSupported'

const allowedAlgorithmsForKeys = {
  ec: ['ES256', 'ES384', 'ES512'],
  rsa: ['RS256', 'PS256', 'RS384', 'PS384', 'RS512', 'PS512'],
  'rsa-pss': ['PS256', 'PS384', 'PS512']
}

const allowedCurves = {
  ES256: 'prime256v1',
  ES384: 'secp384r1',
  ES512: 'secp521r1'
}

export default (algorithm: string, key: KeyObject | CryptoKey) => {
  if (!algorithm || !key) return

  if (!('asymmetricKeyType' in key)) {
    return
  }

  const keyType = key.asymmetricKeyType

  if (!keyType) return

  const isKeySupported = (
    key: string
  ): key is keyof typeof allowedAlgorithmsForKeys =>
    !!key && key in allowedAlgorithmsForKeys

  if (!isKeySupported(keyType)) {
    throw new Error(`Unsupported key type "${keyType}".`)
  }

  const allowedAlgorithms = allowedAlgorithmsForKeys[keyType]

  if (!allowedAlgorithms) {
    throw new Error(`Unknown key type "${keyType}".`)
  }

  if (!allowedAlgorithms.includes(algorithm)) {
    throw new Error(
      `"alg" parameter for "${keyType}" key type must be one of: ${allowedAlgorithms.join(
        ', '
      )}.`
    )
  }

  /*
   * Ignore the next block from test coverage because it gets executed
   * conditionally depending on the Node version. Not ignoring it would
   * prevent us from reaching the target % of coverage for versions of
   * Node under 15.7.0.
   */
  /* istanbul ignore next */
  if (ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
    switch (keyType) {
      case 'ec':
        if (!key.asymmetricKeyDetails) {
          throw new Error(
            `Invalid key for this operation, its EC parameters do not meet the requirements of "alg" ${algorithm}.`
          )
        }

        const keyCurve = key.asymmetricKeyDetails.namedCurve

        const isCurveSupported = (
          alg?: string
        ): alg is keyof typeof allowedCurves => !!alg && alg in allowedCurves

        if (!isCurveSupported(algorithm)) {
          throw new Error(`Unknown algorithm "${algorithm}".`)
        }

        const allowedCurve = allowedCurves[algorithm]

        if (keyCurve !== allowedCurve) {
          throw new Error(
            `"alg" parameter "${algorithm}" requires curve "${allowedCurve}".`
          )
        }
        break

      case 'rsa-pss':
        if (RSA_PSS_KEY_DETAILS_SUPPORTED) {
          const length = parseInt(algorithm.slice(-3), 10)
          const { hashAlgorithm, mgf1HashAlgorithm, saltLength } =
            key.asymmetricKeyDetails ?? {}

          if (
            hashAlgorithm !== `sha${length}` ||
            mgf1HashAlgorithm !== hashAlgorithm
          ) {
            throw new Error(
              `Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${algorithm}.`
            )
          }

          if (saltLength !== undefined && saltLength > length >> 3) {
            throw new Error(
              `Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" ${algorithm}.`
            )
          }
        }
        break
    }
  }
}
