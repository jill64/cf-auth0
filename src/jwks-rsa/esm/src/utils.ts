import { exportSPKI, importJWK } from '../../../jose/esm/src/index.js'
import { JWK } from '../../../jose/esm/src/types.js'
import JwksError from './errors/JwksError.js'

const resolveAlg = (jwk: JWK) => {
  if (jwk.alg) {
    return jwk.alg
  }

  if (jwk.kty === 'RSA') {
    return 'RS256'
  }

  if (jwk.kty === 'EC') {
    switch (jwk.crv) {
      case 'P-256':
        return 'ES256'
      case 'secp256k1':
        return 'ES256K'
      case 'P-384':
        return 'ES384'
      case 'P-521':
        return 'ES512'
    }
  }

  if (jwk.kty === 'OKP') {
    switch (jwk.crv) {
      case 'Ed25519':
      case 'Ed448':
        return 'EdDSA'
    }
  }

  throw new JwksError('Unsupported JWK')
}

const retrieveSigningKeys = async (jwks: JWK[]) => {
  const results = []

  const jwks2 = jwks
    .filter(({ use }) => use === 'sig' || use === undefined)
    .filter(({ kty }) => kty === 'RSA' || kty === 'EC' || kty === 'OKP')

  for (const jwk of jwks2) {
    try {
      const key = await importJWK({ ...jwk, ext: true }, resolveAlg(jwk))

      if (!('type' in key)) {
        continue
      }

      if (key.type !== 'public') {
        continue
      }

      // @ts-expect-error TODO
      const keyTag: unknown = key[Symbol.toStringTag]

      if (keyTag !== 'CryptoKey' && keyTag !== 'KeyObject') {
        throw new JwksError('Unsupported key type')
      }

      const spki = await exportSPKI(key)
      const getSpki = () => spki

      results.push({
        get publicKey() {
          return getSpki()
        },
        get rsaPublicKey() {
          return getSpki()
        },
        getPublicKey() {
          return getSpki()
        },
        ...(typeof jwk.kid === 'string' && jwk.kid
          ? { kid: jwk.kid }
          : undefined),
        ...(typeof jwk.alg === 'string' && jwk.alg
          ? { alg: jwk.alg }
          : undefined)
      })
    } catch {
      console.error('Failed to create a public key from the JWK')
      continue
    }
  }

  return results
}

export { retrieveSigningKeys }
