import * as jose from 'jose'
import type { JWK } from 'jws'

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

  throw new Error('[JwksError]: Unsupported JWK')
}

const retrieveSigningKeys = async (jwks: JWK[]) => {
  const results = []

  jwks = jwks
    .filter(({ use }) => use === 'sig' || use === undefined)
    .filter(({ kty }) => kty === 'RSA' || kty === 'EC' || kty === 'OKP')

  for (const jwk of jwks) {
    try {
      // @ts-expect-error TODO: fix this
      const key = await jose.importJWK({ ...jwk, ext: true }, resolveAlg(jwk))
      // @ts-expect-error TODO: fix this
      if (key.type !== 'public') {
        continue
      }
      let getSpki
      // @ts-expect-error TODO: fix this
      switch (key[Symbol.toStringTag]) {
        case 'CryptoKey': {
          // @ts-expect-error TODO: fix this
          const spki = await jose.exportSPKI(key)
          getSpki = () => spki
          break
        }
        case 'KeyObject':
        // Assume legacy Node.js version without the Symbol.toStringTag backported
        // Fall through
        default:
          // @ts-expect-error TODO: fix this
          getSpki = (): string => key.export({ format: 'pem', type: 'spki' })
      }
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
    } catch (e) {
      console.error(e)
      continue
    }
  }

  return results
}

export { retrieveSigningKeys }
