import { importJWK, exportSPKI } from '../../../jose/esm/src/index.js'
import JwksError from './errors/JwksError.js'

// @ts-expect-error TODO
function resolveAlg(jwk) {
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

// @ts-expect-error TODO
async function retrieveSigningKeys(jwks) {
  const results = []

  jwks = jwks
    // @ts-expect-error TODO
    .filter(({ use }) => use === 'sig' || use === undefined)
    // @ts-expect-error TODO
    .filter(({ kty }) => kty === 'RSA' || kty === 'EC' || kty === 'OKP')

  for (const jwk of jwks) {
    try {
      // eslint-disable-next-line no-undef
      console.log('jwk', jwk)
      const key = await importJWK({ ...jwk, ext: true }, resolveAlg(jwk))
      // eslint-disable-next-line no-undef
      console.log('JwkKey', JSON.stringify(key))
      // @ts-expect-error TODO
      if (key.type !== 'public') {
        continue
      }
      let getSpki

      // eslint-disable-next-line no-undef
      console.log(
        'key[Symbol.toStringTag]',
        // @ts-expect-error TODO
        JSON.stringify(key[Symbol.toStringTag])
      )

      // @ts-expect-error TODO
      switch (key[Symbol.toStringTag]) {
        case 'CryptoKey': {
          // @ts-expect-error TODO
          const spki = await exportSPKI(key)
          getSpki = () => spki
          break
        }
        case 'KeyObject':
        // Assume legacy Node.js version without the Symbol.toStringTag backported
        // Fall through
        default:
          // @ts-expect-error TODO
          getSpki = () => key.export({ format: 'pem', type: 'spki' })
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
    } catch {
      // eslint-disable-next-line no-undef
      console.error('Failed to create a public key from the JWK')
      continue
    }
  }

  // eslint-disable-next-line no-undef
  console.log('results', JSON.stringify(results))

  return results
}

export { retrieveSigningKeys }
