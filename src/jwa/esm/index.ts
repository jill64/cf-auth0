import { Buffer } from 'node:buffer'
import type {
  BinaryLike,
  KeyLike,
  KeyObject,
  SignJsonWebKeyInput,
  SignKeyObjectInput,
  SignPrivateKeyInput,
  VerifyJsonWebKeyInput,
  VerifyKeyObjectInput,
  VerifyPublicKeyInput
} from 'node:crypto'
import util from 'node:util'
import bufferEqual from '../../buffer-equal-constant-time/esm/index.js'
import formatEcdsa from '../../ecdsa-sig-formatter/esm/ecdsa-sig-formatter.js'
import {
  constants,
  createHmac,
  createSign,
  createVerify
} from '../../lib/crypto/index.js'

const MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'
const MSG_INVALID_SECRET = 'secret must be a string or buffer or a KeyObject'
const MSG_INVALID_VERIFIER_KEY =
  'key must be a string or a buffer or a KeyObject'
const MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object'

const checkIsPublicKey = (key: unknown) => {
  if (key === null || key === undefined) {
    throw typeError(MSG_INVALID_VERIFIER_KEY, 1, key)
  }

  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_VERIFIER_KEY, 2, key)
  }

  if (!('type' in key) || typeof key.type !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY, 3, key)
  }

  // TODO
  // if (
  //   !('asymmetricKeyType' in key) ||
  //   typeof key.asymmetricKeyType !== 'string'
  // ) {
  //   throw typeError(MSG_INVALID_VERIFIER_KEY, 4, key)
  // }

  if (!('export' in key) || typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_VERIFIER_KEY, 5, key)
  }
}

const checkIsPrivateKey = (key: unknown) => {
  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return
  }

  if (typeof key === 'object') {
    return
  }

  throw typeError(MSG_INVALID_SIGNER_KEY)
}

const checkIsSecretKey = (key: unknown) => {
  if (key === null || key === undefined) {
    throw typeError(MSG_INVALID_SECRET, 1, key)
  }

  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_SECRET, 2, key)
  }

  if (!('type' in key) || key.type !== 'secret') {
    throw typeError(MSG_INVALID_SECRET, 3, key)
  }

  if (!('export' in key) || typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_SECRET, 4, key)
  }
}

const fromBase64 = (base64: string) =>
  base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

const toBase64 = (base64url: string) => {
  let base64url2 = base64url.toString()

  const padding = 4 - (base64url2.length % 4)

  if (padding !== 4) {
    for (let i = 0; i < padding; ++i) {
      base64url2 += '='
    }
  }

  return base64url2.replace(/-/g, '+').replace(/_/g, '/')
}

const typeError = (template: unknown, ...args: unknown[]) => {
  const errMsg = util.format.bind(util, template).apply(null, args)

  return new TypeError(errMsg)
}

const bufferOrString = (obj: unknown): obj is Buffer | string =>
  Buffer.isBuffer(obj) || typeof obj === 'string'

const normalizeInput = (thing: unknown) =>
  bufferOrString(thing) ? thing : JSON.stringify(thing)

const createHmacSigner =
  (bits: number | string) =>
  (thing: unknown, secret: BinaryLike | KeyObject) => {
    checkIsSecretKey(secret)
    const thing2 = normalizeInput(thing)
    const hmac = createHmac('sha' + bits, secret as BinaryLike)
    const sig = (hmac.update(thing2), hmac.digest('base64'))

    return fromBase64(sig)
  }

const createHmacVerifier =
  (bits: number | string) =>
  (thing: unknown, signature: string, secret: BinaryLike | KeyObject) => {
    const computedSig = createHmacSigner(bits)(thing, secret)

    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig))
  }

const createKeySigner =
  (bits: string | number) =>
  (
    thing: BinaryLike | string,
    privateKey:
      | KeyLike
      | SignKeyObjectInput
      | SignPrivateKeyInput
      | SignJsonWebKeyInput
  ) => {
    checkIsPrivateKey(privateKey)

    const thing2 = normalizeInput(thing)

    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = createSign('RSA-SHA' + bits)
    const sig = (signer.update(thing2), signer.sign(privateKey, 'base64'))

    return fromBase64(sig)
  }

const createKeyVerifier =
  (bits: string | number) =>
  (
    thing: unknown,
    signature: string,
    publicKey:
      | KeyLike
      | VerifyKeyObjectInput
      | VerifyPublicKeyInput
      | VerifyJsonWebKeyInput
  ) => {
    checkIsPublicKey(publicKey)
    const thing2 = normalizeInput(thing)
    const signature2 = toBase64(signature)
    const verifier = createVerify('RSA-SHA' + bits)

    verifier.update(thing2)

    return verifier.verify(publicKey, signature2, 'base64')
  }

const createPSSKeySigner =
  (bits: string | number) => (thing: unknown, privateKey: KeyObject) => {
    checkIsPrivateKey(privateKey)
    const thing2 = normalizeInput(thing)
    const signer = createSign('RSA-SHA' + bits)

    const sig =
      (signer.update(thing2),
      signer.sign(
        {
          key: privateKey as unknown as KeyObject,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST
        },
        'base64'
      ))

    return fromBase64(sig)
  }

const createPSSKeyVerifier =
  (bits: string | number) =>
  (thing: unknown, signature: string, publicKey: KeyObject) => {
    checkIsPublicKey(publicKey)

    const thing2 = normalizeInput(thing)
    const signature2 = toBase64(signature)

    const verifier = createVerify('RSA-SHA' + bits)
    verifier.update(thing2)

    return verifier.verify(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST
      },
      signature2,
      'base64'
    )
  }

const createECDSASigner = (bits: number | string) => {
  const inner = createKeySigner(bits)

  return (
    thing: BinaryLike | string,
    privateKey:
      | KeyLike
      | SignKeyObjectInput
      | SignPrivateKeyInput
      | SignJsonWebKeyInput
  ) => {
    const signature = inner(thing, privateKey)

    return formatEcdsa.derToJose(signature, 'ES' + bits)
  }
}

const createECDSAVerifer = (bits: number | string) => {
  const inner = createKeyVerifier(bits)

  return (
    thing: unknown,
    signature: string,
    publicKey:
      | KeyLike
      | VerifyKeyObjectInput
      | VerifyPublicKeyInput
      | VerifyJsonWebKeyInput
  ) => {
    const signature2 = formatEcdsa
      .joseToDer(signature, 'ES' + bits)
      .toString('base64')

    return inner(thing, signature2, publicKey)
  }
}

const createNoneSigner = () => () => ''

const createNoneVerifier = () => (_: unknown, signature: string) =>
  signature === ''

export default (algorithm: string) => {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner
  }

  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier
  }

  const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/)

  if (!match) throw typeError(MSG_INVALID_ALGORITHM, algorithm)

  const algo = (match[1] || match[3]).toLowerCase()
  const bits = match[2]

  return {
    sign: signerFactories[algo as keyof typeof signerFactories](bits),
    verify: verifierFactories[algo as keyof typeof verifierFactories](bits)
  }
}
