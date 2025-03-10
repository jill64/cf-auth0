import crypto from 'node:crypto'
import { TextEncoder } from 'node:util'
import { Buffer } from 'node:buffer'

const MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'

const MSG_INVALID_SECRET = 'secret must be a string or buffer or a KeyObject'

const MSG_INVALID_VERIFIER_KEY =
  'key must be a string or a buffer or a KeyObject'

const MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object'

const checkIsPublicKey = (key: unknown) => {
  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return
  }

  if (typeof key !== 'object') {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (!key) {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (!('type' in key)) {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.type !== 'string') {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
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

  throw new TypeError(MSG_INVALID_SIGNER_KEY)
}

const checkIsSecretKey = (key: unknown) => {
  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return key
  }

  if (typeof key !== 'object') {
    throw new TypeError(MSG_INVALID_SECRET)
  }

  if (!key) {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (!('type' in key)) {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (key.type !== 'secret') {
    throw new TypeError(MSG_INVALID_SECRET)
  }

  if (!('export' in key)) {
    throw new TypeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.export !== 'function') {
    throw new TypeError(MSG_INVALID_SECRET)
  }
}

const fromBase64 = (base64: string) =>
  base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

const toBase64 = (base64url: string) => {
  base64url = base64url.toString()

  const padding = 4 - (base64url.length % 4)
  if (padding !== 4) {
    for (let i = 0; i < padding; ++i) {
      base64url += '='
    }
  }

  return base64url.replace(/-/g, '+').replace(/_/g, '/')
}

const bufferOrString = (obj: unknown): obj is Buffer | string =>
  Buffer.isBuffer(obj) || typeof obj === 'string'

const normalizeInput = (thing: unknown) =>
  bufferOrString(thing) ? thing : JSON.stringify(thing)

const createHmacSigner = (bits: string) => (thing: unknown, secret: string) => {
  checkIsSecretKey(secret)
  const thing2 = normalizeInput(thing)

  if (thing2 instanceof Buffer) {
    throw new TypeError('data must be a string or an object')
  }

  const hmac = crypto.createHmac('sha' + bits, secret)
  const sig = (hmac.update(thing2), hmac.digest('base64'))
  return fromBase64(sig)
}

const stringToArrayBufferView = (str: string) => {
  const buffer = new ArrayBuffer(str.length)
  const view = new Uint8Array(buffer)
  for (let i = 0; i < str.length; i++) {
    view[i] = str.charCodeAt(i)
  }
  return view
}

const createHmacVerifier =
  (bits: string) => (thing: unknown, signature: string, secret: string) => {
    const computedSig = createHmacSigner(bits)(thing, secret)

    return crypto.timingSafeEqual(
      stringToArrayBufferView(signature),
      stringToArrayBufferView(computedSig)
    )
  }

const createKeySigner =
  (bits: string) => (thing: unknown, privateKey: string) => {
    checkIsPrivateKey(privateKey)
    const thing2 = normalizeInput(thing)
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    const signer = crypto.createSign('RSA-SHA' + bits)
    if (thing2 instanceof Buffer) {
      throw new TypeError('data must be a string or an object')
    }
    const sig = (signer.update(thing2), signer.sign(privateKey, 'base64'))
    return fromBase64(sig)
  }

const base64ToArrayBuffer = (base64: string) => {
  const binary = Buffer.from(base64, 'base64').toString('binary')
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

const createKeyVerifier =
  (bits: string) =>
  async (thing: unknown, signature: string, publicKey: CryptoKey) => {
    checkIsPublicKey(publicKey)
    const data = normalizeInput(thing)

    if (data instanceof Buffer) {
      throw new TypeError('data must be a string or an object')
    }

    const signature2 = toBase64(signature)

    return await crypto.subtle.verify(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-' + bits,
        saltLength: Number(bits) / 8
      },
      publicKey,
      base64ToArrayBuffer(signature2),
      // @ts-expect-error TODO: fix this
      new TextEncoder().encode(data)
    )
  }

export const jwa = (algorithm: string) => {
  const signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner
  }

  const verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier
  }

  const match = algorithm.match(/^(RS|HS)(256|384|512)$|^(none)$/)

  if (!match) {
    throw new TypeError(`${MSG_INVALID_ALGORITHM}: ${algorithm}`)
  }

  const algo = (match[1] || match[3]).toLowerCase() as 'hs' | 'rs'
  const bits = match[2]

  return {
    sign: signerFactories[algo](bits),
    verify: verifierFactories[algo](bits)
  }
}
