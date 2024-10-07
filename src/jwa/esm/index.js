import { Buffer } from 'node:buffer'
import crypto from 'node:crypto'
import util from 'node:util'
import bufferEqual from '../../buffer-equal-constant-time/esm/index.js'
import formatEcdsa from '../../ecdsa-sig-formatter/esm/ecdsa-sig-formatter.js'

var MSG_INVALID_ALGORITHM =
  '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'
var MSG_INVALID_SECRET = 'secret must be a string or buffer'
var MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer'
var MSG_INVALID_SIGNER_KEY = 'key must be a string, a buffer or an object'

var supportsKeyObjects = typeof crypto.createPublicKey === 'function'
if (supportsKeyObjects) {
  MSG_INVALID_VERIFIER_KEY += ' or a KeyObject'
  MSG_INVALID_SECRET += 'or a KeyObject'
}

// @ts-expect-error TODO
function checkIsPublicKey(key) {
  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return
  }

  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.type !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.asymmetricKeyType !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }
}

// @ts-expect-error TODO
function checkIsPrivateKey(key) {
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

// @ts-expect-error TODO
function checkIsSecretKey(key) {
  if (Buffer.isBuffer(key)) {
    return
  }

  if (typeof key === 'string') {
    return key
  }

  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_SECRET)
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_SECRET)
  }

  if (key.type !== 'secret') {
    throw typeError(MSG_INVALID_SECRET)
  }

  if (typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_SECRET)
  }
}

// @ts-expect-error TODO
function fromBase64(base64) {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

// @ts-expect-error TODO
function toBase64(base64url) {
  base64url = base64url.toString()

  var padding = 4 - (base64url.length % 4)
  if (padding !== 4) {
    for (var i = 0; i < padding; ++i) {
      base64url += '='
    }
  }

  return base64url.replace(/-/g, '+').replace(/_/g, '/')
}

// @ts-expect-error TODO
function typeError(template) {
  // @ts-expect-error TODO
  var args = [].slice.call(arguments, 1)
  var errMsg = util.format.bind(util, template).apply(null, args)
  return new TypeError(errMsg)
}

// @ts-expect-error TODO
function bufferOrString(obj) {
  return Buffer.isBuffer(obj) || typeof obj === 'string'
}

// @ts-expect-error TODO
function normalizeInput(thing) {
  if (!bufferOrString(thing)) thing = JSON.stringify(thing)
  return thing
}

// @ts-expect-error TODO
function createHmacSigner(bits) {
  // @ts-expect-error TODO
  return function sign(thing, secret) {
    checkIsSecretKey(secret)
    thing = normalizeInput(thing)
    var hmac = crypto.createHmac('sha' + bits, secret)
    var sig = (hmac.update(thing), hmac.digest('base64'))
    return fromBase64(sig)
  }
}

// @ts-expect-error TODO
function createHmacVerifier(bits) {
  // @ts-expect-error TODO
  return function verify(thing, signature, secret) {
    var computedSig = createHmacSigner(bits)(thing, secret)
    return bufferEqual(Buffer.from(signature), Buffer.from(computedSig))
  }
}

// @ts-expect-error TODO
function createKeySigner(bits) {
  // @ts-expect-error TODO
  return function sign(thing, privateKey) {
    checkIsPrivateKey(privateKey)
    thing = normalizeInput(thing)
    // Even though we are specifying "RSA" here, this works with ECDSA
    // keys as well.
    var signer = crypto.createSign('RSA-SHA' + bits)
    var sig = (signer.update(thing), signer.sign(privateKey, 'base64'))
    return fromBase64(sig)
  }
}

// @ts-expect-error TODO
function createKeyVerifier(bits) {
  // @ts-expect-error TODO
  return function verify(thing, signature, publicKey) {
    checkIsPublicKey(publicKey)
    thing = normalizeInput(thing)
    signature = toBase64(signature)
    var verifier = crypto.createVerify('RSA-SHA' + bits)
    verifier.update(thing)
    return verifier.verify(publicKey, signature, 'base64')
  }
}

// @ts-expect-error TODO
function createPSSKeySigner(bits) {
  // @ts-expect-error TODO
  return function sign(thing, privateKey) {
    checkIsPrivateKey(privateKey)
    thing = normalizeInput(thing)
    var signer = crypto.createSign('RSA-SHA' + bits)
    var sig =
      (signer.update(thing),
      signer.sign(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        },
        'base64'
      ))
    return fromBase64(sig)
  }
}

// @ts-expect-error TODO
function createPSSKeyVerifier(bits) {
  // @ts-expect-error TODO
  return function verify(thing, signature, publicKey) {
    checkIsPublicKey(publicKey)
    thing = normalizeInput(thing)
    signature = toBase64(signature)
    var verifier = crypto.createVerify('RSA-SHA' + bits)
    verifier.update(thing)
    return verifier.verify(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      },
      signature,
      'base64'
    )
  }
}

// @ts-expect-error TODO
function createECDSASigner(bits) {
  var inner = createKeySigner(bits)
  return function sign() {
    // @ts-expect-error TODO
    var signature = inner.apply(null, arguments)
    signature = formatEcdsa.derToJose(signature, 'ES' + bits)
    return signature
  }
}

// @ts-expect-error TODO
function createECDSAVerifer(bits) {
  var inner = createKeyVerifier(bits)
  // @ts-expect-error TODO
  return function verify(thing, signature, publicKey) {
    signature = formatEcdsa.joseToDer(signature, 'ES' + bits).toString('base64')
    var result = inner(thing, signature, publicKey)
    return result
  }
}

function createNoneSigner() {
  return function sign() {
    return ''
  }
}

function createNoneVerifier() {
  // @ts-expect-error TODO
  return function verify(thing, signature) {
    return signature === ''
  }
}

// @ts-expect-error TODO
export default function jwa(algorithm) {
  var signerFactories = {
    hs: createHmacSigner,
    rs: createKeySigner,
    ps: createPSSKeySigner,
    es: createECDSASigner,
    none: createNoneSigner
  }
  var verifierFactories = {
    hs: createHmacVerifier,
    rs: createKeyVerifier,
    ps: createPSSKeyVerifier,
    es: createECDSAVerifer,
    none: createNoneVerifier
  }
  var match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/)
  if (!match) throw typeError(MSG_INVALID_ALGORITHM, algorithm)
  var algo = (match[1] || match[3]).toLowerCase()
  var bits = match[2]

  return {
    // @ts-expect-error TODO
    sign: signerFactories[algo](bits),
    // @ts-expect-error TODO
    verify: verifierFactories[algo](bits)
  }
}
