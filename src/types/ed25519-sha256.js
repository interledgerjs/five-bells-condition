'use strict'

/**
 * @module types
 */

const nacl = require('tweetnacl')
const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')
const ValidationError = require('../errors/validation-error')
const Asn1Ed25519FingerprintContents = require('../schemas/fingerprint').Ed25519FingerprintContents

let ed25519
try {
  ed25519 = require('ed25519')
} catch (err) { }

/**
 * ED25519: Ed25519 signature condition.
 *
 * This condition implements Ed25519 signatures.
 *
 * ED25519 is assigned the type ID 4. It relies only on the ED25519 feature
 * suite which corresponds to a bitmask of 0x20.
 */
class Ed25519Sha256 extends BaseSha256 {
  constructor () {
    super()
    this.publicKey = null
    this.signature = null
  }

  /**
   * Set the public publicKey.
   *
   * This is the Ed25519 public key. It has to be provided as a buffer.
   *
   * @param {Buffer} publicKey Public Ed25519 publicKey
   */
  setPublicKey (publicKey) {
    if (!Buffer.isBuffer(publicKey)) {
      throw new TypeError('Public key must be a Buffer, was: ' + publicKey)
    }

    if (publicKey.length !== 32) {
      throw new Error('Public key must be 32 bytes, was: ' + publicKey.length)
    }

    // TODO Validate public key

    this.publicKey = publicKey
  }

  /**
   * Set the signature.
   *
   * Instead of using the private key to sign using the sign() method, we can
   * also generate the signature elsewhere and pass it in.
   *
   * @param {Buffer} signature 64-byte signature.
   */
  setSignature (signature) {
    if (!Buffer.isBuffer(signature)) {
      throw new TypeError('Signature must be a Buffer, was: ' + signature)
    }

    if (signature.length !== 64) {
      throw new Error('Signature must be 64 bytes, was: ' + signature.length)
    }

    this.signature = signature
  }

  /**
   * Sign a message.
   *
   * This method will take a message and an Ed25519 private key and store a
   * corresponding signature in this fulfillment.
   *
   * @param {Buffer} message Message to sign.
   * @param {String} privateKey Ed25519 private key.
   */
  sign (message, privateKey) {
    if (!Buffer.isBuffer(message)) {
      throw new MissingDataError('Message must be a Buffer')
    }
    if (!Buffer.isBuffer(privateKey)) {
      throw new TypeError('Private key must be a Buffer, was: ' + privateKey)
    }
    if (privateKey.length !== 32) {
      throw new Error('Private key must be 32 bytes, was: ' + privateKey.length)
    }

    // This would be the Ed25519ph version:
    // message = crypto.createHash('sha512')
    //   .update(message)
    //   .digest()

    // Use native library if available (~65x faster)
    if (ed25519) {
      const keyPair = ed25519.MakeKeypair(privateKey)
      this.setPublicKey(keyPair.publicKey)
      this.signature = ed25519.Sign(message, keyPair)
    } else {
      const keyPair = nacl.sign.keyPair.fromSeed(privateKey)
      this.setPublicKey(new Buffer(keyPair.publicKey))
      this.signature = new Buffer(nacl.sign.detached(message, keyPair.secretKey))
    }
  }

  parseJson (json) {
    this.setPublicKey(Buffer.from(json.publicKey, 'base64'))
    this.setSignature(Buffer.from(json.signature, 'base64'))
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @return {Buffer} Encoded contents of fingerprint hash.
   *
   * @private
   */
  getFingerprintContents () {
    if (!this.publicKey) {
      throw new MissingDataError('Requires public key')
    }

    return Asn1Ed25519FingerprintContents.encode({
      publicKey: this.publicKey
    })
  }

  getAsn1JsonPayload () {
    return {
      publicKey: this.publicKey,
      signature: this.signature
    }
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * The cost of the Ed25519 condition is 2^17 = 131072.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    return Ed25519Sha256.CONSTANT_COST
  }

  /**
   * Verify the signature of this Ed25519 fulfillment.
   *
   * The signature of this Ed25519 fulfillment is verified against the provided
   * message and public key.
   *
   * @param {Buffer} message Message to validate against.
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate (message) {
    if (!Buffer.isBuffer(message)) {
      throw new TypeError('Message must be a Buffer')
    }

    // Use native library if available (~60x faster)
    let result
    if (ed25519) {
      result = ed25519.Verify(message, this.signature, this.publicKey)
    } else {
      result = nacl.sign.detached.verify(message, this.signature, this.publicKey)
    }

    if (result !== true) {
      throw new ValidationError('Invalid ed25519 signature')
    }

    return true
  }
}

Ed25519Sha256.TYPE_ID = 4
Ed25519Sha256.TYPE_NAME = 'ed25519-sha-256'
Ed25519Sha256.TYPE_ASN1_CONDITION = 'ed25519Sha256Condition'
Ed25519Sha256.TYPE_ASN1_FULFILLMENT = 'ed25519Sha256Fulfillment'
Ed25519Sha256.TYPE_CATEGORY = 'simple'

Ed25519Sha256.CONSTANT_COST = 131072

module.exports = Ed25519Sha256
