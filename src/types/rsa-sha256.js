'use strict'

/**
 * @module types
 */

const Rsa = require('../crypto/rsa')
const pem = require('../util/pem')
const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')
const ValidationError = require('../errors/validation-error')
const Asn1RsaFingerprintContents = require('../schemas/fingerprint').RsaFingerprintContents

// Instantiate RSA signer with standard settings
const rsa = new Rsa()

/**
 * RSA-SHA-256: RSA signature condition using SHA-256.
 *
 * This RSA condition uses RSA-PSS padding with SHA-256. The salt length is set
 * equal the digest length of 32 bytes.
 *
 * The public exponent is fixed at 65537 and the public modulus must be between
 * 128 (1017 bits) and 512 bytes (4096 bits) long.
 *
 * RSA-SHA-256 is assigned the type ID 3. It relies on the SHA-256 and RSA-PSS
 * feature suites which corresponds to a feature bitmask of 0x11.
 */
class RsaSha256 extends BaseSha256 {
  constructor () {
    super()
    this.modulus = null
    this.signature = null
  }

  parseJson (json) {
    this.modulus = Buffer.from(json.modulus, 'base64')
    this.signature = Buffer.from(json.signature, 'base64')
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
    if (!this.modulus) {
      throw new MissingDataError('Requires modulus')
    }

    return Asn1RsaFingerprintContents.encode({
      modulus: this.modulus
    })
  }

  getAsn1JsonPayload () {
    return {
      modulus: this.modulus,
      signature: this.signature
    }
  }

  /**
   * Set the public modulus.
   *
   * This is the modulus of the RSA public key. It has to be provided as a raw
   * buffer with no leading zeros.
   *
   * @param {Buffer} modulus Public RSA modulus
   */
  setPublicModulus (modulus) {
    if (!Buffer.isBuffer(modulus)) {
      throw new TypeError('Modulus must be a buffer, was: ' + modulus)
    }

    if (modulus[0] === 0) {
      throw new Error('Modulus may not contain leading zeros')
    }

    if (modulus.length > 512 || modulus.length < 128) {
      throw new Error('Modulus must be between 128 bytes (1017 bits) and ' +
        '512 bytes (4096 bits), was: ' + modulus.length + ' bytes')
    }

    this.modulus = modulus
  }

  /**
   * Set the signature manually.
   *
   * The signature must be a valid RSA-PSS siganture.
   *
   * @param {Buffer} signature RSA signature.
   */
  setSignature (signature) {
    if (!Buffer.isBuffer(signature)) {
      throw new TypeError('Signature must be a buffer, was: ' + signature)
    }

    this.signature = signature
  }

  /**
   * Sign the message.
   *
   * This method will take the provided message and create a signature using the
   * provided RSA private key. The resulting signature is stored in the
   * fulfillment.
   *
   * The key should be provided as a PEM encoded private key string.
   *
   * The message is padded using RSA-PSS with SHA256.
   *
   * @param {Buffer} message Message to sign.
   * @param {String} privateKey RSA private key
   */
  sign (message, privateKey) {
    if (!this.modulus) {
      this.setPublicModulus(pem.modulusFromPrivateKey(privateKey))
    }
    this.signature = rsa.sign(privateKey, message)
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * The cost of the RSA condition is the size of the modulus squared, divided
   * by 64.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    return Math.pow(rsa.getModulusBitLength(this.modulus), 2) >>> RsaSha256.COST_RIGHT_SHIFT
  }

  /**
   * Verify the signature of this RSA fulfillment.
   *
   * The signature of this RSA fulfillment is verified against the provided
   * message and the condition's public modulus.
   *
   * @param {Buffer} message Message to verify.
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate (message) {
    if (!Buffer.isBuffer(message)) {
      throw new Error('Message must be provided as a Buffer, was: ' + message)
    }

    const pssResult = rsa.verify(this.modulus, message, this.signature)

    if (!pssResult) {
      throw new ValidationError('Invalid RSA signature')
    }

    return true
  }
}

RsaSha256.TYPE_ID = 3
RsaSha256.TYPE_NAME = 'rsa-sha-256'
RsaSha256.TYPE_ASN1_CONDITION = 'rsaSha256Condition'
RsaSha256.TYPE_ASN1_FULFILLMENT = 'rsaSha256Fulfillment'
RsaSha256.TYPE_CATEGORY = 'simple'

RsaSha256.COST_RIGHT_SHIFT = 6 // 2^6 = 64

module.exports = RsaSha256
