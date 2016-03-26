'use strict'

const crypto = require('crypto')
const constants = require('constants')
const Pss = require('../crypto/pss')
const pem = require('../util/pem')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const MissingDataError = require('../errors/missing-data-error')

class RsaSha256Fulfillment extends BaseSha256Fulfillment {
  constructor () {
    super()
    this.modulus = null
    this.signature = null
  }

  /**
   * Write static header fields.
   *
   * Some fields are common between the hash and the fulfillment payload. This
   * method writes those field to anything implementing the Writer interface.
   * It is used internally when generating the hash of the condition, when
   * generating the fulfillment payload and when calculating the maximum
   * fulfillment size.
   *
   * @param {Writer|Hasher|Predictor} Target for outputting the header.
   */
  writeCommonHeader (writer) {
    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    writer.writeVarBytes(this.modulus)
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
    // TODO: Validate modulus
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
    const pss = new Pss()
    const modulusHighByteBitLength = this.modulus[0].toString(2).length
    const modulusBitLength = (this.modulus.length - 1) * 8 + modulusHighByteBitLength
    const paddedMessage = pss.encode(message, modulusBitLength - 1)
    this.signature = crypto.privateEncrypt({
      key: privateKey,
      padding: constants.RSA_NO_PADDING
    }, paddedMessage)
  }

  /**
   * Generate the contents of the condition hash.
   *
   * Writes the contents of the condition hash to a Hasher. Used internally by
   * `getCondition`.
   *
   * @param {Hasher} hasher Destination where the hash payload will be written.
   */
  writeHashPayload (hasher) {
    hasher.writeVarUInt(RsaSha256Fulfillment.TYPE_BIT)
    this.writeCommonHeader(hasher)
  }

  /**
   * Parse the payload of an RSA fulfillment.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   */
  parsePayload (reader) {
    this.setPublicModulus(reader.readVarBytes())
    this.setSignature(reader.readVarBytes())
  }

  /**
   * Generate the fulfillment payload.
   *
   * This writes the fulfillment payload to a Writer.
   *
   * @param {Writer} writer Subject for writing the fulfillment payload.
   */
  writePayload (writer) {
    if (!this.signature) {
      throw new MissingDataError('Requires a signature')
    }

    this.writeCommonHeader(writer)
    writer.writeVarBytes(this.signature)
  }

  /**
   * Calculates the longest possible fulfillment length.
   *
   * The longest fulfillment for an RSA condition is the length of a fulfillment
   * where the dynamic message length equals its maximum length.
   *
   * @return {Number} Maximum length of the fulfillment payload
   */
  calculateMaxFulfillmentLength () {
    const predictor = new Predictor()

    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    // Calculate the length that the common header would have
    this.writeCommonHeader(predictor)

    // Signature
    predictor.writeVarBytes(this.modulus)

    return predictor.getSize()
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
    // Verify modulus (correct length)
    if (this.modulus.length < 128 || this.modulus.length > 512) {
      throw new Error('Modulus length is out of range: ' + this.modulus.length)
    }

    // Verify modulus (no leading zeros)
    if (this.modulus[0] === 0) {
      throw new Error('Modulus may not contain leading zeros')
    }

    // Verify signature
    const publicKey = pem.modulusToPem(this.modulus)
    const encodedMessage = crypto.publicDecrypt({
      key: publicKey,
      padding: constants.RSA_NO_PADDING
    }, this.signature)
    const pss = new Pss()
    const modulusHighByteBitLength = this.modulus[0].toString(2).length
    const modulusBitLength = (this.modulus.length - 1) * 8 + modulusHighByteBitLength
    return pss.verify(message, encodedMessage, modulusBitLength)
  }
}

RsaSha256Fulfillment.TYPE_BIT = 0x02

module.exports = RsaSha256Fulfillment
