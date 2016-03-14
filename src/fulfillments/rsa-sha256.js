'use strict'

const crypto = require('crypto')
const constants = require('constants')
const Pss = require('../crypto/pss.js')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const MissingDataError = require('../errors/missing-data-error')

class RsaSha256Fulfillment extends BaseSha256Fulfillment {
  constructor () {
    super()
    this.messagePrefix = new Buffer('')
    this.maxDynamicMessageLength = 0
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
    writer.writeVarBytes(this.messagePrefix)
    writer.writeVarUInt(this.maxDynamicMessageLength)
  }

  /**
   * Set the fixed message prefix.
   *
   * The fixed prefix is the portion of the message that is determined when the
   * condition is first created.
   *
   * @param {Buffer} messagePrefix Static portion of the message
   */
  setMessagePrefix (messagePrefix) {
    this.messagePrefix = messagePrefix
  }

  /**
   * Set the maximum length of the dynamic message component.
   *
   * The dynamic message is the part of the signed message that is determined at
   * fulfillment time. However, when the condition is first created, we need to
   * know the maximum fulfillment length, which in turn requires us to put a
   * limit on the length of the dynamic message component.
   *
   * If this method is not called, the maximum dynamic message length defaults
   * to zero.
   *
   * @param {Number} maxDynamicMessageLength Maximum length in bytes
   */
  setMaxDynamicMessageLength (maxDynamicMessageLength) {
    this.maxDynamicMessageLength = maxDynamicMessageLength
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
   * Set the dynamic message portion.
   *
   * Part of the signed message (the suffix) can be determined when the
   * condition is being fulfilled.
   *
   * Length may not exceed the maximum dynamic message length.
   *
   * @param {Buffer} message Binary form of dynamic message.
   */
  setMessage (message) {
    this.message = message
  }

  /**
   * Sign the message.
   *
   * This method will take the currently configured values for the message
   * prefix and suffix and create a signature using the provided RSA private
   * key.
   *
   * The key should be provided as a PEM encoded private key string.
   *
   * The message is padded using RSA-PSS with SHA256.
   *
   * @param {String} privateKey RSA private key
   */
  sign (privateKey) {
    const message = Buffer.concat([this.messagePrefix, this.message])
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
    this.setMessagePrefix(reader.readVarBytes())
    this.setMaxDynamicMessageLength(reader.readVarUInt())
    this.setMessage(reader.readVarBytes())
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
    this.writeCommonHeader(writer)
    writer.writeVarBytes(this.message)
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

    // Message suffix
    predictor.writeVarUInt(this.maxDynamicMessageLength)
    predictor.skip(this.maxDynamicMessageLength)

    // Signature
    predictor.writeVarBytes(this.modulus)

    return predictor.getSize()
  }

  /**
   * Verify the signature of this RSA fulfillment.
   *
   * The signature of this RSA fulfillment is verified against the provided
   * message and public modulus.
   *
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate () {
    // TODO: Validate signature
    return true
  }
}

RsaSha256Fulfillment.TYPE_BIT = 0x02

module.exports = RsaSha256Fulfillment
