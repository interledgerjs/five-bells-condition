'use strict'

const nacl = require('tweetnacl')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const MissingDataError = require('../errors/missing-data-error')

class Ed25519Sha256Fulfillment extends BaseSha256Fulfillment {
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
    if (!this.publicKey) {
      throw new MissingDataError('Requires a public publicKey')
    }

    writer.writeVarBytes(this.publicKey)
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
   * Set the public publicKey.
   *
   * This is the Ed25519 public key. It has to be provided as a buffer.
   *
   * @param {Buffer} publicKey Public Ed25519 publicKey
   */
  setPublicKey (publicKey) {
    if (!Buffer.isBuffer(publicKey)) {
      throw new Error('Public key must be a Buffer')
    } else if (publicKey.length !== 32) {
      throw new Error('Public key is incorrect length')
    }

    // TODO Validate public key

    this.publicKey = publicKey
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
    if (!Buffer.isBuffer(message)) {
      throw new Error('Message must be a Buffer')
    }

    this.message = message
  }

  /**
   * Sign the message.
   *
   * This method will take the currently configured values for the message
   * prefix and suffix and create a signature using the provided Ed25519 private
   * key.
   *
   * @param {String} privateKey Ed25519 private key
   */
  sign (privateKey) {
    if (!Buffer.isBuffer(this.messagePrefix)) {
      throw new MissingDataError('Requires a message prefix')
    }
    if (!Buffer.isBuffer(this.message)) {
      throw new MissingDataError('Requires a message')
    }
    if (!Buffer.isBuffer(privateKey)) {
      throw new Error('Private key must be a Buffer')
    }

    const naclPrivateKey = nacl.sign.keyPair.fromSeed(privateKey).secretKey
    const message = Buffer.concat([this.messagePrefix, this.message])
    // This would be the Ed25519ph version:
    // const message = crypto.createHash('sha512')
    //   .update(Buffer.concat([this.messagePrefix, this.message]))
    //   .digest()
    this.signature = new Buffer(nacl.sign.detached(message, naclPrivateKey))
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
    hasher.writeVarUInt(Ed25519Sha256Fulfillment.TYPE_BIT)
    this.writeCommonHeader(hasher)
  }

  /**
   * Parse the payload of an Ed25519 fulfillment.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   */
  parsePayload (reader) {
    this.setPublicKey(reader.readVarBytes())
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
   * The longest fulfillment for an Ed25519 condition is the length of a
   * fulfillment where the dynamic message length equals its maximum length.
   *
   * @return {Number} Maximum length of the fulfillment payload
   */
  calculateMaxFulfillmentLength () {
    const predictor = new Predictor()

    if (!this.publicKey) {
      throw new MissingDataError('Requires a public key')
    }

    // Calculate the length that the common header would have
    this.writeCommonHeader(predictor)

    // Message suffix
    predictor.writeVarUInt(this.maxDynamicMessageLength)
    predictor.skip(this.maxDynamicMessageLength)

    // Signature
    predictor.writeVarBytes(this.publicKey)

    return predictor.getSize()
  }

  /**
   * Verify the signature of this Ed25519 fulfillment.
   *
   * The signature of this Ed25519 fulfillment is verified against the provided
   * message and public key.
   *
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate () {
    // TODO: Validate signature
    return true
  }
}

Ed25519Sha256Fulfillment.TYPE_BIT = 0x08

module.exports = Ed25519Sha256Fulfillment
