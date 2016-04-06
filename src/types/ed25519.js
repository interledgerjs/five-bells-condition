'use strict'

/**
 * @module types
 */

const nacl = require('tweetnacl')
const Fulfillment = require('../lib/fulfillment')
const MissingDataError = require('../errors/missing-data-error')

/**
 * ED25519: Ed25519 signature condition.
 *
 * This condition implements Ed25519 signatures.
 *
 * ED25519 is assigned the type ID 4. It relies only on the ED25519 feature
 * suite which corresponds to a bitmask of 0x20.
 */
class Ed25519 extends Fulfillment {
  constructor () {
    super()
    this.publicKey = null
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
   *
   * @private
   */
  writeCommonHeader (writer) {
    writer.writeVarOctetString(this.publicKey)
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
   * Set the signature.
   *
   * Instead of using the private key to sign using the sign() method, we can
   * also generate the signature elsewhere and pass it in.
   *
   * @param {Buffer} signature 64-byte signature.
   */
  setSignature (signature) {
    if (!Buffer.isBuffer(signature)) {
      throw new Error('Signature must be a Buffer')
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
      throw new Error('Private key must be a Buffer')
    }

    const keyPair = nacl.sign.keyPair.fromSeed(privateKey)
    this.setPublicKey(new Buffer(keyPair.publicKey))

    // This would be the Ed25519ph version:
    // message = crypto.createHash('sha512')
    //   .update(message)
    //   .digest()
    this.signature = new Buffer(nacl.sign.detached(message, keyPair.secretKey))
  }

  /**
   * Generate the condition hash.
   *
   * Since the public key is the same size as the hash we'd be putting out here,
   * we just return the public key.
   *
   * @param {Hasher} hasher Destination where the hash payload will be written.
   */
  generateHash () {
    if (!this.publicKey) {
      throw new MissingDataError('Requires a public publicKey')
    }

    return this.publicKey
  }

  /**
   * Parse the payload of an Ed25519 fulfillment.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   *
   * @private
   */
  parsePayload (reader) {
    this.setPublicKey(reader.readOctetString(Ed25519.PUBKEY_LENGTH))
    this.setSignature(reader.readOctetString(Ed25519.SIGNATURE_LENGTH))
  }

  /**
   * Generate the fulfillment payload.
   *
   * This writes the fulfillment payload to a Writer.
   *
   * @param {Writer} writer Subject for writing the fulfillment payload.
   *
   * @private
   */
  writePayload (writer) {
    writer.writeOctetString(this.publicKey, Ed25519.PUBKEY_LENGTH)
    writer.writeOctetString(this.signature, Ed25519.SIGNATURE_LENGTH)
  }

  /**
   * Calculates the fulfillment length.
   *
   * Ed25519 signatures are constant size. Consequently fulfillments for this
   * type of condition are also constant size.
   *
   * @return {Number} Length of the fulfillment payload.
   *
   * @private
   */
  calculateMaxFulfillmentLength () {
    return Ed25519.FULFILLMENT_LENGTH
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
    return nacl.sign.detached.verify(message, this.signature, this.publicKey)
  }
}

Ed25519.TYPE_ID = 4
Ed25519.FEATURE_BITMASK = 0x20
Ed25519.PUBKEY_LENGTH = 32
Ed25519.SIGNATURE_LENGTH = 64
Ed25519.FULFILLMENT_LENGTH =
  Ed25519.PUBKEY_LENGTH +
  Ed25519.SIGNATURE_LENGTH

module.exports = Ed25519
