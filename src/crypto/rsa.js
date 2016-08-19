'use strict'

/**
 * @module types
 */

const crypto = require('crypto')
const constants = require('constants')
const Pss = require('../crypto/pss')
const pem = require('../util/pem')

/**
 * RSA-PSS using Node crypto module.
 *
 * This class combines Node's native crypto functionality with PSS padding
 * implemented in this library.
 */
class Rsa {
  constructor (opts) {
    opts = opts || {}

    this.hashAlgorithm = opts.hashAlgorithm || 'sha256'

    this.pss = new Pss({
      hashAlgorithm: this.hashAlgorithm
    })
  }

  /**
   * Sign a message using RSA-PSS.
   *
   * @param {String} privateKey PEM-encoded RSA private key.
   * @param {Buffer} message Message to sign.
   * @return {Buffer} RSA signature.
   */
  sign (privateKey, message) {
    // Calculate modulus bit length
    const modulus = pem.modulusFromPrivateKey(privateKey)
    const modulusHighByteBitLength = modulus[0].toString(2).length
    const modulusBitLength = (modulus.length - 1) * 8 + modulusHighByteBitLength

    // Pad message using PSS
    const encodedMessage = this.pss.encode(message, modulusBitLength - 1)

    // OpenSSL expects the message buffer to be the same length (in bytes) as
    // the modulus.
    const paddedMessage = (encodedMessage.length < modulus.length)
      ? Buffer.concat([Rsa.ZERO_BYTE, encodedMessage])
      : encodedMessage

    // Sign
    return crypto.privateEncrypt(
      {
        key: privateKey,
        padding: constants.RSA_NO_PADDING
      },
      paddedMessage
    )
  }

  /**
   * Verify a RSA-PSS signature.
   *
   * @param {Buffer} modulus RSA public modulus.
   * @param {Buffer} message Message the signature should correspond to.
   * @param {Buffer} signature RSA signature.
   * @return {Boolean} Whether the signature is valid or not.
   */
  verify (modulus, message, signature) {
    // Verify signature
    const publicKey = pem.modulusToPem(modulus)
    const paddedMessage = crypto.publicDecrypt(
      {
        key: publicKey,
        padding: constants.RSA_NO_PADDING
      },
      signature
    )

    // Calculate modulus bit length
    const modulusHighByteBitLength = modulus[0].toString(2).length
    const modulusBitLength = (modulus.length - 1) * 8 + modulusHighByteBitLength

    // OpenSSL returns a buffer based on the bitlength of the modulus, but we
    // a buffer just long enough to fit the bitlength of the encodedMessage,
    // which is one bit shorter.
    const encodedMessage = modulusBitLength % 8 === 1
      ? paddedMessage.slice(1)
      : paddedMessage

    // Verify message padding
    return this.pss.verify(message, encodedMessage, modulusBitLength - 1)
  }
}

// Used to add a zero for padding
Rsa.ZERO_BYTE = new Buffer([0])

module.exports = Rsa
