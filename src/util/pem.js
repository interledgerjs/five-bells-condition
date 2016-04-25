'use strict'

/**
 * @module util
 */

const ber = require('asn1').Ber

// Crypto-conditions always use the same RSA exponent, namely 65537
const RSA_EXPONENT = 65537

/**
 * Utilities for RSA-related DER/PEM encoding.
 */
class Pem {
  /**
   * Convert an RSA modulus to a PEM-encoded RSAPublicKey.
   *
   * Encodes the public using the RSAPublicKey format given in
   * RFC 3447, appendix C.
   *
   * This function assumes that the exponent is 65537.
   *
   * @param {Buffer} modulus RSA public modulus.
   * @return {String} PEM-encoded RSA public key.
   */
  static modulusToPem (modulus) {
    // We expect the modulus with no leading zeros
    if (modulus[0] === 0) {
      throw new Error('Modulus may not start with zero')
    }

    // If the high bit is set, we need to prefix a zero
    if (modulus[0] & 0x80) {
      modulus = Buffer.concat([new Buffer([0]), modulus])
    }

    const berWriter = new ber.Writer()
    berWriter.startSequence()
    berWriter.writeBuffer(modulus, 2)
    berWriter.writeInt(RSA_EXPONENT)
    berWriter.endSequence()

    return (
      '-----BEGIN RSA PUBLIC KEY-----\n' +
      berWriter.buffer.toString('base64').match(/.{1,64}/g).join('\n') + '\n' +
      '-----END RSA PUBLIC KEY-----\n'
    )
  }

  /**
   * Retrieve a modulus from a PEM-encoded private key.
   *
   * @param {String} privateKey PEM-encoded RSA private key.
   * @return {Buffer} modulus RSA public modulus.
   */
  static modulusFromPrivateKey (privateKey) {
    const pem = privateKey
      .replace('-----BEGIN RSA PRIVATE KEY-----', '')
      .replace('-----END RSA PRIVATE KEY-----', '')
      .replace(/\s+|\n\r|\n|\r$/gm, '')
    const buffer = new Buffer(pem, 'base64')

    const reader = new ber.Reader(buffer)
    reader.readSequence()
    reader.readString(2, true) // version
    const modulus = reader.readString(2, true) // modulus
    return modulus[0] === 0 ? modulus.slice(1) : modulus
  }
}

module.exports = Pem
