'use strict'

const crypto = require('crypto')
const Mgf1 = require('./mgf1')
const xor = require('../util/xor')

const Hasher = require('../lib/hasher')

class Pss {
  constructor (opts) {
    opts = opts || {}

    this.hashAlgorithm = opts.hashAlgorithm || 'sha256'
    this.hashLength = Hasher.getLength(this.hashAlgorithm)
    this.saltLength = this.hashLength

    // Used for testing
    this.forceSalt = null
  }

  /**
  * Create padded message for signing.
  *
  * This is an implementation of EMSA-PSS-ENCODE from RFC3447, section 9.1.1.
  *
  * @param {Buffer} message Message to sign.
  * @param {Number} encodedMessageBits Number of bits of the resulting padded
  *   message.
  * @return {Buffer} Padded message of length encodedMessageBits bits
  */
  encode (message, encodedMessageBits) {
    // Calculate emLen
    const encodedMessageBytes = Math.ceil(encodedMessageBits / 8)
    // Step 2. mHash = Hash(M)
    const messageHash = crypto.createHash(this.hashAlgorithm).update(message).digest()
    // Step 3. If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if (encodedMessageBytes < this.hashLength + this.saltLength + 2) {
      throw new Error('Encoding error: RSA modulus is too small for ' + this.hashAlgorithm)
    }
    // Step 4. Generate a random salt
    const salt = this.forceSalt || crypto.randomBytes(this.saltLength)

    // Step 5. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    // Step 6. H = Hash(M')
    const hash = crypto.createHash(this.hashAlgorithm)
      .update(new Buffer(8).fill(0))
      .update(messageHash)
      .update(salt)
      .digest()

    // Step 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
    //   zero octets.
    // Step 8. Let DB = PS || 0x01 || salt
    const dataBlock = Buffer.concat([
      new Buffer(encodedMessageBytes - this.saltLength - this.hashLength - 2).fill(0),
      new Buffer([1]),
      salt
    ])

    // Step 9. Let dbMask = MGF(H, emLen - hLen - 1)
    const mgf1 = new Mgf1({ hashAlgorithm: this.hashAlgorithm })
    const dataBlockMask = mgf1.generate(hash, encodedMessageBytes - this.hashLength - 1)

    // Step 10. Let maskedDB = DB \xor dbMask
    const maskedDataBlock = xor(dataBlock, dataBlockMask)

    // Step 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
    //   maskedDB to zero.
    maskedDataBlock[0] &= 0xff >>> (encodedMessageBytes * 8 - encodedMessageBits)

    // Step 12. Let EM = maskedDB || H || 0xbc.
    // Step 13. Output EM.
    return Buffer.concat([
      maskedDataBlock,
      hash,
      new Buffer([0xbc])
    ])
  }
}

module.exports = Pss
