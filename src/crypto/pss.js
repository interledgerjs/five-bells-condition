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
    const salt = crypto.randomBytes(this.saltLength)

    // Step 5. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    // Step 6. H = Hash(M')
    const hash = crypto.createHash(this.hashAlgorithm)
      .update(new Buffer(8).fill(0))
      .update(messageHash)
      .update(salt)
      .digest()

    // Step 7. Generate an octet string PS consisting of emLen - sLen - hLen - 2
    //         zero octets.
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
    //          maskedDB to zero.
    maskedDataBlock[0] &= 0xff >>> (encodedMessageBytes * 8 - encodedMessageBits)

    // Step 12. Let EM = maskedDB || H || 0xbc.
    // Step 13. Output EM.
    return Buffer.concat([
      maskedDataBlock,
      hash,
      new Buffer([0xbc])
    ])
  }

  /**
   * Verify that a padded message matches a specimen message.
   *
   * Used for RSA signature verification.
   *
   * This is an implementation of EMSA-PSS-VERIFY from RFC3447, section 9.1.2.
   *
   * @param {Buffer} message Message to be verified.
   * @param {Buffer} encodedMessage Padded message to be compared.
   * @param {Number} encodedMessageBits Number of bits in the padded message.
   * @return {Boolean} Verification result.
   */
  verify (message, encodedMessage, encodedMessageBits) {
    // Calculate emLen
    const encodedMessageBytes = Math.ceil(encodedMessageBits / 8)
    // Step 2. mHash = Hash(M)
    const messageHash = crypto.createHash(this.hashAlgorithm).update(message).digest()
    // Step 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    if (encodedMessageBytes < this.hashLength + this.saltLength + 2) {
      return false
    }
    // Step 4. If the rightmost octet of EM does not have hexadecimal value
    //         0xbc, output "inconsistent" and stop.
    if (encodedMessage[encodedMessage.length - 1] !== 0xbc) {
      return false
    }
    // Step 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //         let H be the next hLen octets.
    const dataBlockLength = encodedMessageBytes - this.hashLength - 1
    const maskedDataBlock = encodedMessage.slice(0, dataBlockLength)
    const hash = encodedMessage.slice(dataBlockLength, dataBlockLength + this.hashLength)
    // Step 6. If the leftmost 8emLen - emBits bits of the leftmost octet in
    //         maskedDB are not all equal to zero, output "inconsistent" and
    //          stop.
    const expectedMask = 0xff >>> (encodedMessageBytes * 8 - encodedMessageBits)
    if (maskedDataBlock[0] & ~expectedMask) {
      return false
    }
    // Step 7. Let dbMask = MGF(H, emLen - hLen - 1).
    const mgf1 = new Mgf1({ hashAlgorithm: this.hashAlgorithm })
    const dataBlockMask = mgf1.generate(hash, encodedMessageBytes - this.hashLength - 1)
    // Step 8. Let DB = maskedDB \xor dbMask.
    const dataBlock = xor(maskedDataBlock, dataBlockMask)
    // Step 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
    //         to zero.
    dataBlock[0] &= expectedMask
    // Step 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
    //          or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    //          position is "position 1") does not have hexadecimal value 0x01,
    //          output "inconsistent" and stop.
    const prefixLength = encodedMessageBytes - this.hashLength - this.saltLength - 2
    for (let i = 0; i < prefixLength; i++) {
      if (dataBlock[i] !== 0) {
        return false
      }
    }
    if (dataBlock[prefixLength] !== 0x01) {
      return false
    }
    // Step 11. Let salt be the last sLen octets of DB.
    const salt = dataBlock.slice(dataBlock.length - this.saltLength)
    // Step 12. Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    // Step 13. Let H' = Hash(M'), an octet string of length hLen.
    const reconstructedHash = crypto.createHash(this.hashAlgorithm)
      .update(new Buffer(8).fill(0))
      .update(messageHash)
      .update(salt)
      .digest()
    // Step 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    return Buffer.compare(hash, reconstructedHash) === 0
  }
}

module.exports = Pss
