'use strict'

const Fulfillment = require('../lib/fulfillment')
const Hasher = require('../lib/hasher')

class BaseSha256 extends Fulfillment {
  /**
   * Calculate condition hash.
   *
   * This method is called internally by `getCondition`. It calculates the
   * condition hash by hashing the hash payload.
   *
   * @return {Buffer} Result from hashing the hash payload.
   */
  generateHash () {
    const hasher = new Hasher('sha256')
    this.writeHashPayload(hasher)
    return hasher.getDigest()
  }
}

module.exports = BaseSha256
