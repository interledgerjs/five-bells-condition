'use strict'

const Fulfillment = require('../lib/fulfillment')
const crypto = require('crypto')

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
    const hash = crypto.createHash('sha256')
    hash.update(this.getFingerprintContents())

    return hash.digest()
  }
}

module.exports = BaseSha256
