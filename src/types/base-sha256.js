'use strict'

import Fulfillment from '../lib/fulfillment'
import crypto from 'crypto'

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

export default BaseSha256;