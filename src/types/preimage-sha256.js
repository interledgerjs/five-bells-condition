'use strict'

/**
 * @module types
 */

import BaseSha256 from './base-sha256'
import MissingDataError from '../errors/missing-data-error'

/**
 * PREIMAGE-SHA-256: Hashlock condition using SHA-256.
 *
 * This type of condition is also called a hashlock. By creating a hash
 * of a difficult-to-guess 256-bit random or pseudo-random integer it
 * is possible to create a condition which the creator can trivially
 * fulfill by publishing the random value. However, for anyone else,
 * the condition is cryptgraphically hard to fulfill, because they
 * would have to find a preimage for the given condition hash.
 *
 * PREIMAGE-SHA-256 is assigned the type ID 0. It relies on the SHA-256
 * and PREIMAGE feature suites which corresponds to a feature bitmask
 * of 0x03.
 */
class PreimageSha256 extends BaseSha256 {
  constructor () {
    super()
  }

  /**
   * Generate the contents of the condition hash.
   *
   * @return {Buffer} Hash payload.
   *
   * @private
   */
  getFingerprintContents () {
    if (!this.preimage) {
      throw new MissingDataError('Could not calculate hash, no preimage provided')
    }

    return this.preimage
  }

  /**
   * Provide a preimage.
   *
   * The preimage is the only input to a SHA256 hashlock condition.
   *
   * Note that the preimage should contain enough (pseudo-random) data in order
   * to be difficult to guess. A sufficiently large secret seed and a
   * cryptographically secure pseudo-random number generator (CSPRNG) can be
   * used to avoid having to store each individual preimage.
   *
   * @param {Buffer} preimage Secret data that will be hashed to form the condition.
   */
  setPreimage (preimage) {
    if (!Buffer.isBuffer(preimage)) {
      throw new TypeError('Preimage must be a buffer, was: ' + preimage)
    }

    this.preimage = preimage
  }

  parseJson (json) {
    this.preimage = Buffer.from(json.preimage, 'base64')
  }

  getAsn1JsonPayload () {
    return {
      preimage: this.preimage
    }
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * The cost of the preimage condition equals the size of the preimage in
   * bytes.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    if (!this.preimage) {
      throw new MissingDataError('Preimage must be specified')
    }

    return this.preimage.length
  }

  /**
   * Validate this fulfillment.
   *
   * For a SHA256 hashlock fulfillment, successful parsing implies that the
   * fulfillment is valid, so this method is a no-op.
   *
   * @param {Buffer} Message (ignored in this condition type)
   * @return {Boolean} Validation result
   */
  validate (message) {
    return true
  }
}

PreimageSha256.TYPE_ID = 0
PreimageSha256.TYPE_NAME = 'preimage-sha-256'
PreimageSha256.TYPE_ASN1_CONDITION = 'preimageSha256Condition'
PreimageSha256.TYPE_ASN1_FULFILLMENT = 'preimageSha256Fulfillment'
PreimageSha256.TYPE_CATEGORY = 'simple'

export default PreimageSha256;