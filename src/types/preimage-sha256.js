'use strict'

/**
 * @module types
 */

const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')

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
  /**
   * Generate the contents of the condition hash.
   *
   * Writes the contents of the condition hash to a Hasher. Used internally by
   * `getCondition`.
   *
   * @param {Hasher} hasher Destination where the hash payload will be written.
   *
   * @private
   */
  writeHashPayload (hasher) {
    if (!this.preimage) {
      throw new MissingDataError('Could not calculate hash, no preimage provided')
    }

    hasher.write(this.preimage)
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

  /**
   * Parse the payload of a SHA256 hashlock fulfillment.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   * @param {Number} payloadSize Total size of the fulfillment payload.
   *
   * @private
   */
  parsePayload (reader, payloadSize) {
    this.setPreimage(reader.read(payloadSize))
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
    if (!this.preimage) {
      throw new MissingDataError('Preimage must be specified')
    }

    writer.write(this.preimage)
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
PreimageSha256.FEATURE_BITMASK = 0x03

module.exports = PreimageSha256
