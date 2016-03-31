'use strict'

const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')

class PreimageSha256 extends BaseSha256 {
  /**
   * Generate the contents of the condition hash.
   *
   * Writes the contents of the condition hash to a Hasher. Used internally by
   * `getCondition`.
   *
   * @param {Hasher} hasher Destination where the hash payload will be written.
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
    // TODO: Verify preimage
    this.preimage = preimage
  }

  /**
   * Parse the payload of a SHA256 hashlock fulfillment.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   */
  parsePayload (reader) {
    this.setPreimage(reader.readVarOctetString())
  }

  /**
   * Generate the fulfillment payload.
   *
   * This writes the fulfillment payload to a Writer.
   *
   * @param {Writer} writer Subject for writing the fulfillment payload.
   */
  writePayload (writer) {
    if (!this.preimage) {
      throw new MissingDataError('Preimage must be specified')
    }

    writer.writeVarOctetString(this.preimage)
  }

  /**
   * Validate this fulfillment.
   *
   * For a SHA256 hashlock fulfillment, successful parsing implies that the
   * fulfillment is valid, so this method is a no-op.
   *
   * @return {Boolean} Validation result
   */
  validate () {
    return true
  }
}

PreimageSha256.TYPE_ID = 0
PreimageSha256.FEATURE_BITMASK = 0x03

module.exports = PreimageSha256
