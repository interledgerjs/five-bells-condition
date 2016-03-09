'use strict'

const Condition = require('../lib/condition')
const ParseError = require('../errors/parse-error')

class BaseSha256Condition extends Condition {
  /**
   * Validate and set the hash of this condition.
   *
   * Typically conditions are generated from fulfillments and the hash is
   * calculated automatically. However, sometimes it may be necessary to
   * construct a condition URI from a known hash. This method enables that case.
   *
   * @param {Buffer} hash SHA256 hash as binary.
   */
  setHash (hash) {
    if (!Buffer.isBuffer(hash)) {
      throw new Error('Hash must be a Buffer')
    } else if (hash.length !== 32) {
      throw new Error('Invalid hash: must be 32 bytes long')
    }

    this.hash = hash
  }

  /**
   * Parse any SHA256 condition in binary format.
   *
   * Will populate the condition object with data from the provided binary
   * stream.
   *
   * @param {Reader} reader Binary stream containing the condition.
   */
  parseBinary (reader) {
    const bitmask = reader.readVarUInt()
    if (bitmask !== this.getBitmask()) {
      throw new ParseError('Invalid bitmask')
    }
    this.setHash(reader.read(32))
    this.setMaxFulfillmentLength(reader.readVarUInt())
  }
}

module.exports = BaseSha256Condition
