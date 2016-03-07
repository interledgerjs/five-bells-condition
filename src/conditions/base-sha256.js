'use strict'

const Condition = require('../lib/condition')
const ParseError = require('../errors/parse-error')

class BaseSha256Condition extends Condition {
  setHash (hash) {
    if (!Buffer.isBuffer(hash)) {
      throw new Error('Hash must be a Buffer')
    } else if (hash.length !== 32) {
      throw new Error('Invalid hash: must be 32 bytes long')
    }

    this.hash = hash
  }

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
