'use strict'

const Sha256Condition = require('../conditions/sha256')
const BaseSha256Fulfillment = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')

class Sha256Fulfillment extends BaseSha256Fulfillment {
  writeHashPayload (hasher) {
    if (!this.preimage) {
      throw new MissingDataError('Could not calculate hash, no preimage provided')
    }

    hasher.write(this.preimage)
  }

  setPreimage (preimage) {
    this.preimage = preimage
  }

  parsePayload (reader) {
    this.setPreimage(reader.readVarBytes())
  }

  writePayload (writer) {
    if (!this.preimage) {
      throw new MissingDataError('Preimage must be specified')
    }

    writer.writeVarBytes(this.preimage)
  }
}

Sha256Fulfillment.BITMASK = 0x01
Sha256Fulfillment.ConditionClass = Sha256Condition

module.exports = Sha256Fulfillment
