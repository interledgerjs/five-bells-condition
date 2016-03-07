'use strict'

const crypto = require('crypto')
const util = require('../util')
const BaseSha256 = require('./base-sha256')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')
const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

class Sha256 extends BaseSha256 {
  parseConditionPayload (payload) {
    if (payload[0] !== Sha256.BITMASK) {
      throw new UnsupportedBitmaskError('Unexpected bitmask in payload')
    }

    if (payload.length < 34) {
      throw new ParseError('Payload too short for a SHA256 condition')
    }

    this.setHash(payload.slice(1, 33))
    this.maxFulfillmentLength = util.varuint.decode(payload, 33)
    // TODO check for invalid fulfillment length
  }

  parseFulfillmentPayload (payload) {
    if (payload.length < 1) {
      throw new ParseError('Payload too short for a SHA256 fulfillment')
    }

    const preimageLength = util.varuint.decode(payload, 0)
    const preimageOffset = util.varuint.predictLength(preimageLength)
    this.setPreimage(payload.slice(preimageOffset, preimageOffset + preimageLength))
  }

  generateHash (hash) {
    if (!this.preimage) {
      throw new MissingDataError('Could not calculate hash, no preimage provided')
    }

    return crypto.createHash('sha256').update(this.preimage).digest()
  }

  setPreimage (preimage) {
    this.preimage = preimage
    this.setPreimageLength(preimage.length)
  }

  setPreimageLength (preimageLength) {
    this.maxFulfillmentLength =
      // Preimage
      util.varuint.predictLength(preimageLength) +
      preimageLength
  }

  validate () {
    return true
  }

  validateFulfillment () {
    return true
  }

  serializeFulfillmentPayload () {
    return Buffer.concat([
      util.varuint.encode(this.preimage.length),
      this.preimage
    ])
  }
}

Sha256.BITMASK = 0x01

module.exports = Sha256
