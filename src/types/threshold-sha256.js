'use strict'

const crypto = require('crypto')
const util = require('../util')
const BaseSha256 = require('./base-sha256')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')
const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

class ThresholdSha256 extends BaseSha256 {
  constructor () {
    super()

    this.subconditions = []
  }

  parseConditionPayload (payload) {
    if (payload[0] !== ThresholdSha256.BITMASK) {
      throw new UnsupportedBitmaskError('Unexpected bitmask in payload')
    }

    if (payload.length < 34) {
      throw new ParseError('Payload too short for a SHA256 condition')
    }

    this.setHash(payload.slice(1, 33))
    const fulfillmentLength = util.varuint.decode(payload, 33)
    // TODO check for invalid preimage length
    this.setMaxFulfillmentLength(fulfillmentLength)
  }

  parseFulfillmentPayload (payload) {
    if (payload[0] !== ThresholdSha256.BITMASK) {
      throw new UnsupportedBitmaskError('Unexpected bitmask in payload')
    }

    if (payload.length < 2) {
      throw new ParseError('Payload too short for a THRESHOLD-SHA256 fulfillment')
    }

    const fulfillmentLength = util.varuint.decode(payload, 1)
    this.setMaxFulfillmentLength(fulfillmentLength)

    const expectedLength = 1 + util.varstr.predictLength(fulfillmentLength)
    if (payload.length !== expectedLength) {
      throw new ParseError('Payload length ' + payload.length + ' is inconsistent with expected length ' + expectedLength)
    }
    this.setPreimage(payload.slice(1 + util.varuint.predictLength(fulfillmentLength)))
  }

  generateHash () {
    if (!this.subconditions.length) {
      throw new MissingDataError('Requires subconditions')
    }

    const hash = crypto.createHash('sha256')
      .update(new Buffer([ThresholdSha256.BITMASK]))
      .update(util.varuint.encode(this.threshold))
      .update(util.varuint.encode(this.subconditions.length))

    this.subconditions
      .map((cond) => cond.serializeConditionPayload())
      .sort(Buffer.compare)
      .forEach(hash.update.bind(hash))

    return hash.digest()
  }

  getMaxFulfillmentLength () {
    // Calculate length of longest fulfillments
    const worstCaseFulfillmentsLength = this.subconditions
      .map((cond) => cond.getMaxFulfillmentLength())
      .sort()
      .slice(-this.threshold)
      .reduce((a, b) => a + b, 0)

    const maxFulfillmentLength = (
      // Bitmask
      1 +
      // Conditions
      util.varuint.predictLength(this.subconditions.length) +
      worstCaseFulfillmentsLength
    )

    return maxFulfillmentLength
  }

  setMaxFulfillmentLength (fulfillmentLength) {
    this.fulfillmentLength = fulfillmentLength
  }

  addSubcondition (subcondition) {
    this.subconditions.push(subcondition)
  }

  setThreshold (threshold) {
    this.threshold = threshold
  }

  validate () {
    return true
  }

  validateFulfillment () {
    return true
  }

  serializeFulfillmentPayload () {
    const fulfillments = []
    const conditions = []

    // Get as many fulfillments as possible
    this.subconditions.forEach((cond) => {
      try {
        fulfillments.push({
          cond,
          fulfillment: cond.serializeFulfillmentPayload()
        })
      } catch (err) {
        conditions.push(cond.serializeConditionPayload())
      }
    })

    // Prefer shorter fulfillments
    fulfillments.sort((a, b) => a.length - b.length)

    if (fulfillments.length < this.threshold) {
      throw new MissingDataError('Not enough subconditions have been fulfilled')
    }

    while (fulfillments.length > this.threshold) {
      conditions.push(fulfillments.pop().cond.serializeConditionPayload())
    }

    const payloadComponents = [
      new Buffer([ThresholdSha256.BITMASK]),
      util.varuint.encode(this.subconditions.length)
    ].concat(
      conditions,
      fulfillments.map((f) => f.fulfillment)
    )

    return Buffer.concat(payloadComponents)
  }
}

ThresholdSha256.BITMASK = 0x04

module.exports = ThresholdSha256
