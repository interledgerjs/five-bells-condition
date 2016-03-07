'use strict'

const crypto = require('crypto')
const util = require('../util')
const Condition = require('../lib/condition')
const BaseSha256 = require('./base-sha256')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')

class ThresholdSha256 extends BaseSha256 {
  constructor () {
    super()

    this.subconditions = []
  }

  parseFulfillmentPayload (payload) {
    if (payload.length < 2) {
      throw new ParseError('Payload too short for a THRESHOLD-SHA256 fulfillment')
    }

    const threshold = util.varuint.decode(payload, 0)
    this.setThreshold(threshold)

    const fulfillmentCount = util.varuint.decode(payload, 1)
    let i = fulfillmentCount
    let cursor = 2
    while (i-- > 0) {
      // const weight = 1
      cursor++
      const fulfillment = Condition.fromFulfillmentBinary(payload.slice(cursor))
      this.addSubcondition(fulfillment)
      cursor += fulfillment.serializeFulfillmentBinary().length
    }

    const conditionCount = util.varuint.decode(payload, cursor++)
    i = conditionCount
    while (i-- > 0) {
      // const weight = 1
      cursor++
      const condition = Condition.fromConditionBinary(payload.slice(cursor))
      this.addSubcondition(condition)
      cursor += condition.serializeConditionBinary().length
    }
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
      .map((cond) => cond.serializeConditionBinary())
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
          fulfillment: cond.serializeFulfillmentBinary()
        })
      } catch (err) {
        conditions.push(cond.serializeConditionBinary())
      }
    })

    // Prefer shorter fulfillments
    fulfillments.sort((a, b) => a.fulfillment.length - b.fulfillment.length)

    if (fulfillments.length < this.threshold) {
      throw new MissingDataError('Not enough subconditions have been fulfilled')
    }

    while (fulfillments.length > this.threshold) {
      conditions.push(fulfillments.pop().cond.serializeConditionBinary())
    }

    const payloadComponents = []
    payloadComponents.push(util.varuint.encode(this.threshold))
    payloadComponents.push(util.varuint.encode(fulfillments.length))
    fulfillments.forEach((f) => {
      // TODO: Support custom weights
      payloadComponents.push(new Buffer([1]))
      payloadComponents.push(f.fulfillment)
    })
    payloadComponents.push(util.varuint.encode(conditions.length))
    conditions.forEach((condition) => {
      payloadComponents.push(new Buffer([1]))
      payloadComponents.push(condition)
    })

    return Buffer.concat(payloadComponents)
  }
}

ThresholdSha256.BITMASK = 0x04

module.exports = ThresholdSha256
