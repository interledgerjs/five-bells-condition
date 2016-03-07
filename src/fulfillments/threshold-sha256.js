'use strict'

const ThresholdSha256Condition = require('../conditions/threshold-sha256')
const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const MissingDataError = require('../errors/missing-data-error')

class ThresholdSha256Fulfillment extends BaseSha256Fulfillment {
  constructor () {
    super()

    this.subconditions = []
    this.subfulfillments = []
  }

  addSubcondition (subcondition) {
    if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be objects of type Condition')
    }
    this.subconditions.push(subcondition)
  }

  addSubfulfillment (subfulfillment) {
    if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be objects of type Fulfillment')
    }
    this.subfulfillments.push(subfulfillment)
  }

  getAllSubconditions () {
    return this.subconditions
      .concat(this.subfulfillments.map((f) => f.getCondition()))
  }

  setThreshold (threshold) {
    this.threshold = threshold
  }

  writeHashPayload (hasher) {
    if (!this.subconditions.length && !this.subfulfillments.length) {
      throw new MissingDataError('Requires subconditions')
    }

    const subconditions = this.getAllSubconditions()
      .map((cond) => cond.serializeBinary())
      .sort(Buffer.compare)

    hasher.writeVarUInt(ThresholdSha256Fulfillment.BITMASK)
    hasher.writeVarUInt(this.threshold)
    hasher.writeVarUInt(subconditions.length)
    subconditions.forEach(hasher.write.bind(hasher))
  }

  calculateMaxFulfillmentLength () {
    // TODO Currently wrong

    const predictor = new Predictor()

    // Calculate length of longest fulfillments
    const worstCaseFulfillmentsLength = this.getAllSubconditions()
      .map((cond) => cond.getMaxFulfillmentLength())
      .sort()
      .slice(-this.threshold)
      .reduce((a, b) => a + b, 0)

    predictor.writeVarUInt(2)
    predictor.skip(worstCaseFulfillmentsLength)

    return predictor.getSize()
  }

  setPreimage (preimage) {
    this.preimage = preimage
  }

  parsePayload (reader) {
    this.setThreshold(reader.readVarUInt())

    const fulfillmentCount = reader.readVarUInt()
    for (let i = 0; i < fulfillmentCount; i++) {
      // TODO: Read weights
      // const weight = 1
      reader.skipVarUInt()
      this.addSubfulfillment(Fulfillment.fromBinary(reader))
    }

    const conditionCount = reader.readVarUInt()
    for (let i = 0; i < conditionCount; i++) {
      // TODO: Read weights
      // const weight = 1
      reader.skipVarUInt()
      this.addSubcondition(Condition.fromBinary(reader))
    }
  }

  writePayload (writer) {
    const conditions = this.subconditions.slice()
      .map((c) => c.serializeBinary())

    // Get as many fulfillments as possible
    const fulfillments = this.subfulfillments
      .map((fulfillment) => ({ fulfillment, binary: fulfillment.serializeBinary() }))

    // Prefer shorter fulfillments
    fulfillments.sort((a, b) => a.binary.length - b.binary.length)

    if (fulfillments.length < this.threshold) {
      throw new MissingDataError('Not enough subfulfillments')
    }

    while (fulfillments.length > this.threshold) {
      conditions.push(fulfillments.pop().fulfillment.getCondition().serializeBinary())
    }

    writer.writeVarUInt(this.threshold)
    writer.writeVarUInt(fulfillments.length)
    fulfillments.forEach((f) => {
      // TODO: Support custom weights
      writer.writeVarUInt(1)
      writer.write(f.binary)
    })
    writer.writeVarUInt(conditions.length)
    conditions.forEach((condition) => {
      // TODO: Support custom weights
      writer.writeVarUInt(1)
      writer.write(condition)
    })

    return writer.getBuffer()
  }

  validate () {
    return true
  }
}

ThresholdSha256Fulfillment.BITMASK = 0x04
ThresholdSha256Fulfillment.ConditionClass = ThresholdSha256Condition

module.exports = ThresholdSha256Fulfillment
