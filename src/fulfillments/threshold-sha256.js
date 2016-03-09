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

    this.threshold = null
    this.subconditions = []
    this.subfulfillments = []
  }

  /**
   * Add a subcondition (unfulfilled).
   *
   * This can be used to generate a new threshold condition from a set of
   * subconditions or to provide a non-fulfilled subcondition when creating a
   * threshold fulfillment.
   *
   * @param {Condition} subcondition Condition to add
   */
  addSubcondition (subcondition) {
    if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be objects of type Condition')
    }
    this.subconditions.push(subcondition)
  }

  /**
   * Add a fulfilled subcondition.
   *
   * When constructing a threshold fulfillment, this method allows you to
   * provide a fulfillment for one of the subconditions.
   *
   * Note that you do **not** have to add the subcondition if you're adding the
   * fulfillment. The condition can be calculated from the fulfillment and will
   * be added automatically.
   *
   * @param {Fulfillment} Fulfillment to add
   */
  addSubfulfillment (subfulfillment) {
    if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be objects of type Fulfillment')
    }
    this.subfulfillments.push(subfulfillment)
  }

  /**
   * Returns all subconditions including fulfilled ones.
   *
   * This method returns the subconditions plus all subfulfillments, converted
   * to conditions.
   *
   * @return {Condition[]} Set of subconditions
   */
  getAllSubconditions () {
    return this.subconditions
      .concat(this.subfulfillments.map((f) => f.getCondition()))
  }

  /**
   * Set the threshold.
   *
   * Determines the weighted threshold that is used to consider this condition
   * fulfilled. If the added weight of all valid subfulfillments is greater or
   * equal to this number, the threshold condition is considered to be
   * fulfilled.
   *
   * @param {Number} threshold Integer threshold
   */
  setThreshold (threshold) {
    this.threshold = threshold
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @param {Hasher} hasher Hash generator
   */
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

  /**
   * Calculates the longest possible fulfillment length.
   *
   * In a threshold condition, the maximum length of the fulfillment depends on
   * the maximum lengths of the fulfillments of the subconditions. However,
   * usually not all subconditions must be fulfilled to meet the threshold. This
   * means we only need to consider the worst case where the largest number of
   * largest fulfillments are provided and the smaller fulfillments are not.
   *
   * The algorithm to calculate the worst case fulfillment size is not trivial,
   * however, it does not need to provide the exact worst-case fulfillment
   * length, only an upper bound for it.
   *
   * @return {Number} Maximum length of the fulfillment payload
   */
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

  /**
   * Parse a fulfillment payload.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   */
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

  /**
   * Generate the fulfillment payload.
   *
   * This writes the fulfillment payload to a Writer.
   *
   * @param {Writer} writer Subject for writing the fulfillment payload.
   */
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

  /**
   * Check whether this fulfillment meets all validation criteria.
   *
   * This will validate the subfulfillments and verify that there are enough
   * subfulfillments to meet the threshold.
   *
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate () {
    // TODO: Verify subfulfillments
    // TODO: Verify threshold
    return true
  }
}

ThresholdSha256Fulfillment.BITMASK = 0x04
ThresholdSha256Fulfillment.ConditionClass = ThresholdSha256Condition

module.exports = ThresholdSha256Fulfillment
