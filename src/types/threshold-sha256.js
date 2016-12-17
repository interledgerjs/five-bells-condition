'use strict'

/**
 * @module types
 */

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256 = require('./base-sha256')
const Writer = require('oer-utils/writer')
const MissingDataError = require('../errors/missing-data-error')
const ParseError = require('../errors/parse-error')
const isInteger = require('core-js/library/fn/number/is-integer')

const EMPTY_BUFFER = new Buffer(0)

const CONDITION = 'condition'
const FULFILLMENT = 'fulfillment'

/**
 * THRESHOLD-SHA-256: Threshold gate condition using SHA-256.
 *
 * Threshold conditions can be used to create m-of-n multi-signature groups.
 *
 * Threshold conditions can represent the AND operator by setting the threshold
 * to equal the number of subconditions (n-of-n) or the OR operator by setting
 * the thresold to one (1-of-n).
 *
 * Since threshold conditions operate on conditions, they can be nested as well
 * which allows the creation of deep threshold trees of public keys.
 *
 * By using Merkle trees, threshold fulfillments do not need to to provide the
 * structure of unfulfilled subtrees. That means only the public keys that are
 * actually used in a fulfillment, will actually appear in the fulfillment,
 * saving space.
 *
 * One way to formally interpret a threshold condition is as a booleanthreshold
 * gate. A tree of threshold conditions forms a boolean threshold circuit.
 *
 * THRESHOLD-SHA-256 is assigned the type ID 2. It relies on the SHA-256 and
 * THRESHOLD feature suites which corresponds to a feature bitmask of 0x09.
 */
class ThresholdSha256 extends BaseSha256 {
  constructor () {
    super()

    this.threshold = null
    this.subconditions = []
  }

  /**
   * Add a subcondition (unfulfilled).
   *
   * This can be used to generate a new threshold condition from a set of
   * subconditions or to provide a non-fulfilled subcondition when creating a
   * threshold fulfillment.
   *
   * @param {Condition|String} subcondition Condition object or URI string
   *   representing a new subcondition to be added.
   */
  addSubcondition (subcondition) {
    if (typeof subcondition === 'string') {
      subcondition = Condition.fromUri(subcondition)
    } else if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be URIs or objects of type Condition')
    }

    this.subconditions.push({
      type: CONDITION,
      body: subcondition
    })
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
   * @param {Fulfillment|String} subfulfillment Fulfillment object or URI string
   *   representing a new subfulfillment to be added.
   */
  addSubfulfillment (subfulfillment) {
    if (typeof subfulfillment === 'string') {
      subfulfillment = Fulfillment.fromUri(subfulfillment)
    } else if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be URIs or objects of type Fulfillment')
    }

    this.subconditions.push({
      type: FULFILLMENT,
      body: subfulfillment
    })
  }

  /**
   * Set the threshold.
   *
   * Determines the threshold that is used to consider this condition fulfilled.
   * If the number of valid subfulfillments is greater or equal to this number,
   * the threshold condition is considered to be fulfilled.
   *
   * @param {Number} threshold Integer threshold
   */
  setThreshold (threshold) {
    if (!isInteger(threshold) || threshold < 1) {
      throw new TypeError('Threshold must be a integer greater than zero, was: ' +
        threshold)
    }

    this.threshold = threshold
  }

  /**
   * Get full bitmask.
   *
   * This is a type of condition that can contain subconditions. A complete
   * bitmask must contain the set of types that must be supported in order to
   * validate this fulfillment. Therefore, we need to calculate the bitwise OR
   * of this condition's FEATURE_BITMASK and all subcondition's and
   * subfulfillment's bitmasks.
   *
   * @return {Number} Complete bitmask for this fulfillment.
   */
  getBitmask () {
    let bitmask = super.getBitmask()

    for (let cond of this.subconditions) {
      bitmask |= cond.body.getBitmask()
    }

    return bitmask
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @param {Hasher} hasher Hash generator
   *
   * @private
   */
  writeHashPayload (hasher) {
    if (!this.subconditions.length) {
      throw new MissingDataError('Requires subconditions')
    }

    const subconditions = this.subconditions
      // Serialize each subcondition
      .map((c) => {
        const writer = new Writer()
        writer.write(
          c.type === FULFILLMENT
            ? c.body.getConditionBinary()
            : c.body.serializeBinary()
        )
        return writer.getBuffer()
      })

    // Canonically sort all conditions, first by length, then lexicographically
    const sortedSubconditions = this.constructor.sortBuffers(subconditions)

    hasher.writeUInt32(this.threshold)
    hasher.writeVarUInt(sortedSubconditions.length)
    sortedSubconditions.forEach((c) => hasher.write(c))
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * In a threshold condition, the cost consists of the t most expensive
   * subconditions plus n times 32 where t is the threshold and n is the
   * total number of subconditions.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    // Calculate length of longest fulfillments
    const subconditions = this.subconditions
      .map(this.constructor.getSubconditionCost)

    const worstCaseFulfillmentsCost =
      this.constructor.calculateWorstCaseLength(
        this.threshold,
        subconditions
      )

    if (worstCaseFulfillmentsCost === -Infinity) {
      throw new MissingDataError('Insufficient number of subconditions to meet the threshold')
    }

    return worstCaseFulfillmentsCost + 32 * subconditions.length
  }

  static getSubconditionCost (cond) {
    return cond.type === FULFILLMENT
      ? cond.body.getCondition().getCost()
      : cond.body.getCost()
  }

  /**
   * Calculate the worst case cost of a set of subconditions.
   *
   * Given a set of costs C and a threshold t, it returns the sum of the largest
   * t elements in C.
   *
   * @param {Number} threshold Threshold that the remaining subconditions have
   *   to meet.
   * @param {Number[]} subconditionCosts Set of subconditions.
   * @return {Number} Maximum cost of a valid, minimal set of fulfillments or
   *   -Infinity if there is no valid set.
   *
   * @private
   */
  static calculateWorstCaseLength (threshold, subconditionCosts) {
    if (subconditionCosts.length < threshold) {
      return -Infinity
    }

    return subconditionCosts
      .sort((a, b) => a > b)
      .slice(-threshold)
      .reduce((total, size) => total + size, 0)
  }

  /**
   * Parse a fulfillment payload.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   *
   * @private
   */
  parsePayload (reader) {
    this.setThreshold(reader.readVarUInt())

    const conditionCount = reader.readVarUInt()
    for (let i = 0; i < conditionCount; i++) {
      const fulfillment = reader.readVarOctetString()
      const condition = reader.readVarOctetString()

      if (fulfillment.length && condition.length) {
        throw new ParseError('Subconditions may not provide both subcondition and fulfillment.')
      } else if (fulfillment.length) {
        this.addSubfulfillment(Fulfillment.fromBinary(fulfillment))
      } else if (condition.length) {
        this.addSubcondition(Condition.fromBinary(condition))
      } else {
        throw new ParseError('Subconditions must provide either subcondition or fulfillment.')
      }
    }
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
    const subfulfillments = this.subconditions
      .map((x, i) => (
        x.type === FULFILLMENT
        ? Object.assign({}, x, {
          index: i,
          size: x.body.serializeBinary().length,
          omitSize: x.body.getConditionBinary().length
        })
        : null))
      .filter(Boolean)

    const smallestSet = this.constructor.calculateSmallestValidFulfillmentSet(
      this.threshold,
      subfulfillments
    )

    const optimizedSubfulfillments =
      // Take minimum set of fulfillments and turn rest into conditions
      this.subconditions.map((c, i) => {
        if (c.type === FULFILLMENT && smallestSet.indexOf(i) === -1) {
          return Object.assign({}, c, {
            type: CONDITION,
            body: c.body.getCondition()
          })
        } else {
          return c
        }
      })

    const serializedSubconditions = optimizedSubfulfillments
      .map((cond) => {
        const writer = new Writer()
        writer.writeVarOctetString(cond.type === FULFILLMENT ? cond.body.serializeBinary() : EMPTY_BUFFER)
        writer.writeVarOctetString(cond.type === CONDITION ? cond.body.serializeBinary() : EMPTY_BUFFER)
        return writer.getBuffer()
      })

    const sortedSubconditions = this.constructor.sortBuffers(serializedSubconditions)

    writer.writeVarUInt(this.threshold)
    writer.writeVarUInt(sortedSubconditions.length)
    sortedSubconditions.forEach(writer.write.bind(writer))
  }

  /**
   * Select the smallest valid set of fulfillments.
   *
   * From a set of fulfillments, selects the smallest combination of
   * fulfillments which meets the given threshold.
   *
   * @param {Number} threshold (Remaining) threshold that must be met.
   * @param {Object[]} fulfillments Set of fulfillments
   * @return {Object[]} Minimal set of fulfillments.
   *
   * @private
   */
  static calculateSmallestValidFulfillmentSet (threshold, fulfillments) {
    fulfillments.sort((a, b) => b.size - a.size)

    return fulfillments.slice(0, threshold)
  }

  /**
   * Sort buffers according to spec.
   *
   * Buffers must be sorted first by length. Buffers with the same length are
   * sorted lexicographically.
   *
   * @param {Buffer[]} buffers Set of octet strings to sort.
   * @return {Buffer[]} Sorted buffers.
   *
   * @private
   */
  static sortBuffers (buffers) {
    return buffers.slice().sort((a, b) => (
      a.length !== b.length
      ? a.length - b.length
      : Buffer.compare(a, b)
    ))
  }

  /**
   * Check whether this fulfillment meets all validation criteria.
   *
   * This will validate the subfulfillments and verify that there are enough
   * subfulfillments to meet the threshold.
   *
   * @param {Buffer} message Message to validate against.
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate (message) {
    const fulfillments = this.subconditions.filter((cond) => cond.type === FULFILLMENT)

    // Number of fulfilled conditions must meet the threshold
    if (fulfillments.length < this.threshold) {
      throw new Error('Threshold not met')
    }

    // But the set must be minimal, there mustn't be any fulfillments
    // we could take out
    if (fulfillments.length > this.threshold) {
      throw new Error('Fulfillment is not minimal')
    }

    // Ensure all subfulfillments are valid
    return fulfillments.every((f) => f.body.validate(message))
  }
}

ThresholdSha256.TYPE_ID = 2
ThresholdSha256.FEATURE_BITMASK = 0x09

// DEPRECATED
ThresholdSha256.prototype.addSubconditionUri =
  ThresholdSha256.prototype.addSubcondition
ThresholdSha256.prototype.addSubfulfillmentUri =
  ThresholdSha256.prototype.addSubfulfillment

module.exports = ThresholdSha256
