'use strict'

/**
 * @module types
 */

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')
const isInteger = require('../util/is-integer')

const Asn1ThresholdFingerprintContents = require('../schemas/fingerprint').ThresholdFingerprintContents

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
   * Get set of used type names.
   *
   * This is a type of condition that can contain subconditions. A complete
   * set of subtypes must contain all types that must be supported in order to
   * validate this fulfillment. Therefore, we need to join the type of this
   * fulfillment with all of the sets of subtypes for each of the subconditions.
   *
   * @return {Number} Complete set of types for this fulfillment.
   */
  getSubtypes () {
    const typeSets = this.subconditions
      .map(x => Array.from(x.body.getSubtypes()).concat(x.body.getTypeName()))

    const subtypes = new Set(Array.prototype.concat.apply([], typeSets))

    // Never include our own type as a subtype. The reason is that we already
    // know that the validating implementation knows how to interpret this type,
    // otherwise it wouldn't be able to verify this fulfillment to begin with.
    subtypes.delete(this.constructor.TYPE_NAME)

    return subtypes
  }

  /**
   * Comparison function used to pre-sort conditions due to lack of sorting
   * support in our current DER encoder of choice.
   *
   * See: https://github.com/indutny/asn1.js/issues/80
   *
   * @param {Condition} a First condition to compare
   * @param {Condition} b Second condition to compare
   *
   * @private
   */
  static compareConditions (a, b) {
    return Buffer.compare(a.serializeBinary(), b.serializeBinary())
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @return {Buffer} Encoded contents of fingerprint hash.
   *
   * @private
   */
  getFingerprintContents () {
    return Asn1ThresholdFingerprintContents.encode({
      threshold: this.threshold,
      subconditions: this.subconditions
        .map(x => (
          x.body instanceof Condition
          ? x.body
          : x.body.getCondition()
        ))
        .sort(ThresholdSha256.compareConditions)
        .map(x => x.getAsn1Json())
    })
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

    return worstCaseFulfillmentsCost + 1024 * subconditions.length
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
      .sort((a, b) => a - b)
      .slice(-threshold)
      .reduce((total, size) => total + size, 0)
  }

  parseJson (json) {
    this.setThreshold(json.threshold)
    if (json.subfulfillments) {
      for (let fulfillmentJson of json.subfulfillments) {
        this.addSubfulfillment(Fulfillment.fromJson(fulfillmentJson))
      }
    }
    if (json.subconditions) {
      for (let conditionJson of json.subconditions) {
        this.addSubcondition(Condition.fromJson(conditionJson))
      }
    }
  }

  parseAsn1JsonPayload (json) {
    this.setThreshold(json.subfulfillments.length)
    if (json.subfulfillments) {
      for (let fulfillmentJson of json.subfulfillments) {
        this.addSubfulfillment(Fulfillment.fromAsn1Json(fulfillmentJson))
      }
    }
    if (json.subconditions) {
      for (let conditionJson of json.subconditions) {
        this.addSubcondition(Condition.fromAsn1Json(conditionJson))
      }
    }
  }

  getAsn1JsonPayload () {
    const fulfillments = this.subconditions.filter(x => x.type === FULFILLMENT)
      .sort((a, b) => a.body.getCondition().getCost() - b.body.getCondition().getCost())
    const conditions = this.subconditions.filter(x => x.type === CONDITION)

    if (fulfillments.length < this.threshold) {
      throw new Error('Not enough fulfillments')
    }

    const minimalFulfillments = fulfillments
      .slice(0, this.threshold)

    const remainingConditions = conditions
      .map(x => x.body)
      .concat(
        fulfillments
          .slice(this.threshold)
          .map(x => x.body.getCondition())
      )

    return {
      subfulfillments: minimalFulfillments
        .map(x => x.body)
        .sort(ThresholdSha256.compareConditions)
        .map(x => x.getAsn1Json()),
      subconditions: remainingConditions
        .sort(ThresholdSha256.compareConditions)
        .map(x => x.getAsn1Json())
    }
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
ThresholdSha256.TYPE_NAME = 'threshold-sha-256'
ThresholdSha256.TYPE_ASN1_CONDITION = 'thresholdSha256Condition'
ThresholdSha256.TYPE_ASN1_FULFILLMENT = 'thresholdSha256Fulfillment'
ThresholdSha256.TYPE_CATEGORY = 'compound'

// DEPRECATED
ThresholdSha256.prototype.addSubconditionUri =
  ThresholdSha256.prototype.addSubcondition
ThresholdSha256.prototype.addSubfulfillmentUri =
  ThresholdSha256.prototype.addSubfulfillment

module.exports = ThresholdSha256
