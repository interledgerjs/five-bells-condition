'use strict'

/**
 * @module types
 */

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')

/**
 * PREFIX-SHA-256: Prefix condition using SHA-256.
 *
 * A prefix condition will prepend a static prefix to the message before passing
 * the prefixed message on to a single subcondition.
 *
 * You can use prefix conditions to effectively narrow the scope of a public key
 * or set of public keys. Simply take the condition representing the public key
 * and place it as a subcondition in a prefix condition. Now any message passed
 * to the subcondition will be prepended with a prefix.
 *
 * Prefix conditions are especially useful in conjunction with threshold
 * conditions. You could have a group of signers, each using a different prefix
 * to sign a common message.
 *
 * PREFIX-SHA-256 is assigned the type ID 1. It relies on the SHA-256 and PREFIX
 * feature suites which corresponds to a feature bitmask of 0x05.
 */
class PrefixSha256 extends BaseSha256 {
  constructor () {
    super()

    this.subcondition = null
  }

  /**
   * Set the (unfulfilled) subcondition.
   *
   * Each prefix condition builds on an existing condition which is provided via
   * this method.
   *
   * @param {Condition|String} subcondition Condition object or URI string
   *   representing the condition that will receive the prefixed message.
   */
  setSubcondition (subcondition) {
    if (typeof subcondition === 'string') {
      subcondition = Condition.fromUri(subcondition)
    } else if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be URIs or objects of type Condition')
    }

    this.subcondition = subcondition
  }

  /**
   * Set the (fulfilled) subcondition.
   *
   * When constructing a prefix fulfillment, this method allows you to pass in
   * a fulfillment for the condition that will receive the prefixed message.
   *
   * Note that you only have to add either the subcondition or a subfulfillment,
   * but not both.
   *
   * @param {Fulfillment|String} fulfillment Fulfillment object or URI string
   *   representing the fulfillment to use as the subcondition.
   */
  setSubfulfillment (subfulfillment) {
    if (typeof subfulfillment === 'string') {
      subfulfillment = Fulfillment.fromUri(subfulfillment)
    } else if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be objects of type Fulfillment')
    }

    this.subcondition = subfulfillment
  }

  /**
   * Set the prefix.
   *
   * The prefix will be prepended to the message during validation before the
   * message is passed on to the subcondition.
   *
   * @param {Buffer} prefix Prefix to apply to the message.
   */
  setPrefix (prefix) {
    if (!Buffer.isBuffer(prefix)) {
      throw new TypeError('Prefix must be a Buffer, was: ' + prefix)
    }

    this.prefix = prefix
  }

  /**
   * Get full bitmask.
   *
   * This is a type of condition that contains a subcondition. A complete
   * bitmask must contain the set of types that must be supported in order to
   * validate this fulfillment. Therefore, we need to calculate the bitwise OR
   * of this condition's TYPE_BIT and the subcondition's bitmask.
   *
   * @return {Number} Complete bitmask for this fulfillment.
   */
  getBitmask () {
    return super.getBitmask() | this.subcondition.getBitmask()
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
    if (!this.subcondition) {
      throw new MissingDataError('Requires subcondition')
    }

    hasher.writeVarOctetString(this.prefix)
    hasher.write(
      this.subcondition instanceof Condition
      ? this.subcondition.serializeBinary()
      : this.subcondition.getConditionBinary()
    )
  }

  /**
   * Calculate the cost of fulfilling this condition.
   *
   * The cost of the prefix condition equals (1 + l/256) * (16384 + s) where l
   * is the prefix length in bytes and s is the subcondition cost.
   *
   * @return {Number} Expected maximum cost to fulfill this condition
   * @private
   */
  calculateCost () {
    if (!this.prefix) {
      throw new MissingDataError('Prefix must be specified')
    }

    if (!this.subcondition) {
      throw new MissingDataError('Subcondition must be specified')
    }

    const subconditionCost = this.subcondition instanceof Condition
      ? this.subcondition.getCost()
      : this.subcondition.getCondition().getCost()

    return Math.floor(
      (1 + this.prefix.length / PrefixSha256.CONSTANT_COST_DIVISOR) *
      (PrefixSha256.CONSTANT_BASE_COST + subconditionCost)
    )
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
    this.setPrefix(reader.readVarOctetString())
    this.setSubfulfillment(Fulfillment.fromBinary(reader))
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
    if (!(this.subcondition instanceof Fulfillment)) {
      throw new Error('Subcondition must be fulfilled')
    }

    writer.writeVarOctetString(this.prefix)
    writer.write(this.subcondition.serializeBinary())
  }

  /**
   * Check whether this fulfillment meets all validation criteria.
   *
   * This will validate the subfulfillment. The message will be prepended with
   * the prefix before being passed to the subfulfillment's validation routine.
   *
   * @param {Buffer} message Message to validate against.
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate (message) {
    if (!(this.subcondition instanceof Fulfillment)) {
      throw new Error('Subcondition is not a fulfillment')
    }
    if (!Buffer.isBuffer(message)) {
      throw new Error('Message must be provided as a Buffer, was: ' + message)
    }

    // Ensure the subfulfillment is valid
    return this.subcondition.validate(Buffer.concat([this.prefix, message]))
  }
}

PrefixSha256.TYPE_ID = 1
PrefixSha256.FEATURE_BITMASK = 0x05

PrefixSha256.CONSTANT_BASE_COST = 16384
PrefixSha256.CONSTANT_COST_DIVISOR = 256

// DEPRECATED
PrefixSha256.prototype.setSubconditionUri =
  PrefixSha256.prototype.setSubcondition
PrefixSha256.prototype.setSubfulfillmentUri =
  PrefixSha256.prototype.setSubfulfillment

module.exports = PrefixSha256
