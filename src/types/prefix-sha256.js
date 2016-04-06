'use strict'

/**
 * @module types
 */

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256 = require('./base-sha256')
const Predictor = require('../lib/predictor')
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
   * @param {Condition} subcondition Condition that will receive the prefixed
   *   message.
   */
  setSubcondition (subcondition) {
    if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be URIs or objects of type Condition')
    }

    this.subcondition = subcondition
  }

  /**
   * Set the (unfulfilled) subcondition.
   *
   * This will automatically parse the URI and call setSubcondition.
   *
   * @param {String} Subcondition URI.
   */
  setSubconditionUri (subconditionUri) {
    if (typeof subconditionUri !== 'string') {
      throw new Error('Subcondition must be provided as a URI string')
    }

    this.setSubcondition(Condition.fromUri(subconditionUri))
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
   * @param {Fulfillment} fulfillment Fulfillment to use for the subcondition.
   */
  setSubfulfillment (subfulfillment) {
    if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be objects of type Fulfillment')
    }

    this.subcondition = subfulfillment
  }

  /**
   * Set the (fulfilled) subcondition.
   *
   * This will automatically parse the URI and call setSubfulfillment.
   *
   * @param {String} Subfulfillment URI.
   */
  setSubfulfillmentUri (subfulfillmentUri) {
    if (typeof subfulfillmentUri !== 'string') {
      throw new Error('Subfulfillment must be provided as a URI string')
    }

    this.setSubfulfillment(Fulfillment.fromUri(subfulfillmentUri))
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
      throw new Error('Prefix must be a Buffer')
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
   * Calculates the maximum size of any fulfillment for this condition.
   *
   * In a threshold condition, the maximum length of the fulfillment depends on
   * the maximum lengths of the fulfillments of the subconditions. However,
   * usually not all subconditions must be fulfilled in order to meet the
   * threshold.
   *
   * Consequently, this method relies on an algorithm to determine which
   * combination of fulfillments, where no fulfillment can be left out, results
   * in the largest total fulfillment size.
   *
   * @return {Number} Maximum length of the fulfillment payload
   *
   * @private
   */
  calculateMaxFulfillmentLength () {
    // Calculate length of subfulfillment
    const subfulfillmentLength = this.subcondition instanceof Condition
      ? this.subcondition.getMaxFulfillmentLength()
      : this.subcondition.getCondition().getMaxFulfillmentLength()

    // Calculate resulting total maximum fulfillment size
    const predictor = new Predictor()
    predictor.writeVarOctetString(this.prefix)
    predictor.skip(subfulfillmentLength)

    return predictor.getSize()
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
      throw new Error('Message must be provided as a Buffer')
    }

    // Ensure the subfulfillment is valid
    return this.subcondition.validate(Buffer.concat([this.prefix, message]))
  }
}

PrefixSha256.TYPE_ID = 1
PrefixSha256.FEATURE_BITMASK = 0x05

module.exports = PrefixSha256
