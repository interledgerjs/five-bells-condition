'use strict'

/**
 * @module types
 */

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256 = require('./base-sha256')
const MissingDataError = require('../errors/missing-data-error')
const isInteger = require('core-js/library/fn/number/is-integer')
const Asn1PrefixFingerprintContents = require('../schemas/fingerprint').PrefixFingerprintContents

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

    this.prefix = new Buffer(0)
    this.subcondition = null
    this.maxMessageLength = 16384
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
   * Set the threshold.
   *
   * Determines the threshold that is used to consider this condition fulfilled.
   * If the number of valid subfulfillments is greater or equal to this number,
   * the threshold condition is considered to be fulfilled.
   *
   * @param {Number} maxMessageLength Integer threshold
   */
  setMaxMessageLength (maxMessageLength) {
    if (!isInteger(maxMessageLength) || maxMessageLength < 0) {
      throw new TypeError('Max message length must be an integer greater than or equal to zero, was: ' +
        maxMessageLength)
    }

    this.maxMessageLength = maxMessageLength
  }

  /**
   * Get types used in this condition.
   *
   * This is a type of condition that contains a subcondition. A complete
   * set of subtypes must contain the set of types that must be supported in
   * order to validate this fulfillment. Therefore, we need to join the type of
   * this condition to the types used in the subcondition.
   *
   * @return {Set<String>} Complete type names for this fulfillment.
   */
  getSubtypes () {
    const subtypes = new Set([...this.subcondition.getSubtypes(), this.subcondition.getTypeName()])

    // Never include our own type as a subtype. The reason is that we already
    // know that the validating implementation knows how to interpret this type,
    // otherwise it wouldn't be able to verify this fulfillment to begin with.
    subtypes.delete(this.constructor.TYPE_NAME)

    return subtypes
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
    if (!this.subcondition) {
      throw new MissingDataError('Requires subcondition')
    }

    return Asn1PrefixFingerprintContents.encode({
      prefix: this.prefix,
      maxMessageLength: this.maxMessageLength,
      subcondition: this.subcondition instanceof Condition
        ? this.subcondition.getAsn1Json()
        : this.subcondition.getCondition().getAsn1Json()
    })
  }

  getAsn1JsonPayload () {
    return {
      prefix: this.prefix,
      maxMessageLength: this.maxMessageLength,
      subfulfillment: this.subcondition.getAsn1Json()
    }
  }

  parseJson (json) {
    this.setPrefix(Buffer.from(json.prefix, 'base64'))
    this.setMaxMessageLength(json.maxMessageLength)
    this.setSubfulfillment(Fulfillment.fromJson(json.subfulfillment))
  }

  parseAsn1JsonPayload (json) {
    this.setPrefix(Buffer.from(json.prefix, 'base64'))
    this.setMaxMessageLength(json.maxMessageLength.toNumber())
    this.setSubfulfillment(Fulfillment.fromAsn1Json(json.subfulfillment))
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

    return Number(this.prefix.length) + this.maxMessageLength + subconditionCost + 1024
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
PrefixSha256.TYPE_NAME = 'prefix-sha-256'
PrefixSha256.TYPE_ASN1_CONDITION = 'prefixSha256Condition'
PrefixSha256.TYPE_ASN1_FULFILLMENT = 'prefixSha256Fulfillment'
PrefixSha256.TYPE_CATEGORY = 'compound'

PrefixSha256.CONSTANT_BASE_COST = 16384
PrefixSha256.CONSTANT_COST_DIVISOR = 256

// DEPRECATED
PrefixSha256.prototype.setSubconditionUri =
  PrefixSha256.prototype.setSubcondition
PrefixSha256.prototype.setSubfulfillmentUri =
  PrefixSha256.prototype.setSubfulfillment

module.exports = PrefixSha256
