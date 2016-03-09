'use strict'

const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')

const base64url = require('../util/base64url')
const Reader = require('./reader')
const Writer = require('../lib/writer')
const BitmaskRegistry = require('./bitmask-registry')

// Regex for validating conditions
//
// Note that this regex is very strict and specific to the set of conditions
// supported by this implementation.
const CONDITION_REGEX = /^cc:1:[1-9a-f][0-9a-f]{0,2}:[a-zA-Z0-9_-]{43}:[1-9][0-9]{0,50}$/

class Condition {
  /**
   * Create a Condition object from a URI.
   *
   * This method will parse a condition URI and construct a corresponding
   * Condition object.
   *
   * @param {String} serializedCondition URI representing the condition
   * @return {Condition} Resulting object
   */
  static fromUri (serializedCondition) {
    if (typeof serializedCondition !== 'string') {
      throw new Error('Serialized condition must be a string')
    }

    const pieces = serializedCondition.split(':')
    if (pieces[0] !== 'cc') {
      throw new PrefixError('Serialized condition must start with "cc:"')
    }

    if (pieces[1] !== '1') {
      throw new PrefixError('Condition must be version 1')
    }

    if (!CONDITION_REGEX.exec(serializedCondition)) {
      throw new ParseError('Invalid condition format')
    }

    const bitmask = parseInt(pieces[2], 16)
    const hash = base64url.decode(pieces[3])
    const maxFulfillmentLength = parseInt(pieces[4], 10)

    const ConditionClass = BitmaskRegistry.getClassFromBitmask(bitmask).ConditionClass
    const condition = new ConditionClass()
    condition.setHash(hash)
    condition.setMaxFulfillmentLength(maxFulfillmentLength)

    return condition
  }

  /**
   * Create a Condition object from a binary blob.
   *
   * This method will parse a stream of binary data and construct a
   * corresponding Condition object.
   *
   * @param {Reader} reader Binary stream implementing the Reader interface
   * @return {Condition} Resulting object
   */
  static fromBinary (reader) {
    reader = Reader.from(reader)

    const ConditionClass = BitmaskRegistry.getClassFromBitmask(reader.peekVarUInt()).ConditionClass

    // Instantiate condition
    const condition = new ConditionClass()
    condition.parseBinary(reader)

    return condition
  }

  /**
   * Return the bitmask of this condition.
   *
   * For simple condition types this is simply the bit representing this type.
   *
   * For meta-conditions, these are the bits representing the types of the
   * subconditions.
   *
   * @return {Number} Bitmask corresponding to this condition.
   */
  getBitmask () {
    // TODO: Return the right thing for meta-types
    return this.constructor.BITMASK
  }

  /**
   * Return the hash of the condition.
   *
   * A primary component of all conditions is the hash. It encodes the static
   * properties of the condition. This method enables the conditions to be
   * constant size, no matter how complex they actually are. The data used to
   * generate the hash consists of all the static properties of the condition
   * and is provided later as part of the fulfillment.
   *
   * @return {Buffer} Hash of the condition
   */
  getHash () {
    if (!this.hash) {
      throw new MissingDataError('Maximum fulfillment length not set')
    }

    return this.hash
  }

  /**
   * Return the maximum fulfillment length.
   *
   * The maximum fulfillment length is the maximum allowed length for any
   * fulfillment payload to fulfill this condition.
   *
   * The condition defines a maximum fulfillment length which all
   * implementations will enforce. This allows implementations to verify that
   * their local maximum fulfillment size is guaranteed to accomodate any
   * possible fulfillment for this condition.
   *
   * Otherwise an attacker could craft a fulfillment which exceeds the maximum
   * size of one implementation, but meets the maximum size of another, thereby
   * violating the fundamental property that fulfillments are either valid
   * everywhere or nowhere.
   *
   * @return {Number} Maximum length (in bytes) of any fulfillment payload that
   *   fulfills this condition..
   */
  getMaxFulfillmentLength () {
    if (!this.maxFulfillmentLength) {
      throw new MissingDataError('Maximum fulfillment length not set')
    }

    return this.maxFulfillmentLength
  }

  /**
   * Set the maximum fulfillment length.
   *
   * The maximum fulfillment length is normally calculated automatically, when
   * calling `Fulfillment#getCondition`. However, when
   *
   * @param {Number} Maximum fulfillment payload length in bytes.
   */
  setMaxFulfillmentLength (maxFulfillmentLength) {
    this.maxFulfillmentLength = maxFulfillmentLength
  }

  /**
   * Generate the URI form encoding of this condition.
   *
   * Turns the condition into a URI containing only URL-safe characters. This
   * format is convenient for passing around conditions in URLs, JSON and other
   * text-based formats.
   *
   * @return {String} Condition as a URI
   */
  serializeUri () {
    return 'cc:1:' + this.getBitmask().toString(16) +
      ':' + base64url.encode(this.getHash()) +
      ':' + this.getMaxFulfillmentLength()
  }

  /**
   * Serialize condition to a buffer.
   *
   * Encodes the condition as a string of bytes. This is used internally for
   * encoding subconditions, but can also be used to passing around conditions
   * in a binary protocol for instance.
   *
   * @return {Buffer} Serialized condition
   */
  serializeBinary () {
    const writer = new Writer()
    writer.writeVarUInt(this.getBitmask())
    writer.write(this.getHash())
    writer.writeVarUInt(this.getMaxFulfillmentLength())
    return writer.getBuffer()
  }

  /**
   * Ensure the condition is valid according the local rules.
   *
   * Checks the condition against the local bitmask (supported condition types)
   * and the local maximum fulfillment size.
   *
   * @return {Boolean} Whether the condition is valid according to local rules.
   */
  validate () {
    return true
  }
}

module.exports = Condition
