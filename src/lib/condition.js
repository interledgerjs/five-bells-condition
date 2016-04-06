'use strict'

/**
 * @module types
 */

const TypeRegistry = require('./type-registry')
const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')

const base64url = require('../util/base64url')
const Reader = require('./reader')
const Writer = require('../lib/writer')

// Regex for validating conditions
//
// This is a generic, future-proof version of the crypto-condition regular
// expression.
const CONDITION_REGEX = /^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,15}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$/

// This is a stricter version based on limitations of the current
// implementation. Specifically, we can't handle bitmasks greater than 32 bits.
const CONDITION_REGEX_STRICT = /^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,7}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$/

/**
 * Crypto-condition.
 *
 * A primary design goal of crypto-conditions was to keep the size of conditions
 * constant. Even a complex multi-signature can be represented by the same size
 * condition as a simple hashlock.
 *
 * However, this means that a condition only carries the absolute minimum
 * information required. It does not tell you anything about its structure.
 *
 * All that is included with a condition is the fingerprint (usually a hash of
 * the parts of the fulfillment that are known up-front, e.g. public keys), the
 * maximum fulfillment size, the set of features used and the condition type.
 *
 * This information is just enough that an implementation can tell with
 * certainty whether it would be able to process the corresponding fulfillment.
 */
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

    if (!Condition.REGEX_STRICT.exec(serializedCondition)) {
      throw new ParseError('Invalid condition format')
    }

    const condition = new Condition()
    condition.setTypeId(parseInt(pieces[1], 16))
    condition.setBitmask(parseInt(pieces[2], 16))
    condition.setHash(base64url.decode(pieces[3]))
    condition.setMaxFulfillmentLength(parseInt(pieces[4], 10))

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

    // Instantiate condition
    const condition = new Condition()
    condition.parseBinary(reader)

    return condition
  }

  /**
   * Return the type of this condition.
   *
   * The type is a unique integer ID assigned to each type of condition.
   *
   * @return {Number} Type corresponding to this condition.
   */
  getTypeId () {
    return this.type
  }

  /**
   * Set the type.
   *
   * Sets the type ID for this condition.
   *
   * @param {Number} type Integer representation of type.
   */
  setTypeId (type) {
    this.type = type
  }

  /**
   * Return the bitmask of this condition.
   *
   * For simple condition types this is simply the set of bits representing the
   * features required by the condition type.
   *
   * For structural conditions, this is the bitwise OR of the bitmasks of the
   * condition and all its subconditions, recursively.
   *
   * @return {Number} Bitmask required to verify this condition.
   */
  getBitmask () {
    return this.bitmask
  }

  /**
   * Set the bitmask.
   *
   * Sets the required bitmask to validate a fulfillment for this condition.
   *
   * @param {Number} bitmask Integer representation of bitmask.
   */
  setBitmask (bitmask) {
    this.bitmask = bitmask
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
   * Validate and set the hash of this condition.
   *
   * Typically conditions are generated from fulfillments and the hash is
   * calculated automatically. However, sometimes it may be necessary to
   * construct a condition URI from a known hash. This method enables that case.
   *
   * @param {Buffer} hash Hash as binary.
   */
  setHash (hash) {
    if (!Buffer.isBuffer(hash)) {
      throw new Error('Hash must be a Buffer')
    }

    this.hash = hash
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
    if (typeof this.maxFulfillmentLength !== 'number') {
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
    return 'cc' +
      ':' + this.getTypeId().toString(16) +
      ':' + this.getBitmask().toString(16) +
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
    writer.writeUInt16(this.getTypeId())                // type
    writer.writeVarUInt(this.getBitmask())              // requiredSuites
    writer.writeVarOctetString(this.getHash())          // fingerprint
    writer.writeVarUInt(this.getMaxFulfillmentLength()) // maxFulfillmentLength
    return writer.getBuffer()
  }

  /**
   * Parse any condition in binary format.
   *
   * Will populate the condition object with data from the provided binary
   * stream.
   *
   * @param {Reader} reader Binary stream containing the condition.
   *
   * @private
   */
  parseBinary (reader) {
    this.setTypeId(reader.readUInt16())
    this.setBitmask(reader.readVarUInt())
    // TODO Ensure bitmask is supported?
    this.setHash(reader.readVarOctetString())
    this.setMaxFulfillmentLength(reader.readVarUInt())
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
    // Get class for type ID, throws on error
    TypeRegistry.getClassFromTypeId(this.getTypeId())

    // Bitmask can have at most 32 bits with current implementation
    if (this.getBitmask() > Condition.MAX_SAFE_BITMASK) {
      throw new Error('Bitmask too large to be safely represented')
    }

    // Assert all requested features are supported by this implementation
    if (this.getBitmask() & ~Condition.SUPPORTED_BITMASK) {
      throw new Error('Condition requested unsupported feature suites')
    }

    // Assert the requested fulfillment size is supported by this implementation
    if (this.getMaxFulfillmentLength() > Condition.MAX_FULFILLMENT_LENGTH) {
      throw new Error('Condition requested too large of a max fulfillment size')
    }

    return true
  }
}

// Our current implementation can only represent up to 32 bits for our bitmask
Condition.MAX_SAFE_BITMASK = 0xffffffff

// Feature suites supported by this implementation
Condition.SUPPORTED_BITMASK = 0x3f

// Max fulfillment size supported by this implementation
Condition.MAX_FULFILLMENT_LENGTH = 65535

// Expose regular expressions
Condition.REGEX = CONDITION_REGEX
Condition.REGEX_STRICT = CONDITION_REGEX_STRICT

module.exports = Condition
