'use strict'

/**
 * @module types
 */

const TypeRegistry = require('./type-registry')
const Condition = require('./condition')
const Predictor = require('oer-utils/predictor')
const Writer = require('oer-utils/writer')
const Reader = require('oer-utils/reader')
const base64url = require('../util/base64url')
const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')

// Regex for validating fulfillments
//
// This is a generic, future-proof version of the fulfillment regular
// expression.
const FULFILLMENT_REGEX = /^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$/

/**
 * Base class for fulfillment types.
 */
class Fulfillment {
  /**
   * Create a Fulfillment object from a URI.
   *
   * This method will parse a fulfillment URI and construct a corresponding
   * Fulfillment object.
   *
   * @param {String} serializedFulfillment URI representing the fulfillment
   * @return {Fulfillment} Resulting object
   */
  static fromUri (serializedFulfillment) {
    if (serializedFulfillment instanceof Fulfillment) {
      return serializedFulfillment
    } else if (typeof serializedFulfillment !== 'string') {
      throw new Error('Serialized fulfillment must be a string')
    }

    const pieces = serializedFulfillment.split(':')
    if (pieces[0] !== 'cf') {
      throw new PrefixError('Serialized fulfillment must start with "cf:"')
    }

    if (!Fulfillment.REGEX.exec(serializedFulfillment)) {
      throw new ParseError('Invalid fulfillment format')
    }

    const typeId = parseInt(pieces[1], 16)
    const payload = base64url.decode(pieces[2])

    const ConditionClass = TypeRegistry.getClassFromTypeId(typeId)
    const fulfillment = new ConditionClass()
    fulfillment.parsePayload(Reader.from(payload), payload.length)

    return fulfillment
  }

  /**
   * Create a Fulfillment object from a binary blob.
   *
   * This method will parse a stream of binary data and construct a
   * corresponding Fulfillment object.
   *
   * @param {Reader} reader Binary stream implementing the Reader interface
   * @return {Fulfillment} Resulting object
   */
  static fromBinary (reader) {
    reader = Reader.from(reader)

    const ConditionClass = TypeRegistry.getClassFromTypeId(reader.readUInt16())

    const condition = new ConditionClass()
    const payloadLength = reader.readLengthPrefix()
    condition.parsePayload(reader, payloadLength)

    return condition
  }

  /**
   * Return the type ID of this fulfillment.
   *
   * @return {Number} Type ID as an integer.
   */
  getTypeId () {
    return this.constructor.TYPE_ID
  }

  /**
   * Return the bitmask of this fulfillment.
   *
   * For simple fulfillment types this is simply the bit representing this type.
   *
   * For meta-fulfillments, these are the bits representing the types of the
   * subconditions.
   *
   * @return {Number} Bitmask corresponding to this fulfillment.
   */
  getBitmask () {
    return this.constructor.FEATURE_BITMASK
  }

  /**
   * Generate condition corresponding to this fulfillment.
   *
   * An important property of crypto-conditions is that the condition can always
   * be derived from the fulfillment. This makes it very easy to post
   * fulfillments to a system without having to specify which condition the
   * relate to. The system can keep an index of conditions and look up any
   * matching events related to that condition.
   *
   * @return {Condition} Condition corresponding to this fulfillment.
   */
  getCondition () {
    const condition = new Condition()
    condition.setTypeId(this.getTypeId())
    condition.setBitmask(this.getBitmask())
    condition.setHash(this.generateHash())
    condition.setMaxFulfillmentLength(this.calculateMaxFulfillmentLength())
    return condition
  }

  /**
   * Shorthand for getting condition URI.
   *
   * Stands for getCondition().serializeUri().
   *
   * @return {String} Condition URI.
   */
  getConditionUri () {
    return this.getCondition().serializeUri()
  }

  /**
   * Shorthand for getting condition encoded as binary.
   *
   * Stands for getCondition().serializeBinary().
   *
   * @return {Buffer} Binary encoded condition.
   */
  getConditionBinary () {
    return this.getCondition().serializeBinary()
  }

  /**
   * Generate the hash of the fulfillment.
   *
   * This method is a stub and will be overridden by subclasses.
   *
   * @return {Buffer} Fingerprint of the condition.
   *
   * @private
   */
  generateHash () {
    throw new Error('This method should be implemented by a subclass')
  }

  /**
   * Calculate the maximum length of the fulfillment payload.
   *
   * This implementation works by measuring the length of the fulfillment.
   * Condition types that do not have a constant length will override this
   * method with one that calculates the maximum possible length.
   *
   * @return {Number} Maximum fulfillment length
   *
   * @private
   */
  calculateMaxFulfillmentLength () {
    const predictor = new Predictor()
    this.writePayload(predictor)
    return predictor.getSize()
  }

  /**
   * Generate the URI form encoding of this fulfillment.
   *
   * Turns the fulfillment into a URI containing only URL-safe characters. This
   * format is convenient for passing around fulfillments in URLs, JSON and
   * other text-based formats.
   *
   * @return {String} Fulfillment as a URI
   */
  serializeUri () {
    return 'cf' +
      ':' + base64url.encode(this.serializeBinary())
  }

  /**
   * Serialize fulfillment to a buffer.
   *
   * Encodes the fulfillment as a string of bytes. This is used internally for
   * encoding subfulfillments, but can also be used to passing around
   * fulfillments in a binary protocol for instance.
   *
   * @return {Buffer} Serialized fulfillment
   */
  serializeBinary () {
    const writer = new Writer()
    writer.writeUInt16(this.getTypeId())
    writer.writeVarOctetString(this.serializePayload())
    return writer.getBuffer()
  }

  /**
   * Return the fulfillment payload as a buffer.
   *
   * Note that the fulfillment payload is not the standard format for passing
   * fulfillments in binary protocols. Use `serializeBinary` for that. The
   * fulfillment payload is purely the type-specific data and does not include
   * the bitmask.
   *
   * @return {Buffer} Fulfillment payload
   *
   * @private
   */
  serializePayload () {
    const writer = new Writer()
    this.writePayload(writer)
    return writer.getBuffer()
  }

  /**
   * Validate this fulfillment.
   *
   * This implementation is a stub and will be overridden by the subclasses.
   *
   * @return {Boolean} Validation result
   */
  validate () {
    throw new Error('Not implemented')
  }
}

Fulfillment.REGEX = FULFILLMENT_REGEX

module.exports = Fulfillment
