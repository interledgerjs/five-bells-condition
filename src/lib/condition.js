'use strict'

/**
 * @module types
 */

const querystring = require('querystring')

const TypeRegistry = require('./type-registry')
const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')

const base64url = require('../util/base64url')
const isInteger = require('../util/is-integer')

const Asn1Condition = require('../schemas/condition').Condition

// Regex for validating conditions
//
// This is a generic, future-proof version of the crypto-condition regular
// expression.
const CONDITION_REGEX = /^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})\?(.+)$/

// This is a stricter version based on limitations of the current
// implementation. Specifically, we can't handle bitmasks greater than 32 bits.
const CONDITION_REGEX_STRICT = CONDITION_REGEX

const INTEGER_REGEX = /^0|[1-9]\d*$/

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
    if (serializedCondition instanceof Condition) {
      return serializedCondition
    } else if (typeof serializedCondition !== 'string') {
      throw new Error('Serialized condition must be a string')
    }

    const pieces = serializedCondition.split(':')
    if (pieces[0] !== 'ni') {
      throw new PrefixError('Serialized condition must start with "ni:"')
    }

    const parsed = Condition.REGEX_STRICT.exec(serializedCondition)
    if (!parsed) {
      throw new ParseError('Invalid condition format')
    }

    const query = querystring.parse(parsed[2])

    const type = TypeRegistry.findByName(query.fpt)

    const cost = INTEGER_REGEX.exec(query.cost)

    if (!cost) {
      throw new ParseError('No or invalid cost provided')
    }

    const condition = new Condition()
    condition.setTypeId(type.typeId)
    if (type.Class.TYPE_CATEGORY === 'compound') {
      condition.setSubtypes(new Set(query.subtypes.split(',')))
    } else {
      condition.setSubtypes(new Set())
    }
    condition.setHash(base64url.decode(parsed[1]))
    condition.setCost(Number(query.cost))

    return condition
  }

  /**
   * Create a Condition object from a binary blob.
   *
   * This method will parse a stream of binary data and construct a
   * corresponding Condition object.
   *
   * @param {Buffer} data Condition in binary format
   * @return {Condition} Resulting object
   */
  static fromBinary (data) {
    const conditionJson = Asn1Condition.decode(data)

    return Condition.fromAsn1Json(conditionJson)
  }

  static fromAsn1Json (json) {
    const type = TypeRegistry.findByAsn1ConditionType(json.type)

    const condition = new Condition()
    condition.setTypeId(type.typeId)
    condition.setHash(json.value.fingerprint)
    condition.setCost(json.value.cost.toNumber())

    if (type.Class.TYPE_CATEGORY === 'compound') {
      const subtypesBuffer = json.value.subtypes.data
      const subtypes = new Set()
      let byteIndex = 0
      while (byteIndex < subtypesBuffer.length) {
        for (let i = 0; i < 8; i++) {
          if ((1 << (7 - i)) & subtypesBuffer[byteIndex]) {
            const typeId = byteIndex * 8 + i
            const typeName = TypeRegistry.findByTypeId(typeId).name
            subtypes.add(typeName)
          }
        }
        byteIndex++
      }
      condition.setSubtypes(subtypes)
    } else {
      condition.setSubtypes(new Set())
    }

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

  getTypeName () {
    return TypeRegistry.findByTypeId(this.type).name
  }

  /**
   * Return the subtypes of this condition.
   *
   * For simple condition types this is simply the set of bits representing the
   * features required by the condition type.
   *
   * For structural conditions, this is the bitwise OR of the bitmasks of the
   * condition and all its subconditions, recursively.
   *
   * @return {Number} Bitmask required to verify this condition.
   */
  getSubtypes () {
    return this.subtypes
  }

  /**
   * Set the subtypes.
   *
   * Sets the required subtypes to validate a fulfillment for this condition.
   *
   * @param {Number} subtypes Integer representation of subtypes.
   */
  setSubtypes (subtypes) {
    this.subtypes = subtypes
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
      throw new MissingDataError('Hash not set')
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
      throw new TypeError('Hash must be a Buffer')
    }

    if (hash.length !== 32) {
      throw new Error('Hash is of invalid length ' + hash.length + ', should be 32')
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
  getCost () {
    if (typeof this.cost !== 'number') {
      throw new MissingDataError('Cost not set')
    }

    return this.cost
  }

  /**
   * Set the maximum fulfillment length.
   *
   * The maximum fulfillment length is normally calculated automatically, when
   * calling `Fulfillment#getCondition`. However, when
   *
   * @param {Number} Maximum fulfillment payload length in bytes.
   */
  setCost (cost) {
    if (!isInteger(cost)) {
      throw new TypeError('Cost must be an integer')
    } else if (cost < 0) {
      throw new TypeError('Cost must be positive or zero')
    }

    this.cost = cost
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
    const ConditionClass = TypeRegistry.findByTypeId(this.type).Class
    const includeSubtypes = ConditionClass.TYPE_CATEGORY === 'compound'
    return 'ni:///sha-256;' +
      base64url.encode(this.getHash()) +
      '?fpt=' + this.getTypeName() +
      '&cost=' + this.getCost() +
      (includeSubtypes ? '&subtypes=' + Array.from(this.getSubtypes()).sort().join(',') : '')
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
    const asn1Json = this.getAsn1Json()
    return Asn1Condition.encode(asn1Json)
  }

  getAsn1Json () {
    const ConditionClass = TypeRegistry.findByTypeId(this.type).Class

    const asn1Json = {
      type: ConditionClass.TYPE_ASN1_CONDITION,
      value: {
        fingerprint: this.getHash(),
        cost: this.getCost()
      }
    }

    if (ConditionClass.TYPE_CATEGORY === 'compound') {
      // Convert the subtypes set of type names to an array of type IDs
      const subtypeIds = Array.from(this.getSubtypes())
        .map(TypeRegistry.findByName)
        .map(x => x.typeId)

      // Allocate a large enough buffer for the subtypes bitarray
      const maxId = subtypeIds.reduce((a, b) => Math.max(a, b), 0)
      const subtypesBuffer = Buffer.alloc(1 + (maxId >>> 3))
      for (let id of subtypeIds) {
        subtypesBuffer[id >>> 3] |= 1 << (7 - id % 8)
      }

      // Determine the number of unused bits at the end
      const trailingZeroBits = 7 - maxId % 8

      asn1Json.value.subtypes = { unused: trailingZeroBits, data: subtypesBuffer }
    }

    return asn1Json
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
    this.setSubtypes(reader.readVarUInt())
    // TODO Ensure subtypes is supported?
    this.setHash(reader.readVarOctetString())
    this.setCost(reader.readVarUInt())
  }

  /**
   * Ensure the condition is valid according the local rules.
   *
   * Checks the condition against the local subtypes (supported condition types)
   * and the local maximum fulfillment size.
   *
   * @return {Boolean} Whether the condition is valid according to local rules.
   */
  validate () {
    // Get info for type ID, throws on error
    TypeRegistry.findByTypeId(this.getTypeId())

    // Bitmask can have at most 32 bits with current implementation
    if (this.getSubtypes() > Condition.MAX_SAFE_SUBTYPES) {
      throw new Error('Bitmask too large to be safely represented')
    }

    // Assert all requested features are supported by this implementation
    if (this.getSubtypes() & ~Condition.SUPPORTED_SUBTYPES) {
      throw new Error('Condition requested unsupported feature suites')
    }

    // Assert the requested fulfillment size is supported by this implementation
    if (this.getCost() > Condition.MAX_COST) {
      throw new Error('Condition requested too large of a max fulfillment size')
    }

    return true
  }
}

// Our current implementation can only represent up to 32 bits for our subtypes
Condition.MAX_SAFE_SUBTYPES = 0xffffffff

// Feature suites supported by this implementation
Condition.SUPPORTED_SUBTYPES = 0x3f

// Max fulfillment size supported by this implementation
Condition.MAX_COST = 2097152

// Expose regular expressions
Condition.REGEX = CONDITION_REGEX
Condition.REGEX_STRICT = CONDITION_REGEX_STRICT

module.exports = Condition
