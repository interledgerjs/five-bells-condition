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

  static fromBinary (reader) {
    reader = Reader.from(reader)

    const ConditionClass = BitmaskRegistry.getClassFromBitmask(reader.peekVarUInt()).ConditionClass

    // Instantiate condition
    const condition = new ConditionClass()
    condition.parseBinary(reader)

    return condition
  }

  getBitmask () {
    return this.constructor.BITMASK
  }

  getHash () {
    if (!this.hash) {
      throw new MissingDataError('Maximum fulfillment length not set')
    }

    return this.hash
  }

  getMaxFulfillmentLength () {
    if (!this.maxFulfillmentLength) {
      throw new MissingDataError('Maximum fulfillment length not set')
    }

    return this.maxFulfillmentLength
  }

  setMaxFulfillmentLength (maxFulfillmentLength) {
    this.maxFulfillmentLength = maxFulfillmentLength
  }

  serializeUri () {
    return 'cc:1:' + this.getBitmask().toString(16) +
      ':' + base64url.encode(this.getHash()) +
      ':' + this.getMaxFulfillmentLength()
  }

  serializeBinary () {
    const writer = new Writer()
    writer.writeVarUInt(this.getBitmask())
    writer.write(this.getHash())
    writer.writeVarUInt(this.getMaxFulfillmentLength())
    return writer.getBuffer()
  }

  validate () {
    return true
  }
}

module.exports = Condition
