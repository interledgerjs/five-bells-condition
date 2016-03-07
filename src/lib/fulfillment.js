'use strict'

const BitmaskRegistry = require('./bitmask-registry')
const Predictor = require('./predictor')
const Writer = require('./writer')
const Reader = require('./reader')
const base64url = require('../util/base64url')
const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')

const FULFILLMENT_REGEX = /^cf:1:[1-9a-f][0-9a-f]{0,2}:[a-zA-Z0-9_-]+$/

class Fulfillment {
  static fromUri (serializedFulfillment) {
    if (typeof serializedFulfillment !== 'string') {
      throw new Error('Serialized fulfillment must be a string')
    }

    const pieces = serializedFulfillment.split(':')
    if (pieces[0] !== 'cf') {
      throw new PrefixError('Serialized fulfillment must start with "cf:"')
    }

    if (pieces[1] !== '1') {
      throw new PrefixError('Fulfillment must be version 1')
    }

    if (!FULFILLMENT_REGEX.exec(serializedFulfillment)) {
      throw new ParseError('Invalid fulfillment format')
    }

    const bitmask = parseInt(pieces[2], 16)
    const payload = Reader.from(base64url.decode(pieces[3]))

    const ConditionClass = BitmaskRegistry.getClassFromBitmask(bitmask)
    const fulfillment = new ConditionClass()
    fulfillment.parsePayload(payload)

    return fulfillment
  }

  static fromBinary (reader) {
    reader = Reader.from(reader)

    const ConditionClass = BitmaskRegistry.getClassFromBitmask(reader.readVarUInt())

    const condition = new ConditionClass()
    condition.parsePayload(reader)

    return condition
  }

  getBitmask () {
    return this.constructor.BITMASK
  }

  getCondition () {
    const condition = new this.constructor.ConditionClass()
    condition.setHash(this.generateHash())
    condition.setMaxFulfillmentLength(this.calculateMaxFulfillmentLength())
    return condition
  }

  generateHash () {
    throw new Error('This method should be implemented by a subclass')
  }

  calculateMaxFulfillmentLength () {
    const predictor = new Predictor()
    this.writePayload(predictor)
    return predictor.getSize()
  }

  serializeUri () {
    return 'cf:1:' + this.getBitmask().toString(16) + ':' +
      base64url.encode(this.serializePayload())
  }

  serializeBinary () {
    return Buffer.concat([
      new Buffer([this.getBitmask()]),
      this.serializePayload()
    ])
  }

  serializePayload () {
    const writer = new Writer()
    this.writePayload(writer)
    return writer.getBuffer()
  }

  validate () {
    return true
  }
}

module.exports = Fulfillment
