'use strict'

const PrefixError = require('../errors/prefix-error')
const ParseError = require('../errors/parse-error')
const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

const util = require('../util')

// Regex for validating conditions
//
// Note that this regex is very strict and specific to the set of conditions
// supported by this implementation.
const CONDITION_REGEX = /^cc:1:[1-9a-f][0-9a-f]{0,2}:[a-zA-Z0-9_-]{43}:[1-9][0-9]{0,50}$/
const FULFILLMENT_REGEX = /^cf:1:[1-9a-f][0-9a-f]{0,2}:[a-zA-Z0-9_-]+$/

class Condition {

  static fromConditionUri (serializedCondition) {
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
    const hash = util.decodeBase64url(pieces[3])
    const maxFulfillmentLength = parseInt(pieces[4], 10)

    const ConditionClass = Condition.getClassFromBitmask(bitmask)
    const condition = new ConditionClass()
    condition.setHash(hash)
    condition.setMaxFulfillmentLength(maxFulfillmentLength)

    return condition
  }

  static fromConditionBinary (payload) {
    const ConditionClass = Condition.getClassFromBitmask(util.varuint.decode(payload, 0))

    // Instantiate condition
    const condition = new ConditionClass()
    condition.parseConditionBinary(payload)

    return condition
  }

  static fromFulfillmentUri (serializedFulfillment) {
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
    const payload = util.decodeBase64url(pieces[3])

    const ConditionClass = Condition.getClassFromBitmask(bitmask)
    const fulfillment = new ConditionClass()
    fulfillment.parseFulfillmentPayload(payload)

    return fulfillment
  }

  static fromFulfillmentBinary (payload) {
    const ConditionClass = Condition.getClassFromBitmask(util.varuint.decode(payload, 0))

    const condition = new ConditionClass()
    condition.parseFulfillmentPayload(payload.slice(1))

    return condition
  }

  static getClassFromBitmask (bitmask) {
    // Determine type of condition
    if (bitmask > Number.MAX_SAFE_INTEGER) {
      throw new UnsupportedBitmaskError('Bitmask ' + bitmask + ' is not supported')
    }

    for (let type of Condition.registeredMetaTypes) {
      if (bitmask & type.bitmask) return type.Class
    }

    for (let type of Condition.registeredTypes) {
      if (bitmask === type.bitmask) return type.Class
    }

    throw new UnsupportedBitmaskError('Bitmask ' + bitmask + ' is not supported')
  }

  static registerType (Class) {
    // TODO Do some sanity checks on Class

    Condition.registeredTypes.push({
      bitmask: Class.BITMASK,
      Class
    })
  }

  static registerMetaType (Class) {
    Condition.registeredMetaTypes.push({
      bitmask: Class.BITMASK,
      Class
    })
  }
}

Condition.registeredMetaTypes = []
Condition.registeredTypes = []

module.exports = Condition
