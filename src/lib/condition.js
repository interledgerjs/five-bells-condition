'use strict'

const varint = require('varint')
const PrefixError = require('../errors/prefix-error')
const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

const util = require('../util')

class Condition {

  static fromCondition (serializedCondition) {
    if (typeof serializedCondition !== 'string') {
      throw new Error('Serialized condition must be a string')
    }

    if (serializedCondition.substr(0, 3) !== 'cc:') {
      throw new PrefixError('Serialized condition must start with "cc:"')
    }

    if (serializedCondition.substr(3, 2) !== '1:') {
      throw new PrefixError('Condition must be version 1')
    }

    const payload = util.decodeBase64url(serializedCondition.substr(5))

    return Condition.fromConditionPayload(payload)
  }

  static fromConditionPayload (payload) {
    const ConditionClass = Condition.getClassFromBitmask(payload)

    // Instantiate condition
    const condition = new ConditionClass()
    condition.parseConditionPayload(payload)

    return condition
  }

  static fromFulfillment (serializedFulfillment) {
    if (typeof serializedFulfillment !== 'string') {
      throw new Error('Serialized fulfillment must be a string')
    }

    if (serializedFulfillment.substr(0, 3) !== 'cf:') {
      throw new PrefixError('Serialized fulfillment must start with "cc:"')
    }

    if (serializedFulfillment.substr(3, 2) !== '1:') {
      throw new PrefixError('Fulfillment must be version 1')
    }

    const payload = util.decodeBase64url(serializedFulfillment.substr(5))

    return Condition.fromFulfillmentPayload(payload)
  }

  static fromFulfillmentPayload (payload) {
    const ConditionClass = Condition.getClassFromBitmask(payload)

    const condition = new ConditionClass()
    condition.parseFulfillmentPayload(payload)

    return condition
  }

  static getClassFromBitmask (payload) {
    // Determine type of condition
    const bitmask = varint.decode(payload, 0)

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
}

Condition.registeredMetaTypes = []
Condition.registeredTypes = []

module.exports = Condition
