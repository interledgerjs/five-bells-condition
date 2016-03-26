'use strict'

require('babel-polyfill')
const Condition = require('./src/lib/condition')
const Fulfillment = require('./src/lib/fulfillment')
const BitmaskRegistry = require('./src/lib/bitmask-registry')
const Sha256Fulfillment = require('./src/fulfillments/sha256')
const RsaSha256Fulfillment = require('./src/fulfillments/rsa-sha256')
const PrefixSha256Fulfillment = require('./src/fulfillments/prefix-sha256')
const ThresholdSha256Fulfillment = require('./src/fulfillments/threshold-sha256')
const Ed25519Sha256Fulfillment = require('./src/fulfillments/ed25519-sha256')

const validate = (serializedCondition) => {
  try {
    // Parse condition, throw on error
    const condition = Condition.fromUri(serializedCondition)

    // Validate condition, throw on error
    return {
      valid: condition.validate(),
      error: null
    }
  } catch (error) {
    return { valid: false, error }
  }
}

const validateFulfillment = (serializedFulfillment, message) => {
  try {
    // Parse fulfillment, throw on error
    const fulfillment = Fulfillment.fromUri(serializedFulfillment)

    // Validate fulfillment, throw on error
    return {
      valid: fulfillment.validate(message),
      condition: fulfillment.getCondition().serializeUri(),
      error: null
    }
  } catch (error) {
    return {
      valid: false,
      condition: null,
      error
    }
  }
}

BitmaskRegistry.registerType(Sha256Fulfillment)
BitmaskRegistry.registerType(RsaSha256Fulfillment)
BitmaskRegistry.registerType(PrefixSha256Fulfillment)
BitmaskRegistry.registerType(ThresholdSha256Fulfillment)
BitmaskRegistry.registerType(Ed25519Sha256Fulfillment)

module.exports = {
  Condition,
  Fulfillment,
  BitmaskRegistry,
  Sha256Fulfillment,
  RsaSha256Fulfillment,
  PrefixSha256Fulfillment,
  ThresholdSha256Fulfillment,
  Ed25519Sha256Fulfillment,
  validate,
  validateFulfillment,
  fromConditionUri: Condition.fromUri.bind(Condition),
  fromConditionBinary: Condition.fromBinary.bind(Condition),
  fromFulfillmentUri: Fulfillment.fromUri.bind(Fulfillment),
  fromFulfillmentBinary: Fulfillment.fromBinary.bind(Fulfillment)
}
