'use strict'

const Condition = require('./src/lib/condition')
const Fulfillment = require('./src/lib/fulfillment')
const BitmaskRegistry = require('./src/lib/bitmask-registry')
const Sha256Condition = require('./src/conditions/sha256')
const RsaSha256Condition = require('./src/conditions/rsa-sha256')
const ThresholdSha256Condition = require('./src/conditions/threshold-sha256')
const Sha256Fulfillment = require('./src/fulfillments/sha256')
const RsaSha256Fulfillment = require('./src/fulfillments/rsa-sha256')
const ThresholdSha256Fulfillment = require('./src/fulfillments/threshold-sha256')

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

const validateFulfillment = (serializedFulfillment) => {
  try {
    // Parse fulfillment, throw on error
    const fulfillment = Fulfillment.fromUri(serializedFulfillment)

    // Validate fulfillment, throw on error
    return {
      valid: fulfillment.validate(),
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
BitmaskRegistry.registerMetaType(ThresholdSha256Fulfillment)

module.exports = {
  Condition,
  Fulfillment,
  BitmaskRegistry,
  Sha256Condition,
  RsaSha256Condition,
  ThresholdSha256Condition,
  Sha256Fulfillment,
  RsaSha256Fulfillment,
  ThresholdSha256Fulfillment,
  validate,
  validateFulfillment,
  fromConditionUri: Condition.fromUri.bind(Condition),
  fromConditionBinary: Condition.fromBinary.bind(Condition),
  fromFulfillmentUri: Fulfillment.fromUri.bind(Fulfillment),
  fromFulfillmentBinary: Fulfillment.fromBinary.bind(Fulfillment)
}
