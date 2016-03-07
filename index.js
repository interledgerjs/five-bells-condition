'use strict'

const Condition = require('./src/lib/condition')
const Sha256 = require('./src/types/sha256')
const RsaSha256 = require('./src/types/rsa-sha256')
const ThresholdSha256 = require('./src/types/threshold-sha256')

const validate = (serializedCondition) => {
  try {
    // Parse condition, throw on error
    const condition = Condition.fromConditionUri(serializedCondition)

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
    const fulfillment = Condition.fromFulfillmentUri(serializedFulfillment)

    // Validate fulfillment, throw on error
    return {
      valid: fulfillment.validateFulfillment(),
      condition: fulfillment.serializeConditionUri(),
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

Condition.registerType(Sha256)
Condition.registerType(RsaSha256)
Condition.registerMetaType(ThresholdSha256)

module.exports = {
  Condition,
  Sha256,
  RsaSha256,
  ThresholdSha256,
  validate,
  validateFulfillment,
  fromConditionUri: Condition.fromConditionUri.bind(Condition),
  fromConditionBinary: Condition.fromConditionBinary.bind(Condition),
  fromFulfillmentUri: Condition.fromFulfillmentUri.bind(Condition),
  fromFulfillmentBinary: Condition.fromFulfillmentBinary.bind(Condition)
}
