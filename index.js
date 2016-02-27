'use strict'

const Condition = require('./src/lib/condition')
const Sha256 = require('./src/types/sha256')
const RsaSha256 = require('./src/types/rsa-sha256')
const ThresholdSha256 = require('./src/types/threshold-sha256')

const validate = (serializedCondition) => {
  try {
    // Parse condition, throw on error
    const condition = Condition.fromCondition(serializedCondition)

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
    const fulfillment = Condition.fromFulfillment(serializedFulfillment)

    // Validate fulfillment, throw on error
    return {
      valid: fulfillment.validateFulfillment(),
      condition: fulfillment.serializeCondition(),
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
  fromCondition: Condition.fromCondition.bind(Condition),
  fromFulfillment: Condition.fromFulfillment.bind(Condition)
}
