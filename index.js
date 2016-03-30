'use strict'

require('babel-polyfill')
const Condition = require('./src/lib/condition')
const Fulfillment = require('./src/lib/fulfillment')
const TypeRegistry = require('./src/lib/type-registry')
const PreimageSha256Fulfillment = require('./src/fulfillments/preimage-sha256')
const PrefixSha256Fulfillment = require('./src/fulfillments/prefix-sha256')
const ThresholdSha256Fulfillment = require('./src/fulfillments/threshold-sha256')
const RsaSha256Fulfillment = require('./src/fulfillments/rsa-sha256')
const Ed25519Fulfillment = require('./src/fulfillments/ed25519')

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

TypeRegistry.registerType(PreimageSha256Fulfillment)
TypeRegistry.registerType(PrefixSha256Fulfillment)
TypeRegistry.registerType(ThresholdSha256Fulfillment)
TypeRegistry.registerType(RsaSha256Fulfillment)
TypeRegistry.registerType(Ed25519Fulfillment)

module.exports = {
  Condition,
  Fulfillment,
  TypeRegistry,
  PreimageSha256Fulfillment,
  RsaSha256Fulfillment,
  PrefixSha256Fulfillment,
  ThresholdSha256Fulfillment,
  Ed25519Fulfillment,
  validate,
  validateFulfillment,
  fromConditionUri: Condition.fromUri.bind(Condition),
  fromConditionBinary: Condition.fromBinary.bind(Condition),
  fromFulfillmentUri: Fulfillment.fromUri.bind(Fulfillment),
  fromFulfillmentBinary: Fulfillment.fromBinary.bind(Fulfillment)
}
