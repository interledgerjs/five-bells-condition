'use strict'

require('babel-polyfill')
const Condition = require('./src/lib/condition')
const Fulfillment = require('./src/lib/fulfillment')
const TypeRegistry = require('./src/lib/type-registry')
const PreimageSha256 = require('./src/types/preimage-sha256')
const PrefixSha256 = require('./src/types/prefix-sha256')
const ThresholdSha256 = require('./src/types/threshold-sha256')
const RsaSha256 = require('./src/types/rsa-sha256')
const Ed25519 = require('./src/types/ed25519')

const EMPTY_BUFFER = new Buffer(0)

const validateCondition = (serializedCondition) => {
  // Parse condition, throw on error
  const condition = Condition.fromUri(serializedCondition)

  // Validate condition, throw on error
  return condition.validate()
}

const validateFulfillment = (serializedFulfillment, serializedCondition, message) => {
  if (typeof message === 'undefined') {
    message = EMPTY_BUFFER
  }

  if (!Buffer.isBuffer(message)) {
    throw new Error('Message must be provided as a Buffer')
  }

  // Parse fulfillment, throw on error
  const fulfillment = Fulfillment.fromUri(serializedFulfillment)

  // Compare condition URI, throw on error
  const conditionUri = fulfillment.getConditionUri()
  if (conditionUri !== serializedCondition) {
    throw new Error('Fulfillment does not match condition')
  }

  // Validate fulfillment, throw on error
  return fulfillment.validate(message)
}

const fulfillmentToCondition = (serializedFulfillment) => {
  // Parse fulfillment, throw on error
  const fulfillment = Fulfillment.fromUri(serializedFulfillment)

  return fulfillment.getConditionUri()
}

TypeRegistry.registerType(PreimageSha256)
TypeRegistry.registerType(PrefixSha256)
TypeRegistry.registerType(ThresholdSha256)
TypeRegistry.registerType(RsaSha256)
TypeRegistry.registerType(Ed25519)

module.exports = {
  Condition,
  Fulfillment,
  TypeRegistry,
  PreimageSha256,
  RsaSha256,
  PrefixSha256,
  ThresholdSha256,
  Ed25519,
  validateCondition,
  validateFulfillment,
  fulfillmentToCondition,
  fromConditionUri: Condition.fromUri.bind(Condition),
  fromConditionBinary: Condition.fromBinary.bind(Condition),
  fromFulfillmentUri: Fulfillment.fromUri.bind(Fulfillment),
  fromFulfillmentBinary: Fulfillment.fromBinary.bind(Fulfillment)
}
