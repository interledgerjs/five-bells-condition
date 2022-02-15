import Condition from './lib/condition'
import Fulfillment from './lib/fulfillment'
import TypeRegistry from './lib/type-registry'
import PreimageSha256 from './types/preimage-sha256'
import PrefixSha256 from './types/prefix-sha256'
import ThresholdSha256 from './types/threshold-sha256'
import RsaSha256 from './types/rsa-sha256'
import Ed25519Sha256 from './types/ed25519-sha256'
import base64url from './util/base64url'

const EMPTY_BUFFER = Buffer.alloc(0)

TypeRegistry.registerType(PreimageSha256)
TypeRegistry.registerType(PrefixSha256)
TypeRegistry.registerType(ThresholdSha256)
TypeRegistry.registerType(RsaSha256)
TypeRegistry.registerType(Ed25519Sha256)

export const validateCondition = (serializedCondition) => {
  // Parse condition, throw on error
  const condition = Condition.fromUri(serializedCondition)

  // Validate condition, throw on error
  return condition.validate()
}

export const validateFulfillment = (
  serializedFulfillment,
  serializedCondition,
  message
) => {
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
    throw new Error(
      'Fulfillment does not match condition (expected: ' +
        serializedCondition +
        ', actual: ' +
        conditionUri +
        ')'
    )
  }

  // Validate fulfillment, throw on error
  return fulfillment.validate(message)
}

export const fulfillmentToCondition = (serializedFulfillment) => {
  // Parse fulfillment, throw on error
  const fulfillment = Fulfillment.fromUri(serializedFulfillment)
  return fulfillment.getConditionUri()
}

export const fromJson = (json) => Fulfillment.fromJson(json)

export const fromConditionUri = Condition.fromUri.bind(Condition)
export const fromConditionBinary = Condition.fromBinary.bind(Condition)
export const fromFulfillmentUri = Fulfillment.fromUri.bind(Fulfillment)
export const fromFulfillmentBinary = Fulfillment.fromBinary.bind(Fulfillment)

export {
  Condition,
  Fulfillment,
  PreimageSha256,
  PrefixSha256,
  ThresholdSha256,
  RsaSha256,
  base64url
}
