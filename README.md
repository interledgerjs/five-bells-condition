# Crypto Conditions

> Implementation of crypto-conditions

## Spec

You can find the draft specification under [**docs/spec.md**](docs/spec.md).

## Usage

``` js
const condition = require('five-bells-condition')

// Check a condition for validity
const exampleCondition = 'cc:1:1:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:1'
const validationResult = condition.validate(exampleCondition)
// validationResult === { valid: true, error: null }

// Validate a fulfillment
const exampleFulfillment = 'cf:1:1:AA'
const compiled = condition.validateFulfillment(exampleFulfillment)
// compiled === { valid: true, condition: exampleCondition, error: null }
// Then simply verify that the fulfillment matches the condition
console.log(compiled.valid && compiled.condition === exampleCondition)
// prints true

// Create a SHA256 condition
const myCondition = new condition.Condition()
myCondition.setBitmask(condition.Sha256Fulfillment.TYPE_BIT)
myCondition.setHash(new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
myCondition.setMaxFulfillmentLength(1)
console.log(myCondition.serializeUri())
// prints exampleCondition

// Create a SHA256 fulfillment
const myFulfillment = new condition.Sha256Fulfillment()
myFulfillment.setPreimage(new Buffer(''))
console.log(myFulfillment.serializeUri())
// prints exampleFulfillment

// Parse a fulfillment
const parsedFulfillment = condition.fromFulfillmentUri(exampleFulfillment)
// parsedFulfillment instanceof condition.Sha256Fulfillment === true
// Note: Merely parsing a fulfillment DOES NOT validate it.

// Validate a fulfillment
parsedFulfillment.validate()

// Compile a fulfillment
console.log(parsedFulfillment.serializeUri())
// prints exampleFulfillment

// Parse a condition
const parsedCondition = condition.fromConditionUri(exampleCondition)
console.log(parsedCondition.constructor.name)
// prints 'Condition'

// Compile to a condition
console.log(parsedCondition.serializeUri())
// prints exampleCondition

// Create an RSA-SHA256 condition
const rsaFulfillment = new condition.RsaSha256Fulfillment()
rsaFulfillment.setPublicModulus(new Buffer('a125cbdaf5b7494349b164e12dce4b40d12813da65d38a1293fd1a9c0196c2ef4fada6269ccc1a77c16ab766da0e4761c48275ce833f8a937d9c29d3d5e6d2e9'))
rsaFulfillment.setMessagePrefix(new Buffer('Hello world!'))
rsaFulfillment.setMaxDynamicMessageLength(32) // defaults to 0
console.log(rsaFulfillment.getCondition().serializeUri())
// prints 'cc:1:2:KNc4bchlwmAt9wON-VsRCmXwJomU0Iv6tuG6_DARBHM:307'

// Fulfill an RSA-SHA256 condition
const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIBOwIBAAJBAKEly9r1t0lDSbFk4S3OS0DRKBPaZdOKEpP9GpwBlsLvT62mJpzM\n' +
  'GnfBardm2g5HYcSCdc6DP4qTfZwp09Xm0ukCAwEAAQJAf0CBgh6W5dukzdiDmNBW\n' +
  'zJBdvY+w6SMXGJW99YOrsbJXXVGhwqnmdjDS2X8gSqEWnEw5QxoMBeVjiJmxE0N8\n' +
  'AQIhANXJQtKIF6C2BTp5vqIf7yQUsBS3lSCCD6ymFPKKNCbZAiEAwPex4tccWZ9t\n' +
  'tZdwc2auMCpn8GNUdlUVFTw4IbJUIpECIQCUvZOFYPR3d0zJ83xj1i4O/2nG8DeM\n' +
  'R5FaQK8gVHGWeQIhAIOovLNEB7DSiT0r/WqPdWuhk1c9voQaWw8pDjdXf/YxAiA1\n' +
  'CIg/WgYXGcFHCLcGA6vqiGRrTldNndjnNHhlY3cDEg==\n' +
  '-----END RSA PRIVATE KEY-----\n'

rsaFulfillment.setMessage(new Buffer(' Conditions are here!'))
// rsaFulfillment.setSignature(new Buffer('...'))
// -- or --
rsaFulfillment.sign(privateKey)
console.log(rsaFulfillment.serializeUri())
// prints 'cf:1:2:gAFhMTI1Y2JkYWY1Yjc0OTQzNDliMTY0ZTEyZGNlNGI0MGQxMjgxM2RhNjVkMzhhMTI5M2ZkMWE5YzAxOTZjMmVmNGZhZGE2MjY5Y2NjMWE3N2MxNmFiNzY2ZGEwZTQ3NjFjNDgyNzVjZTgzM2Y4YTkzN2Q5YzI5ZDNkNWU2ZDJlOQxIZWxsbyB3b3JsZCEgFSBDb25kaXRpb25zIGFyZSBoZXJlIUBBSxMRUAuT16C5YvwgaSBBNFjsqZGS-8An_3iFhMSSRJna7dNLm7KPeAzu4CDi1E4ebEQroo9vWKLNW_8hO_YM'

// Create a threshold condition
const thresholdFulfillment = new condition.ThresholdSha256Fulfillment()
thresholdFulfillment.addSubfulfillment(rsaFulfillment)
thresholdFulfillment.addSubfulfillment(myFulfillment)
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getCondition().serializeUri())
// prints 'cc:1:7:W4f22oX9bXocepiaAIyExP-3aE2NzE8XR5bTFiSVij8:308'

const thresholdFulfillmentUri = thresholdFulfillment.serializeUri()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillmentUri.length === 65
console.log(thresholdFulfillmentUri)
// prints 'cf:1:4:AQEBAQABAQIgKNc4bchlwmAt9wON-VsRCmXwJomU0Iv6tuG6_DARBHOzAg'

const reparsedFulfillment = condition.fromFulfillmentUri(thresholdFulfillmentUri)

const reserializedFulfillment = reparsedFulfillment.serializeUri()
console.log(reserializedFulfillment)
// prints thresholdFulfillmentUri
```
