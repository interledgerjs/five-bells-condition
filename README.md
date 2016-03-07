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
const myCondition = new condition.Sha256()
myCondition.setPreimage(new Buffer(''))
// -- or --
myCondition.setHash(new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
console.log(myCondition.serializeConditionUri())
// prints exampleCondition

// Create a SHA256 fulfillment
const myFulfillment = new condition.Sha256()
myFulfillment.setPreimage(new Buffer(''))
console.log(myCondition.serializeFulfillmentUri())
// prints 'cf:1:1:AA'

// Parse a fulfillment
const parsedFulfillment = condition.fromFulfillmentUri(exampleFulfillment)
// parsedFulfillment instanceof condition.Sha256 === true
// Note: Merely parsing a fulfillment DOES NOT validate it.

// Validate a fulfillment
parsedFulfillment.validate()

// Compile a fulfillment
console.log(parsedFulfillment.serializeFulfillmentUri())
// prints exampleFulfillment

// Parse a condition
const parsedCondition = condition.fromConditionUri(exampleCondition)
console.log(parsedCondition.constructor.name)
// prints 'Sha256'

// Compile to a condition
console.log(parsedCondition.serializeConditionUri())
// prints exampleCondition

// Create an RSA-SHA256 condition
const rsaCondition = new condition.RsaSha256()
rsaCondition.setPublicModulus(new Buffer('a125cbdaf5b7494349b164e12dce4b40d12813da65d38a1293fd1a9c0196c2ef4fada6269ccc1a77c16ab766da0e4761c48275ce833f8a937d9c29d3d5e6d2e9'))
rsaCondition.setMessagePrefix(new Buffer('Hello world!'))
rsaCondition.setMaxMessageLength(32) // defaults to 0
console.log(rsaCondition.serializeConditionUri())
// prints 'cc:1:2:aX_QGANFWTfZ9dNUxDpXVJIoWvEAXtcd6B4jXq9Np7E:305'

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

rsaCondition.setMessage(new Buffer(' Conditions are here!'))
// rsaCondition.setSignature(new Buffer('...'))
// -- or --
rsaCondition.sign(privateKey)
console.log(rsaCondition.serializeFulfillmentUri())
// prints 'cf:1:2:gAFhMTI1Y2JkYWY1Yjc0OTQzNDliMTY0ZTEyZGNlNGI0MGQxMjgxM2RhNjVkMzhhMTI5M2ZkMWE5YzAxOTZjMmVmNGZhZGE2MjY5Y2NjMWE3N2MxNmFiNzY2ZGEwZTQ3NjFjNDgyNzVjZTgzM2Y4YTkzN2Q5YzI5ZDNkNWU2ZDJlOQxIZWxsbyB3b3JsZCEVIENvbmRpdGlvbnMgYXJlIGhlcmUhQUsTEVALk9eguWL8IGkgQTRY7KmRkvvAJ_94hYTEkkSZ2u3TS5uyj3gM7uAg4tROHmxEK6KPb1iizVv_ITv2DAA'

// Create a threshold condition
const thresholdCondition = new condition.ThresholdSha256()
thresholdCondition.addSubcondition(rsaCondition)
thresholdCondition.addSubcondition(myCondition)
thresholdCondition.setThreshold(1) // defaults to subconditions.length
console.log(thresholdCondition.serializeConditionUri())
// prints 'cc:1:4:LBSkmeQXCfWofjESgd02JrCCdzd_DVNd4GYUaFuwOpY:306'

const thresholdFulfillment = thresholdCondition.serializeFulfillmentUri()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillment.length === 63
console.log(thresholdFulfillment)
// prints 'cf:1:4:AQEBAQABAQJpf9AYA0VZN9n101TEOldUkiha8QBe1x3oHiNer02nsbEC'

const reparsedFulfillment = condition.fromFulfillmentUri(thresholdFulfillment)

const reserializedFulfillment = reparsedFulfillment.serializeFulfillmentUri()
console.log(reserializedFulfillment)
// prints thresholdFulfillment
```
