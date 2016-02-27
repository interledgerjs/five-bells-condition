# Crypto Conditions

> Implementation of crypto-conditions

## Usage

``` js
const condition = require('five-bells-condition')

// Check a condition for validity
const exampleCondition = 'cc:1:AeOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAg'
const validationResult = condition.validate(exampleCondition)
// validationResult === { valid: true, error: null }

// Validate a fulfillment
const compiled = condition.validateFulfillment('cf:1:AQI')
// compiled === { valid: true, condition: exampleCondition, error: null }
// Then simply verify that the fulfillment matches the condition
console.log(compiled.valid && compiled.condition === exampleCondition)
// prints true

// Create a SHA256 condition
const myCondition = new condition.Sha256()
myCondition.setPreimage(new Buffer(''))
// -- or --
myCondition.setHash(new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
console.log(myCondition.serializeCondition())
// prints 'cc:1:AeOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAg'

// Create a SHA256 fulfillment
const myFulfillment = new condition.Sha256()
myFulfillment.setPreimage(new Buffer(''))
console.log(myCondition.serializeFulfillment())
// prints 'cf:1:AQI'

// Parse a fulfillment
const parsedFulfillment = condition.fromFulfillment('cf:1:AQA')
// parsedFulfillment instanceof condition.Sha256 === true
// Note: Merely parsing a fulfillment DOES NOT validate it.

// Validate a fulfillment
parsedFulfillment.validate()

// Compile a fulfillment
parsedFulfillment.serializeFulfillment()

// Parse a condition
const parsedCondition = condition.fromCondition('cc:1:AeOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAg')
console.log(parsedCondition.constructor.name)
// prints 'Sha256'

// Compile to a condition
console.log(parsedCondition.serializeCondition())
// prints 'cc:1:AeOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVAg'

// Create an RSA-SHA256 condition
const rsaCondition = new condition.RsaSha256()
rsaCondition.setPublicModulus(new Buffer('a125cbdaf5b7494349b164e12dce4b40d12813da65d38a1293fd1a9c0196c2ef4fada6269ccc1a77c16ab766da0e4761c48275ce833f8a937d9c29d3d5e6d2e9'))
rsaCondition.setMessagePrefix(new Buffer('Hello world!'))
rsaCondition.setMaxMessageLength(32) // defaults to 0
console.log(rsaCondition.serializeCondition())
// prints 'cc:1:Aml_0BgDRVk32fXTVMQ6V1SSKFrxAF7XHegeI16vTaexsgI'

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
console.log(rsaCondition.serializeFulfillment())
// prints 'cf:1:AoABYTEyNWNiZGFmNWI3NDk0MzQ5YjE2NGUxMmRjZTRiNDBkMTI4MTNkYTY1ZDM4YTEyOTNmZDFhOWMwMTk2YzJlZjRmYWRhNjI2OWNjYzFhNzdjMTZhYjc2NmRhMGU0NzYxYzQ4Mjc1Y2U4MzNmOGE5MzdkOWMyOWQzZDVlNmQyZTkMSGVsbG8gd29ybGQhFSBDb25kaXRpb25zIGFyZSBoZXJlIUFLExFQC5PXoLli_CBpIEE0WOypkZL7wCf_eIWExJJEmdrt00ubso94DO7gIOLUTh5sRCuij29Yos1b_yE79gwA'

// Create a threshold condition
const thresholdCondition = new condition.ThresholdSha256()
thresholdCondition.addSubcondition(myCondition)
thresholdCondition.addSubcondition(rsaCondition)
thresholdCondition.setThreshold(1) // defaults to subconditions.length
console.log(thresholdCondition.serializeCondition())
// prints 'cc:1:BETwrHWUsdWZknhVSmoPhorke3nDGa6izP3lyF4Q-h6OtAI'

const thresholdFulfillment = thresholdCondition.serializeFulfillment()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillment.length === 57
console.log(thresholdFulfillment)
// prints 'cf:1:BAICaX_QGANFWTfZ9dNUxDpXVJIoWvEAXtcd6B4jXq9Np7GyAgEC'

```
