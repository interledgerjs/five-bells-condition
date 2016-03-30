# Crypto Conditions

> Implementation of crypto-conditions

## Specification

Editor's Draft: [**draft-thomas-crypto-conditions-01**](https://interledger.org/five-bells-condition/spec.html)

This specification is only a draft at this stage and has not been submitted.

## Usage

``` js
const condition = require('five-bells-condition')

// Check a condition for validity
const exampleCondition = 'cc:1:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:1'
const validationResult = condition.validate(exampleCondition)
// validationResult === { valid: true, error: null }

// Validate a fulfillment
const exampleFulfillment = 'cf:1:0:AA'
const compiled = condition.validateFulfillment(exampleFulfillment)
// compiled === { valid: true, condition: exampleCondition, error: null }
// Then simply verify that the fulfillment matches the condition
console.log(compiled.valid && compiled.condition === exampleCondition)
// prints true

// Create a SHA256 condition
const myCondition = new condition.Condition()
myCondition.setBitmask(condition.PreimageSha256Fulfillment.FEATURE_BITMASK)
myCondition.setHash(new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
myCondition.setMaxFulfillmentLength(1)
console.log(myCondition.serializeUri())
// prints exampleCondition

// Create a SHA256 fulfillment
const myFulfillment = new condition.PreimageSha256Fulfillment()
myFulfillment.setPreimage(new Buffer(''))
console.log(myFulfillment.serializeUri())
// prints exampleFulfillment

// Parse a fulfillment
const parsedFulfillment = condition.fromFulfillmentUri(exampleFulfillment)
// parsedFulfillment instanceof condition.PreimageSha256Fulfillment === true
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
rsaFulfillment.setPublicModulus(new Buffer('b30e7a938783babf836850ff49e14f87e3f92d5c46e33feca3e4f0b22358580b11765995f4b8eea7fb4712c2e1e316f7f775a953d232216a169d9a64ddc007120a400b37f2afc077b62fe304de74de6a119ec4076b529c4f6096b0baad4f533df0173b9b822fd85d65fa4befa92d8f524f69cbca0136bd80d095c169aec0e095', 'hex'))
console.log(rsaFulfillment.getCondition().serializeUri())
// prints 'cc:1:11:d4LPlqIsCKjjUlxJjUxkV9dyE5fDOIdr9mTa0hsRGGE:260'

// Fulfill an RSA-SHA256 condition
const privateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICXAIBAAKBgQCzDnqTh4O6v4NoUP9J4U+H4/ktXEbjP+yj5PCyI1hYCxF2WZX0\n' +
  'uO6n+0cSwuHjFvf3dalT0jIhahadmmTdwAcSCkALN/KvwHe2L+ME3nTeahGexAdr\n' +
  'UpxPYJawuq1PUz3wFzubgi/YXWX6S++pLY9ST2nLygE2vYDQlcFprsDglQIDAQAB\n' +
  'AoGAB7Rjyd1W6b475U027vLm/S3uFumVk0m44QSE5uVmc8NmKPWJ4lHi0w+Y61G/\n' +
  'booaeWdytcyho5ZxCq8OEAynQSkJiBNtzBg+xCGcO6GPOf+dFBYZFQsXiG/EbwrA\n' +
  'pT0cv+AqiGzLIAh2WtNI6cr5/ZEMScNhMcQ4AZ1kRyUdpIECQQDbRtFz0dSMMvS/\n' +
  '1KtDZxej9HqC5xOEuCDEZuLvk4bW4mC02OP/H/VV5qqclz0LIvMWK6TDtoFRpkvD\n' +
  'UYiYoc85AkEA0QtH1zQlGGlliLcWoPeqjkbtf3ocmYy2exBSCwnOf87xV//k9pNC\n' +
  '7jmoIzRgKVef8kQR/mXWszo3WbWMt0aAPQJBAMtoRD/GM/7h/fw9Uamy5lEnJsZr\n' +
  'iMWi8HKAZp+LIJgRY1gfolA12yWWVknwWaYNA6ZbUfpjQE73jmxfI/FCmLECQBmF\n' +
  'WAr06cZ2L5gmShPyyJbAIASdItq4LBsQHgQM+XHvENXeftR/m/87eMR7g3XopbVN\n' +
  'DClTw4d0Bwfjuz8w0z0CQFG7RmgPqsTEGfojpRgLZnec87R6XhuUY5ZoGgpnx7r9\n' +
  '/zGekAwjBZDKpc+H0jC14JjMzRRKeWVEpDU3k2cfBH0=\n' +
  '-----END RSA PRIVATE KEY-----\n'

// rsaFulfillment.setSignature(new Buffer('...'))
// -- or --
rsaFulfillment.sign(new Buffer('Hello World! Conditions are here!'), privateKey)
console.log(rsaFulfillment.serializeUri().length)
// prints '354'

// Create a threshold condition
const thresholdFulfillment = new condition.ThresholdSha256Fulfillment()
thresholdFulfillment.addSubfulfillment(rsaFulfillment)
thresholdFulfillment.addSubfulfillment(myFulfillment)
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getCondition().serializeUri())
// prints 'cc:1:1b:nXCiu2GjMxzsCMaM6IhXPQavllDOXc1LplmfDkaN83g:308'

const thresholdFulfillmentUri = thresholdFulfillment.serializeUri()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillmentUri.length === 69
console.log(thresholdFulfillmentUri)
// prints 'cf:1:2:AQIBAgAAAAEAJBEgd4LPlqIsCKjjUlxJjUxkV9dyE5fDOIdr9mTa0hsRGGGEAg'

const reparsedFulfillment = condition.fromFulfillmentUri(thresholdFulfillmentUri)

const reserializedFulfillment = reparsedFulfillment.serializeUri()
console.log(reserializedFulfillment)
// prints thresholdFulfillmentUri

// Create an ED25519-SHA-256 condition
const ed25519Fulfillment = new condition.Ed25519Fulfillment()
ed25519Fulfillment.setPublicKey(new Buffer('ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf', 'hex'))
console.log(ed25519Fulfillment.getCondition().serializeUri())
// prints 'cc:1:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:98'

// Fulfill an ED25519-SHA-256 condition
const edPrivateKey = new Buffer('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'hex')

// ed25519Fulfillment.setSignature(new Buffer('...'))
// -- or --
ed25519Fulfillment.sign(new Buffer('Hello World! Conditions are here!'), edPrivateKey)
console.log(ed25519Fulfillment.serializeUri())
// prints 'cf:1:4:IOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_QLYikfrZQy-PKYucSkiV2-KT9v_aGmja3wzN719HoMchKl_qPNqXo_TAPqny6Kwc7IalHUUhJ6vboJ0bbzMcBwo'

```
