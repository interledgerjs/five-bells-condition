# Crypto Conditions

[![npm][npm-image]][npm-url] 
<!-- [![circle][circle-image]][circle-url] [![codecov][codecov-image]][codecov-url] -->

[npm-image]: https://img.shields.io/npm/v/crypto-conditions.svg?style=flat
[npm-url]: https://npmjs.org/package/crypto-conditions
<!-- [circle-image]: https://circleci.com/gh/interledgerjs/five-bells-condition.svg?style=shield -->
<!-- [circle-url]: https://circleci.com/gh/interledgerjs/five-bells-condition -->
<!-- [codecov-image]: https://codecov.io/gh/interledgerjs/five-bells-condition/branch/master/graph/badge.svg -->
<!-- [codecov-url]: https://codecov.io/gh/interledgerjs/five-bells-condition -->

> Implementation of crypto-conditions in JavaScript for Node.js and the browser

## Specification

Editor's Draft: [**draft-thomas-crypto-conditions-02**](https://tools.ietf.org/html/draft-thomas-crypto-conditions-02)

This specification is only a draft at this stage and has not been submitted.

## Table of Contents

- [Crypto Conditions](#crypto-conditions)
    - [Specification](#specification)
    - [Table of Contents](#table-of-contents)
    - [API Documentation](#api-documentation)
    - [Usage](#usage)
        - [Validate a Condition](#validate-a-condition)
        - [Validate a Fulfillment (No Message)](#validate-a-fulfillment-no-message)
        - [Get Condition from Fulfillment And Validate](#get-condition-from-fulfillment-and-validate)
        - [Create a PREIMAGE-SHA-256 Condition (Hashlock)](#create-a-preimage-sha-256-condition-hashlock)
        - [Create a PREIMAGE-SHA-256 Fullfillment (Hashlock)](#create-a-preimage-sha-256-fullfillment-hashlock)
        - [Parse a Fulfillment](#parse-a-fulfillment)
        - [Create an ED25519 Condition](#create-an-ed25519-condition)
        - [Fulfill an ED25519 Condition](#fulfill-an-ed25519-condition)
        - [Verify a Fulfillment (with Message)](#verify-a-fulfillment-with-message)
        - [Create a THRESHOLD-SHA-256 Condition](#create-a-threshold-sha-256-condition)
        - [Create a THRESHOLD-SHA-256 Fulfillment](#create-a-threshold-sha-256-fulfillment)
        - [Create a PREFIX-SHA-256 Condition](#create-a-prefix-sha-256-condition)
        - [Create a PREFIX-SHA-256 Fulfillment](#create-a-prefix-sha-256-fulfillment)
        - [Create an RSA-SHA-256 Condition](#create-an-rsa-sha-256-condition)
        - [Create an RSA-SHA-256 Fulfillment](#create-an-rsa-sha-256-fulfillment)
        - [Advanced: Parse a Condition](#advanced-parse-a-condition)
        - [Advanced: Parse and Reserialize a THRESHOLD-SHA-256 Fulfillment](#advanced-parse-and-reserialize-a-threshold-sha-256-fulfillment)
        - [Advanced: Manually Create a Condition](#advanced-manually-create-a-condition)
        - [In browser environment](#in-browser-environment)

## API Documentation

TODO: Host doc on [https://www.bigchaindb.com/](https://www.bigchaindb.com/)

**[API Docs](https://interledger.org/five-bells-condition/jsdoc/)**

## Usage

### Validate a Condition

``` js
const cc = require('crypto-conditions')

// Check a condition for validity
const condition = 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
const validationResult = cc.validateCondition(condition)
// validationResult === true
```

This will ensure that the requested type, features and fulfillment length are
all accepted by the current implementation.

### Validate a Fulfillment (No Message)

``` js
const cc = require('crypto-conditions')

const condition = 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
const fulfillment = 'oAKAAA'
const validationResult = cc.validateFulfillment(fulfillment, condition)
// validationResult === true
```

This validates the fulfillment and ensures that it matches the given condition.

### Get Condition from Fulfillment And Validate

``` js
const cc = require('crypto-conditions')

const fulfillment = 'oAKAAA'
const condition = cc.fulfillmentToCondition(fulfillment)

// You could now look up this condition in your database etc.

const validationResult = cc.validateFulfillment(fulfillment, condition)
// validationResult === true
```

### Create a PREIMAGE-SHA-256 Condition (Hashlock)

``` js
const cc = require('crypto-conditions')

const myFulfillment = new cc.PreimageSha256()
myFulfillment.setPreimage(Buffer.from(''))
console.log(myFulfillment.getConditionUri())
// prints 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
```

### Create a PREIMAGE-SHA-256 Fullfillment (Hashlock)

``` js
const cc = require('crypto-conditions')

const myFulfillment = new cc.PreimageSha256()
myFulfillment.setPreimage(Buffer.from(''))
console.log(myFulfillment.serializeUri())
// prints 'oAKAAA'
```

### Parse a Fulfillment

``` js
const cc = require('crypto-conditions')

const parsedFulfillment = cc.fromFulfillmentUri('oAKAAA')
// parsedFulfillment instanceof cc.PreimageSha256 === true
// Note: Merely parsing a fulfillment DOES NOT validate it.

// Validate a fulfillment
parsedFulfillment.validate()
```

### Create an ED25519 Condition

``` js
const cc = require('crypto-conditions')

const ed25519Fulfillment = new cc.Ed25519Sha256()
ed25519Fulfillment.setPublicKey(Buffer.from('ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf', 'hex'))
console.log(ed25519Fulfillment.getConditionUri())
// prints 'ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072'
```

### Fulfill an ED25519 Condition

``` js
const cc = require('crypto-conditions')

const edPrivateKey = Buffer.from('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'hex')

const ed25519Fulfillment = new cc.Ed25519Sha256()
// ed25519Fulfillment.setPublicKey(Buffer.from('...'))
// ed25519Fulfillment.setSignature(Buffer.from('...'))
// -- or --
ed25519Fulfillment.sign(Buffer.from('Hello World! Conditions are here!'), edPrivateKey)
console.log(ed25519Fulfillment.getConditionUri())
// prints 'ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072'
console.log(ed25519Fulfillment.serializeUri())
// prints 'pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
```

### Verify a Fulfillment (with Message)

``` js
const cc = require('crypto-conditions')

const fulfillment = 'pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
const condition = 'ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072'
const message = Buffer.from('Hello World! Conditions are here!')

const result = cc.validateFulfillment(fulfillment, condition, message)
// result === true
```

### Create a THRESHOLD-SHA-256 Condition
``` js
const cc = require('crypto-conditions')

const thresholdFulfillment = new cc.ThresholdSha256()
thresholdFulfillment.addSubconditionUri('ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072')
thresholdFulfillment.addSubfulfillmentUri('oAKAAA')
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getConditionUri())
// prints 'ni:///sha-256;l-wuy18t5Ic2GfCbVb9yAiTJ_gJbN2x34fk3eHOz5kY?fpt=threshold-sha-256&cost=133120&subtypes=ed25519-sha-256,preimage-sha-256'
```

### Create a THRESHOLD-SHA-256 Fulfillment

``` js
const cc = require('crypto-conditions')

const thresholdFulfillment = new cc.ThresholdSha256()
thresholdFulfillment.addSubfulfillmentUri('pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')
thresholdFulfillment.addSubfulfillmentUri('oAKAAA')
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getConditionUri())
// prints 'ni:///sha-256;l-wuy18t5Ic2GfCbVb9yAiTJ_gJbN2x34fk3eHOz5kY?fpt=threshold-sha-256&cost=133120&subtypes=ed25519-sha-256,preimage-sha-256'
const thresholdFulfillmentUri = thresholdFulfillment.serializeUri()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillmentUri.length === 68
console.log(thresholdFulfillmentUri)
// prints 'ojGgBKACgAChKaQngCBTViEV1bSU4j5JUXc9sM_i3-VV5-P_60Hk_XXK98FqgYEDAgAA'
```

### Create a PREFIX-SHA-256 Condition

``` js
const cc = require('crypto-conditions')

const prefix = new cc.PrefixSha256()
prefix.setPrefix(Buffer.from('2016:'))
prefix.setMaxMessageLength(65536)
prefix.setSubconditionUri('ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072')
console.log(prefix.getConditionUri())
// prints 'ni:///sha-256;3Q87-ZwAaOH3KKkRD-wAuTiA3g7T8idCir2Gie6hkoI?fpt=prefix-sha-256&cost=197637&subtypes=ed25519-sha-256'
```

### Create a PREFIX-SHA-256 Fulfillment

``` js
const cc = require('crypto-conditions')

const prefix = new cc.PrefixSha256()
prefix.setPrefix(Buffer.from('Hello World! '))
prefix.setMaxMessageLength(16384)
prefix.setSubfulfillmentUri('pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')
const fulfillmentUri = prefix.serializeUri()
console.log(fulfillmentUri)
// prints 'oXuADUhlbGxvIFdvcmxkISCBAkAAomakZIAg7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-BQLYikfrZQy-PKYucSkiV2-KT9v_aGmja3wzN719HoMchKl_qPNqXo_TAPqny6Kwc7IalHUUhJ6vboJ0bbzMcBwo'

const conditionUri = prefix.getConditionUri()
const message = Buffer.from('Conditions are here!')
cc.validateFulfillment(fulfillmentUri, conditionUri, message)
```

### Create an RSA-SHA-256 Condition

``` js
const cc = require('crypto-conditions')

const rsaFulfillment = new cc.RsaSha256()
rsaFulfillment.setPublicModulus(Buffer.from('b30e7a938783babf836850ff49e14f87e3f92d5c46e33feca3e4f0b22358580b11765995f4b8eea7fb4712c2e1e316f7f775a953d232216a169d9a64ddc007120a400b37f2afc077b62fe304de74de6a119ec4076b529c4f6096b0baad4f533df0173b9b822fd85d65fa4befa92d8f524f69cbca0136bd80d095c169aec0e095', 'hex'))
console.log(rsaFulfillment.getConditionUri())
// prints 'ni:///sha-256;j2luKLUjz-Ilu0jdDQO-Eg5Srmu06lEs4dsZHHVxcdc?fpt=rsa-sha-256&cost=16384'
```

### Create an RSA-SHA-256 Fulfillment

``` js
const cc = require('crypto-conditions')

const exampleMessage = Buffer.from('Hello World! Conditions are here!')
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

const rsaFulfillment = new cc.RsaSha256()
// rsaFulfillment.setPublicModulus(Buffer.from('...'))
// rsaFulfillment.setSignature(Buffer.from('...'))
// -- or --
rsaFulfillment.sign(exampleMessage, privateKey)
console.log(rsaFulfillment.serializeUri().length)
// prints '355'

// Verify RSA-SHA256 condition
const rsaFulfillmentUri = rsaFulfillment.serializeUri()
const rsaConditionUri = rsaFulfillment.getConditionUri()
cc.validateFulfillment(rsaFulfillmentUri, rsaConditionUri, exampleMessage)
```

### Advanced: Parse a Condition
``` js
const cc = require('crypto-conditions')

// Parse a condition
const condition = 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
const parsedCondition = cc.fromConditionUri(condition)
console.log(parsedCondition.constructor.name)
// prints 'Condition'

// Compile to a condition
console.log(parsedCondition.serializeUri())
// prints condition
```
### Advanced: Parse and Reserialize a THRESHOLD-SHA-256 Fulfillment

``` js
const cc = require('crypto-conditions')

const thresholdFulfillmentUri = 'oi-gBKACgAChJ6AlgCB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaYEBDA'
const reparsedFulfillment = cc.fromFulfillmentUri(thresholdFulfillmentUri)

const reserializedFulfillment = reparsedFulfillment.serializeUri()
console.log(reserializedFulfillment)
// prints thresholdFulfillmentUri
```

### Advanced: Manually Create a Condition

``` js
const cc = require('crypto-conditions')

const myCondition = new cc.Condition()
myCondition.setTypeId(cc.PreimageSha256.TYPE_ID)
myCondition.setSubtypes(new Set('preimage-sha-256'))
myCondition.setHash(Buffer.from('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
myCondition.setCost(0)
console.log(myCondition.serializeUri())
// prints 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
```

### In browser environment

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CryptoConditions</title>
  </head>
  <body>
    <script src="https://unpkg.com/crypto-conditions@2.0.3/dist/browser/CryptoConditions.window.min.js"></script>
    <script>
      const conditionUri = 'ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0'
      const validationResult = CryptoConditions.validateCondition(condition)
      console.log(`Condition ${conditionUri} is valid ? ${validationResult}`)
      alert(JSON.stringify(CryptoConditions.Condition.fromUri(conditionUri), null, 2))
    </script>
  </body>
</html>
```
