# Crypto Conditions

> Implementation of crypto-conditions

## Specification

Editor's Draft: [**draft-thomas-crypto-conditions-01**](https://interledger.org/five-bells-condition/spec.html)

This specification is only a draft at this stage and has not been submitted.

## Table of Contents

- [Crypto Conditions](#crypto-conditions)
    - [Specification](#specification)
    - [Table of Contents](#table-of-contents)
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
    - [API Reference](#api-reference)
        - [types~Condition](#typescondition)
            - [condition.getTypeId() ⇒ <code>Number</code>](#conditiongettypeid--codenumbercode)
            - [condition.setTypeId(type)](#conditionsettypeidtype)
            - [condition.getBitmask() ⇒ <code>Number</code>](#conditiongetbitmask--codenumbercode)
            - [condition.setBitmask(bitmask)](#conditionsetbitmaskbitmask)
            - [condition.getHash() ⇒ <code>Buffer</code>](#conditiongethash--codebuffercode)
            - [condition.setHash(hash)](#conditionsethashhash)
            - [condition.getMaxFulfillmentLength() ⇒ <code>Number</code>](#conditiongetmaxfulfillmentlength--codenumbercode)
            - [condition.setMaxFulfillmentLength(Maximum)](#conditionsetmaxfulfillmentlengthmaximum)
            - [condition.serializeUri() ⇒ <code>String</code>](#conditionserializeuri--codestringcode)
            - [condition.serializeBinary() ⇒ <code>Buffer</code>](#conditionserializebinary--codebuffercode)
            - [condition.validate() ⇒ <code>Boolean</code>](#conditionvalidate--codebooleancode)
            - [Condition.fromUri(serializedCondition) ⇒ <code>Condition</code>](#conditionfromuriserializedcondition--codeconditioncode)
            - [Condition.fromBinary(reader) ⇒ <code>Condition</code>](#conditionfrombinaryreader--codeconditioncode)
        - [types~Fulfillment](#typesfulfillment)
            - [fulfillment.getTypeId() ⇒ <code>Number</code>](#fulfillmentgettypeid--codenumbercode)
            - [fulfillment.getBitmask() ⇒ <code>Number</code>](#fulfillmentgetbitmask--codenumbercode)
            - [fulfillment.getCondition() ⇒ <code>Condition</code>](#fulfillmentgetcondition--codeconditioncode)
            - [fulfillment.getConditionUri() ⇒ <code>String</code>](#fulfillmentgetconditionuri--codestringcode)
            - [fulfillment.getConditionBinary() ⇒ <code>Buffer</code>](#fulfillmentgetconditionbinary--codebuffercode)
            - [fulfillment.serializeUri() ⇒ <code>String</code>](#fulfillmentserializeuri--codestringcode)
            - [fulfillment.serializeBinary() ⇒ <code>Buffer</code>](#fulfillmentserializebinary--codebuffercode)
            - [fulfillment.validate() ⇒ <code>Boolean</code>](#fulfillmentvalidate--codebooleancode)
            - [Fulfillment.fromUri(serializedFulfillment) ⇒ <code>Fulfillment</code>](#fulfillmentfromuriserializedfulfillment--codefulfillmentcode)
            - [Fulfillment.fromBinary(reader) ⇒ <code>Fulfillment</code>](#fulfillmentfrombinaryreader--codefulfillmentcode)
        - [types~Ed25519](#typesed25519)
            - [ed25519.setPublicKey(publicKey)](#ed25519setpublickeypublickey)
            - [ed25519.setSignature(signature)](#ed25519setsignaturesignature)
            - [ed25519.sign(message, privateKey)](#ed25519signmessage-privatekey)
            - [ed25519.generateHash(hasher)](#ed25519generatehashhasher)
            - [ed25519.validate(message) ⇒ <code>Boolean</code>](#ed25519validatemessage--codebooleancode)
        - [types~PrefixSha256](#typesprefixsha256)
            - [prefixSha256.setSubcondition(subcondition)](#prefixsha256setsubconditionsubcondition)
            - [prefixSha256.setSubconditionUri(Subcondition)](#prefixsha256setsubconditionurisubcondition)
            - [prefixSha256.setSubfulfillment(fulfillment)](#prefixsha256setsubfulfillmentfulfillment)
            - [prefixSha256.setSubfulfillmentUri(Subfulfillment)](#prefixsha256setsubfulfillmenturisubfulfillment)
            - [prefixSha256.setPrefix(prefix)](#prefixsha256setprefixprefix)
            - [prefixSha256.getBitmask() ⇒ <code>Number</code>](#prefixsha256getbitmask--codenumbercode)
            - [prefixSha256.validate(message) ⇒ <code>Boolean</code>](#prefixsha256validatemessage--codebooleancode)
        - [types~PreimageSha256](#typespreimagesha256)
            - [preimageSha256.setPreimage(preimage)](#preimagesha256setpreimagepreimage)
            - [preimageSha256.validate() ⇒ <code>Boolean</code>](#preimagesha256validate--codebooleancode)
        - [types~RsaSha256](#typesrsasha256)
            - [rsaSha256.setPublicModulus(modulus)](#rsasha256setpublicmodulusmodulus)
            - [rsaSha256.setSignature(signature)](#rsasha256setsignaturesignature)
            - [rsaSha256.sign(message, privateKey)](#rsasha256signmessage-privatekey)
            - [rsaSha256.validate(message) ⇒ <code>Boolean</code>](#rsasha256validatemessage--codebooleancode)
        - [types~ThresholdSha256](#typesthresholdsha256)
            - [thresholdSha256.addSubcondition(subcondition, [weight])](#thresholdsha256addsubconditionsubcondition-weight)
            - [thresholdSha256.addSubconditionUri(Subcondition)](#thresholdsha256addsubconditionurisubcondition)
            - [thresholdSha256.addSubfulfillment(Fulfillment, [weight])](#thresholdsha256addsubfulfillmentfulfillment-weight)
            - [thresholdSha256.addSubfulfillmentUri(Subfulfillment)](#thresholdsha256addsubfulfillmenturisubfulfillment)
            - [thresholdSha256.setThreshold(threshold)](#thresholdsha256setthresholdthreshold)
            - [thresholdSha256.getBitmask() ⇒ <code>Number</code>](#thresholdsha256getbitmask--codenumbercode)
            - [thresholdSha256.validate(message) ⇒ <code>Boolean</code>](#thresholdsha256validatemessage--codebooleancode)
        - [util~BaseError](#utilbaseerror)
        - [util~Base64Url](#utilbase64url)
            - [Base64Url.decode(base64urlString) ⇒ <code>Buffer</code>](#base64urldecodebase64urlstring--codebuffercode)
            - [Base64Url.encode(buffer) ⇒ <code>String</code>](#base64urlencodebuffer--codestringcode)
        - [util~Pem](#utilpem)
            - [Pem.modulusToPem(modulus) ⇒ <code>String</code>](#pemmodulustopemmodulus--codestringcode)
            - [Pem.modulusFromPrivateKey(privateKey) ⇒ <code>Buffer</code>](#pemmodulusfromprivatekeyprivatekey--codebuffercode)

## Usage

### Validate a Condition

``` js
const cc = require('five-bells-condition')

// Check a condition for validity
const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
const validationResult = cc.validateCondition(condition)
// validationResult === true
```

This will ensure that the requested type, features and fulfillment length are
all accepted by the current implementation.

### Validate a Fulfillment (No Message)

``` js
const cc = require('five-bells-condition')

const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
const fulfillment = 'cf:0:'
const validationResult = cc.validateFulfillment(fulfillment, condition)
// validationResult === true
```

This validates the fulfillment and ensures that it matches the given condition.

### Get Condition from Fulfillment And Validate

``` js
const cc = require('five-bells-condition')

const fulfillment = 'cf:0:'
const condition = cc.fulfillmentToCondition(fulfillment)

// You could now look up this condition in your database etc.

const validationResult = cc.validateFulfillment(fulfillment, condition)
// validationResult === true
```

### Create a PREIMAGE-SHA-256 Condition (Hashlock)

``` js
const cc = require('five-bells-condition')

const myFulfillment = new cc.PreimageSha256()
myFulfillment.setPreimage(new Buffer(''))
console.log(myFulfillment.getConditionUri())
// prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
```

### Create a PREIMAGE-SHA-256 Fullfillment (Hashlock)

``` js
const cc = require('five-bells-condition')

const myFulfillment = new cc.PreimageSha256()
myFulfillment.setPreimage(new Buffer(''))
console.log(myFulfillment.serializeUri())
// prints 'cf:0:'
```

### Parse a Fulfillment

``` js
const cc = require('five-bells-condition')

const parsedFulfillment = cc.fromFulfillmentUri('cf:0:')
// parsedFulfillment instanceof cc.PreimageSha256 === true
// Note: Merely parsing a fulfillment DOES NOT validate it.

// Validate a fulfillment
parsedFulfillment.validate()
```

### Create an ED25519 Condition

``` js
const cc = require('five-bells-condition')

const ed25519Fulfillment = new cc.Ed25519()
ed25519Fulfillment.setPublicKey(new Buffer('ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf', 'hex'))
console.log(ed25519Fulfillment.getConditionUri())
// prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
```

### Fulfill an ED25519 Condition

``` js
const cc = require('five-bells-condition')

const edPrivateKey = new Buffer('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'hex')

const ed25519Fulfillment = new cc.Ed25519()
// ed25519Fulfillment.setPublicKey(new Buffer('...'))
// ed25519Fulfillment.setSignature(new Buffer('...'))
// -- or --
ed25519Fulfillment.sign(new Buffer('Hello World! Conditions are here!'), edPrivateKey)
console.log(ed25519Fulfillment.getConditionUri())
// prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
console.log(ed25519Fulfillment.serializeUri())
// prints 'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
```

### Verify a Fulfillment (with Message)

``` js
const cc = require('five-bells-condition')

const fulfillment = 'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
const condition = 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
const message = new Buffer('Hello World! Conditions are here!')

const result = cc.validateFulfillment(fulfillment, condition, message)
// result === true
```

### Create a THRESHOLD-SHA-256 Condition
``` js
const cc = require('five-bells-condition')

const thresholdFulfillment = new cc.ThresholdSha256()
thresholdFulfillment.addSubconditionUri('cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96')
thresholdFulfillment.addSubfulfillmentUri('cf:0:')
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getConditionUri())
// prints 'cc:2:2b:mJUaGKCuF5n-3tfXM2U81VYtHbX-N8MP6kz8R-ASwNQ:146'
```

### Create a THRESHOLD-SHA-256 Fulfillment

``` js
const cc = require('five-bells-condition')

const thresholdFulfillment = new cc.ThresholdSha256()
thresholdFulfillment.addSubfulfillmentUri('cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')
thresholdFulfillment.addSubfulfillmentUri('cf:0:')
thresholdFulfillment.setThreshold(1) // defaults to subconditions.length
console.log(thresholdFulfillment.getConditionUri())
// prints 'cc:2:2b:mJUaGKCuF5n-3tfXM2U81VYtHbX-N8MP6kz8R-ASwNQ:146'
const thresholdFulfillmentUri = thresholdFulfillment.serializeUri()
// Note: If there are more than enough fulfilled subconditions, shorter
// fulfillments will be chosen over longer ones.
// thresholdFulfillmentUri.length === 77
console.log(thresholdFulfillmentUri)
// prints 'cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg'
```

### Create a PREFIX-SHA-256 Condition

``` js
const cc = require('five-bells-condition')

const prefix = new cc.PrefixSha256()
prefix.setPrefix(new Buffer('2016:'))
prefix.setSubconditionUri('cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96')
console.log(prefix.getConditionUri())
// prints 'cc:1:25:7myveZs3EaZMMuez-3kq6u69BDNYMYRMi_VF9yIuFLc:102'
```

### Create a PREFIX-SHA-256 Fulfillment

``` js
const cc = require('five-bells-condition')

const prefix = new cc.PrefixSha256()
prefix.setPrefix(new Buffer('Hello World! '))
prefix.setSubfulfillmentUri('cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')
const fulfillmentUri = prefix.serializeUri()
console.log(fulfillmentUri)
// prints 'cf:1:DUhlbGxvIFdvcmxkISAABGDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfiv7YikfrZQy-PKYucSkiV2-KT9v_aGmja3wzN719HoMchKl_qPNqXo_TAPqny6Kwc7IalHUUhJ6vboJ0bbzMcBwo'

const conditionUri = prefix.getConditionUri()
const message = new Buffer('Conditions are here!')
cc.validateFulfillment(fulfillmentUri, conditionUri, message)
```

### Create an RSA-SHA-256 Condition

``` js
const cc = require('five-bells-condition')

const rsaFulfillment = new cc.RsaSha256()
rsaFulfillment.setPublicModulus(new Buffer('b30e7a938783babf836850ff49e14f87e3f92d5c46e33feca3e4f0b22358580b11765995f4b8eea7fb4712c2e1e316f7f775a953d232216a169d9a64ddc007120a400b37f2afc077b62fe304de74de6a119ec4076b529c4f6096b0baad4f533df0173b9b822fd85d65fa4befa92d8f524f69cbca0136bd80d095c169aec0e095', 'hex'))
console.log(rsaFulfillment.getConditionUri())
// prints 'cc:3:11:Bw-r77AGqSCL0huuMQYj3KW0Jh67Fpayeq9h_4UJctg:260'
```

### Create an RSA-SHA-256 Fulfillment

``` js
const cc = require('five-bells-condition')

const exampleMessage = new Buffer('Hello World! Conditions are here!')
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
// rsaFulfillment.setPublicModulus(new Buffer('...'))
// rsaFulfillment.setSignature(new Buffer('...'))
// -- or --
rsaFulfillment.sign(exampleMessage, privateKey)
console.log(rsaFulfillment.serializeUri().length)
// prints '352'

// Verify RSA-SHA256 condition
const rsaFulfillmentUri = rsaFulfillment.serializeUri()
const rsaConditionUri = rsaFulfillment.getConditionUri()
cc.validateFulfillment(rsaFulfillmentUri, rsaConditionUri, exampleMessage)
```

### Advanced: Parse a Condition
``` js
const cc = require('five-bells-condition')

// Parse a condition
const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
const parsedCondition = cc.fromConditionUri(condition)
console.log(parsedCondition.constructor.name)
// prints 'Condition'

// Compile to a condition
console.log(parsedCondition.serializeUri())
// prints condition
```
### Advanced: Parse and Reserialize a THRESHOLD-SHA-256 Fulfillment

``` js
const cc = require('five-bells-condition')

const thresholdFulfillmentUri = 'cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg'
const reparsedFulfillment = cc.fromFulfillmentUri(thresholdFulfillmentUri)

const reserializedFulfillment = reparsedFulfillment.serializeUri()
console.log(reserializedFulfillment)
// prints thresholdFulfillmentUri
```

### Advanced: Manually Create a Condition

``` js
const cc = require('five-bells-condition')

const myCondition = new cc.Condition()
myCondition.setTypeId(cc.PreimageSha256.TYPE_ID)
myCondition.setBitmask(cc.PreimageSha256.FEATURE_BITMASK)
myCondition.setHash(new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex'))
myCondition.setMaxFulfillmentLength(0)
console.log(myCondition.serializeUri())
// prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
```

## API Reference


* [types](#module_types)
    * [~Condition](#module_types..Condition)
        * _instance_
            * [.getTypeId()](#module_types..Condition+getTypeId) ⇒ <code>Number</code>
            * [.setTypeId(type)](#module_types..Condition+setTypeId)
            * [.getBitmask()](#module_types..Condition+getBitmask) ⇒ <code>Number</code>
            * [.setBitmask(bitmask)](#module_types..Condition+setBitmask)
            * [.getHash()](#module_types..Condition+getHash) ⇒ <code>Buffer</code>
            * [.setHash(hash)](#module_types..Condition+setHash)
            * [.getMaxFulfillmentLength()](#module_types..Condition+getMaxFulfillmentLength) ⇒ <code>Number</code>
            * [.setMaxFulfillmentLength(Maximum)](#module_types..Condition+setMaxFulfillmentLength)
            * [.serializeUri()](#module_types..Condition+serializeUri) ⇒ <code>String</code>
            * [.serializeBinary()](#module_types..Condition+serializeBinary) ⇒ <code>Buffer</code>
            * [.validate()](#module_types..Condition+validate) ⇒ <code>Boolean</code>
        * _static_
            * [.fromUri(serializedCondition)](#module_types..Condition.fromUri) ⇒ <code>Condition</code>
            * [.fromBinary(reader)](#module_types..Condition.fromBinary) ⇒ <code>Condition</code>
    * [~Fulfillment](#module_types..Fulfillment)
        * _instance_
            * [.getTypeId()](#module_types..Fulfillment+getTypeId) ⇒ <code>Number</code>
            * [.getBitmask()](#module_types..Fulfillment+getBitmask) ⇒ <code>Number</code>
            * [.getCondition()](#module_types..Fulfillment+getCondition) ⇒ <code>Condition</code>
            * [.getConditionUri()](#module_types..Fulfillment+getConditionUri) ⇒ <code>String</code>
            * [.getConditionBinary()](#module_types..Fulfillment+getConditionBinary) ⇒ <code>Buffer</code>
            * [.serializeUri()](#module_types..Fulfillment+serializeUri) ⇒ <code>String</code>
            * [.serializeBinary()](#module_types..Fulfillment+serializeBinary) ⇒ <code>Buffer</code>
            * [.validate()](#module_types..Fulfillment+validate) ⇒ <code>Boolean</code>
        * _static_
            * [.fromUri(serializedFulfillment)](#module_types..Fulfillment.fromUri) ⇒ <code>Fulfillment</code>
            * [.fromBinary(reader)](#module_types..Fulfillment.fromBinary) ⇒ <code>Fulfillment</code>
    * [~Ed25519](#module_types..Ed25519)
        * [.setPublicKey(publicKey)](#module_types..Ed25519+setPublicKey)
        * [.setSignature(signature)](#module_types..Ed25519+setSignature)
        * [.sign(message, privateKey)](#module_types..Ed25519+sign)
        * [.generateHash(hasher)](#module_types..Ed25519+generateHash)
        * [.validate(message)](#module_types..Ed25519+validate) ⇒ <code>Boolean</code>
    * [~PrefixSha256](#module_types..PrefixSha256)
        * [.setSubcondition(subcondition)](#module_types..PrefixSha256+setSubcondition)
        * [.setSubconditionUri(Subcondition)](#module_types..PrefixSha256+setSubconditionUri)
        * [.setSubfulfillment(fulfillment)](#module_types..PrefixSha256+setSubfulfillment)
        * [.setSubfulfillmentUri(Subfulfillment)](#module_types..PrefixSha256+setSubfulfillmentUri)
        * [.setPrefix(prefix)](#module_types..PrefixSha256+setPrefix)
        * [.getBitmask()](#module_types..PrefixSha256+getBitmask) ⇒ <code>Number</code>
        * [.validate(message)](#module_types..PrefixSha256+validate) ⇒ <code>Boolean</code>
    * [~PreimageSha256](#module_types..PreimageSha256)
        * [.setPreimage(preimage)](#module_types..PreimageSha256+setPreimage)
        * [.validate()](#module_types..PreimageSha256+validate) ⇒ <code>Boolean</code>
    * [~RsaSha256](#module_types..RsaSha256)
        * [.setPublicModulus(modulus)](#module_types..RsaSha256+setPublicModulus)
        * [.setSignature(signature)](#module_types..RsaSha256+setSignature)
        * [.sign(message, privateKey)](#module_types..RsaSha256+sign)
        * [.validate(message)](#module_types..RsaSha256+validate) ⇒ <code>Boolean</code>
    * [~ThresholdSha256](#module_types..ThresholdSha256)
        * [.addSubcondition(subcondition, [weight])](#module_types..ThresholdSha256+addSubcondition)
        * [.addSubconditionUri(Subcondition)](#module_types..ThresholdSha256+addSubconditionUri)
        * [.addSubfulfillment(Fulfillment, [weight])](#module_types..ThresholdSha256+addSubfulfillment)
        * [.addSubfulfillmentUri(Subfulfillment)](#module_types..ThresholdSha256+addSubfulfillmentUri)
        * [.setThreshold(threshold)](#module_types..ThresholdSha256+setThreshold)
        * [.getBitmask()](#module_types..ThresholdSha256+getBitmask) ⇒ <code>Number</code>
        * [.validate(message)](#module_types..ThresholdSha256+validate) ⇒ <code>Boolean</code>


* [util](#module_util)
    * [~BaseError](#module_util..BaseError)
    * [~Base64Url](#module_util..Base64Url)
        * [.decode(base64urlString)](#module_util..Base64Url.decode) ⇒ <code>Buffer</code>
        * [.encode(buffer)](#module_util..Base64Url.encode) ⇒ <code>String</code>
    * [~Pem](#module_util..Pem)
        * [.modulusToPem(modulus)](#module_util..Pem.modulusToPem) ⇒ <code>String</code>
        * [.modulusFromPrivateKey(privateKey)](#module_util..Pem.modulusFromPrivateKey) ⇒ <code>Buffer</code>


<a name="module_types..Condition"></a>

### types~Condition
Crypto-condition.

A primary design goal of crypto-conditions was to keep the size of conditions
constant. Even a complex multi-signature can be represented by the same size
condition as a simple hashlock.

However, this means that a condition only carries the absolute minimum
information required. It does not tell you anything about its structure.

All that is included with a condition is the fingerprint (usually a hash of
the parts of the fulfillment that are known up-front, e.g. public keys), the
maximum fulfillment size, the set of features used and the condition type.

This information is just enough that an implementation can tell with
certainty whether it would be able to process the corresponding fulfillment.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~Condition](#module_types..Condition)
    * _instance_
        * [.getTypeId()](#module_types..Condition+getTypeId) ⇒ <code>Number</code>
        * [.setTypeId(type)](#module_types..Condition+setTypeId)
        * [.getBitmask()](#module_types..Condition+getBitmask) ⇒ <code>Number</code>
        * [.setBitmask(bitmask)](#module_types..Condition+setBitmask)
        * [.getHash()](#module_types..Condition+getHash) ⇒ <code>Buffer</code>
        * [.setHash(hash)](#module_types..Condition+setHash)
        * [.getMaxFulfillmentLength()](#module_types..Condition+getMaxFulfillmentLength) ⇒ <code>Number</code>
        * [.setMaxFulfillmentLength(Maximum)](#module_types..Condition+setMaxFulfillmentLength)
        * [.serializeUri()](#module_types..Condition+serializeUri) ⇒ <code>String</code>
        * [.serializeBinary()](#module_types..Condition+serializeBinary) ⇒ <code>Buffer</code>
        * [.validate()](#module_types..Condition+validate) ⇒ <code>Boolean</code>
    * _static_
        * [.fromUri(serializedCondition)](#module_types..Condition.fromUri) ⇒ <code>Condition</code>
        * [.fromBinary(reader)](#module_types..Condition.fromBinary) ⇒ <code>Condition</code>

<a name="module_types..Condition+getTypeId"></a>

#### condition.getTypeId() ⇒ <code>Number</code>
Return the type of this condition.

The type is a unique integer ID assigned to each type of condition.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Number</code> - Type corresponding to this condition.  
<a name="module_types..Condition+setTypeId"></a>

#### condition.setTypeId(type)
Set the type.

Sets the type ID for this condition.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  

| Param | Type | Description |
| --- | --- | --- |
| type | <code>Number</code> | Integer representation of type. |

<a name="module_types..Condition+getBitmask"></a>

#### condition.getBitmask() ⇒ <code>Number</code>
Return the bitmask of this condition.

For simple condition types this is simply the set of bits representing the
features required by the condition type.

For structural conditions, this is the bitwise OR of the bitmasks of the
condition and all its subconditions, recursively.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Number</code> - Bitmask required to verify this condition.  
<a name="module_types..Condition+setBitmask"></a>

#### condition.setBitmask(bitmask)
Set the bitmask.

Sets the required bitmask to validate a fulfillment for this condition.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  

| Param | Type | Description |
| --- | --- | --- |
| bitmask | <code>Number</code> | Integer representation of bitmask. |

<a name="module_types..Condition+getHash"></a>

#### condition.getHash() ⇒ <code>Buffer</code>
Return the hash of the condition.

A primary component of all conditions is the hash. It encodes the static
properties of the condition. This method enables the conditions to be
constant size, no matter how complex they actually are. The data used to
generate the hash consists of all the static properties of the condition
and is provided later as part of the fulfillment.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Buffer</code> - Hash of the condition  
<a name="module_types..Condition+setHash"></a>

#### condition.setHash(hash)
Validate and set the hash of this condition.

Typically conditions are generated from fulfillments and the hash is
calculated automatically. However, sometimes it may be necessary to
construct a condition URI from a known hash. This method enables that case.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  

| Param | Type | Description |
| --- | --- | --- |
| hash | <code>Buffer</code> | Hash as binary. |

<a name="module_types..Condition+getMaxFulfillmentLength"></a>

#### condition.getMaxFulfillmentLength() ⇒ <code>Number</code>
Return the maximum fulfillment length.

The maximum fulfillment length is the maximum allowed length for any
fulfillment payload to fulfill this condition.

The condition defines a maximum fulfillment length which all
implementations will enforce. This allows implementations to verify that
their local maximum fulfillment size is guaranteed to accomodate any
possible fulfillment for this condition.

Otherwise an attacker could craft a fulfillment which exceeds the maximum
size of one implementation, but meets the maximum size of another, thereby
violating the fundamental property that fulfillments are either valid
everywhere or nowhere.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Number</code> - Maximum length (in bytes) of any fulfillment payload that
  fulfills this condition..  
<a name="module_types..Condition+setMaxFulfillmentLength"></a>

#### condition.setMaxFulfillmentLength(Maximum)
Set the maximum fulfillment length.

The maximum fulfillment length is normally calculated automatically, when
calling `Fulfillment#getCondition`. However, when

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  

| Param | Type | Description |
| --- | --- | --- |
| Maximum | <code>Number</code> | fulfillment payload length in bytes. |

<a name="module_types..Condition+serializeUri"></a>

#### condition.serializeUri() ⇒ <code>String</code>
Generate the URI form encoding of this condition.

Turns the condition into a URI containing only URL-safe characters. This
format is convenient for passing around conditions in URLs, JSON and other
text-based formats.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>String</code> - Condition as a URI  
<a name="module_types..Condition+serializeBinary"></a>

#### condition.serializeBinary() ⇒ <code>Buffer</code>
Serialize condition to a buffer.

Encodes the condition as a string of bytes. This is used internally for
encoding subconditions, but can also be used to passing around conditions
in a binary protocol for instance.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Buffer</code> - Serialized condition  
<a name="module_types..Condition+validate"></a>

#### condition.validate() ⇒ <code>Boolean</code>
Ensure the condition is valid according the local rules.

Checks the condition against the local bitmask (supported condition types)
and the local maximum fulfillment size.

**Kind**: instance method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Boolean</code> - Whether the condition is valid according to local rules.  
<a name="module_types..Condition.fromUri"></a>

#### Condition.fromUri(serializedCondition) ⇒ <code>Condition</code>
Create a Condition object from a URI.

This method will parse a condition URI and construct a corresponding
Condition object.

**Kind**: static method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Condition</code> - Resulting object  

| Param | Type | Description |
| --- | --- | --- |
| serializedCondition | <code>String</code> | URI representing the condition |

<a name="module_types..Condition.fromBinary"></a>

#### Condition.fromBinary(reader) ⇒ <code>Condition</code>
Create a Condition object from a binary blob.

This method will parse a stream of binary data and construct a
corresponding Condition object.

**Kind**: static method of <code>[Condition](#module_types..Condition)</code>  
**Returns**: <code>Condition</code> - Resulting object  

| Param | Type | Description |
| --- | --- | --- |
| reader | <code>Reader</code> | Binary stream implementing the Reader interface |

<a name="module_types..Fulfillment"></a>

### types~Fulfillment
Base class for fulfillment types.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~Fulfillment](#module_types..Fulfillment)
    * _instance_
        * [.getTypeId()](#module_types..Fulfillment+getTypeId) ⇒ <code>Number</code>
        * [.getBitmask()](#module_types..Fulfillment+getBitmask) ⇒ <code>Number</code>
        * [.getCondition()](#module_types..Fulfillment+getCondition) ⇒ <code>Condition</code>
        * [.getConditionUri()](#module_types..Fulfillment+getConditionUri) ⇒ <code>String</code>
        * [.getConditionBinary()](#module_types..Fulfillment+getConditionBinary) ⇒ <code>Buffer</code>
        * [.serializeUri()](#module_types..Fulfillment+serializeUri) ⇒ <code>String</code>
        * [.serializeBinary()](#module_types..Fulfillment+serializeBinary) ⇒ <code>Buffer</code>
        * [.validate()](#module_types..Fulfillment+validate) ⇒ <code>Boolean</code>
    * _static_
        * [.fromUri(serializedFulfillment)](#module_types..Fulfillment.fromUri) ⇒ <code>Fulfillment</code>
        * [.fromBinary(reader)](#module_types..Fulfillment.fromBinary) ⇒ <code>Fulfillment</code>

<a name="module_types..Fulfillment+getTypeId"></a>

#### fulfillment.getTypeId() ⇒ <code>Number</code>
Return the type ID of this fulfillment.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Number</code> - Type ID as an integer.  
<a name="module_types..Fulfillment+getBitmask"></a>

#### fulfillment.getBitmask() ⇒ <code>Number</code>
Return the bitmask of this fulfillment.

For simple fulfillment types this is simply the bit representing this type.

For meta-fulfillments, these are the bits representing the types of the
subconditions.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Number</code> - Bitmask corresponding to this fulfillment.  
<a name="module_types..Fulfillment+getCondition"></a>

#### fulfillment.getCondition() ⇒ <code>Condition</code>
Generate condition corresponding to this fulfillment.

An important property of crypto-conditions is that the condition can always
be derived from the fulfillment. This makes it very easy to post
fulfillments to a system without having to specify which condition the
relate to. The system can keep an index of conditions and look up any
matching events related to that condition.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Condition</code> - Condition corresponding to this fulfillment.  
<a name="module_types..Fulfillment+getConditionUri"></a>

#### fulfillment.getConditionUri() ⇒ <code>String</code>
Shorthand for getting condition URI.

Stands for getCondition().serializeUri().

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>String</code> - Condition URI.  
<a name="module_types..Fulfillment+getConditionBinary"></a>

#### fulfillment.getConditionBinary() ⇒ <code>Buffer</code>
Shorthand for getting condition encoded as binary.

Stands for getCondition().serializeBinary().

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Buffer</code> - Binary encoded condition.  
<a name="module_types..Fulfillment+serializeUri"></a>

#### fulfillment.serializeUri() ⇒ <code>String</code>
Generate the URI form encoding of this fulfillment.

Turns the fulfillment into a URI containing only URL-safe characters. This
format is convenient for passing around fulfillments in URLs, JSON and
other text-based formats.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>String</code> - Fulfillment as a URI  
<a name="module_types..Fulfillment+serializeBinary"></a>

#### fulfillment.serializeBinary() ⇒ <code>Buffer</code>
Serialize fulfillment to a buffer.

Encodes the fulfillment as a string of bytes. This is used internally for
encoding subfulfillments, but can also be used to passing around
fulfillments in a binary protocol for instance.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Buffer</code> - Serialized fulfillment  
<a name="module_types..Fulfillment+validate"></a>

#### fulfillment.validate() ⇒ <code>Boolean</code>
Validate this fulfillment.

This implementation is a stub and will be overridden by the subclasses.

**Kind**: instance method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Boolean</code> - Validation result  
<a name="module_types..Fulfillment.fromUri"></a>

#### Fulfillment.fromUri(serializedFulfillment) ⇒ <code>Fulfillment</code>
Create a Fulfillment object from a URI.

This method will parse a fulfillment URI and construct a corresponding
Fulfillment object.

**Kind**: static method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Fulfillment</code> - Resulting object  

| Param | Type | Description |
| --- | --- | --- |
| serializedFulfillment | <code>String</code> | URI representing the fulfillment |

<a name="module_types..Fulfillment.fromBinary"></a>

#### Fulfillment.fromBinary(reader) ⇒ <code>Fulfillment</code>
Create a Fulfillment object from a binary blob.

This method will parse a stream of binary data and construct a
corresponding Fulfillment object.

**Kind**: static method of <code>[Fulfillment](#module_types..Fulfillment)</code>  
**Returns**: <code>Fulfillment</code> - Resulting object  

| Param | Type | Description |
| --- | --- | --- |
| reader | <code>Reader</code> | Binary stream implementing the Reader interface |

<a name="module_types..Ed25519"></a>

### types~Ed25519
ED25519: Ed25519 signature condition.

This condition implements Ed25519 signatures.

ED25519 is assigned the type ID 4. It relies only on the ED25519 feature
suite which corresponds to a bitmask of 0x20.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~Ed25519](#module_types..Ed25519)
    * [.setPublicKey(publicKey)](#module_types..Ed25519+setPublicKey)
    * [.setSignature(signature)](#module_types..Ed25519+setSignature)
    * [.sign(message, privateKey)](#module_types..Ed25519+sign)
    * [.generateHash(hasher)](#module_types..Ed25519+generateHash)
    * [.validate(message)](#module_types..Ed25519+validate) ⇒ <code>Boolean</code>

<a name="module_types..Ed25519+setPublicKey"></a>

#### ed25519.setPublicKey(publicKey)
Set the public publicKey.

This is the Ed25519 public key. It has to be provided as a buffer.

**Kind**: instance method of <code>[Ed25519](#module_types..Ed25519)</code>  

| Param | Type | Description |
| --- | --- | --- |
| publicKey | <code>Buffer</code> | Public Ed25519 publicKey |

<a name="module_types..Ed25519+setSignature"></a>

#### ed25519.setSignature(signature)
Set the signature.

Instead of using the private key to sign using the sign() method, we can
also generate the signature elsewhere and pass it in.

**Kind**: instance method of <code>[Ed25519](#module_types..Ed25519)</code>  

| Param | Type | Description |
| --- | --- | --- |
| signature | <code>Buffer</code> | 64-byte signature. |

<a name="module_types..Ed25519+sign"></a>

#### ed25519.sign(message, privateKey)
Sign a message.

This method will take a message and an Ed25519 private key and store a
corresponding signature in this fulfillment.

**Kind**: instance method of <code>[Ed25519](#module_types..Ed25519)</code>  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to sign. |
| privateKey | <code>String</code> | Ed25519 private key. |

<a name="module_types..Ed25519+generateHash"></a>

#### ed25519.generateHash(hasher)
Generate the condition hash.

Since the public key is the same size as the hash we'd be putting out here,
we just return the public key.

**Kind**: instance method of <code>[Ed25519](#module_types..Ed25519)</code>  

| Param | Type | Description |
| --- | --- | --- |
| hasher | <code>Hasher</code> | Destination where the hash payload will be written. |

<a name="module_types..Ed25519+validate"></a>

#### ed25519.validate(message) ⇒ <code>Boolean</code>
Verify the signature of this Ed25519 fulfillment.

The signature of this Ed25519 fulfillment is verified against the provided
message and public key.

**Kind**: instance method of <code>[Ed25519](#module_types..Ed25519)</code>  
**Returns**: <code>Boolean</code> - Whether this fulfillment is valid.  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to validate against. |

<a name="module_types..PrefixSha256"></a>

### types~PrefixSha256
PREFIX-SHA-256: Prefix condition using SHA-256.

A prefix condition will prepend a static prefix to the message before passing
the prefixed message on to a single subcondition.

You can use prefix conditions to effectively narrow the scope of a public key
or set of public keys. Simply take the condition representing the public key
and place it as a subcondition in a prefix condition. Now any message passed
to the subcondition will be prepended with a prefix.

Prefix conditions are especially useful in conjunction with threshold
conditions. You could have a group of signers, each using a different prefix
to sign a common message.

PREFIX-SHA-256 is assigned the type ID 1. It relies on the SHA-256 and PREFIX
feature suites which corresponds to a feature bitmask of 0x05.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~PrefixSha256](#module_types..PrefixSha256)
    * [.setSubcondition(subcondition)](#module_types..PrefixSha256+setSubcondition)
    * [.setSubconditionUri(Subcondition)](#module_types..PrefixSha256+setSubconditionUri)
    * [.setSubfulfillment(fulfillment)](#module_types..PrefixSha256+setSubfulfillment)
    * [.setSubfulfillmentUri(Subfulfillment)](#module_types..PrefixSha256+setSubfulfillmentUri)
    * [.setPrefix(prefix)](#module_types..PrefixSha256+setPrefix)
    * [.getBitmask()](#module_types..PrefixSha256+getBitmask) ⇒ <code>Number</code>
    * [.validate(message)](#module_types..PrefixSha256+validate) ⇒ <code>Boolean</code>

<a name="module_types..PrefixSha256+setSubcondition"></a>

#### prefixSha256.setSubcondition(subcondition)
Set the (unfulfilled) subcondition.

Each prefix condition builds on an existing condition which is provided via
this method.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| subcondition | <code>Condition</code> | Condition that will receive the prefixed   message. |

<a name="module_types..PrefixSha256+setSubconditionUri"></a>

#### prefixSha256.setSubconditionUri(Subcondition)
Set the (unfulfilled) subcondition.

This will automatically parse the URI and call setSubcondition.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| Subcondition | <code>String</code> | URI. |

<a name="module_types..PrefixSha256+setSubfulfillment"></a>

#### prefixSha256.setSubfulfillment(fulfillment)
Set the (fulfilled) subcondition.

When constructing a prefix fulfillment, this method allows you to pass in
a fulfillment for the condition that will receive the prefixed message.

Note that you only have to add either the subcondition or a subfulfillment,
but not both.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| fulfillment | <code>Fulfillment</code> | Fulfillment to use for the subcondition. |

<a name="module_types..PrefixSha256+setSubfulfillmentUri"></a>

#### prefixSha256.setSubfulfillmentUri(Subfulfillment)
Set the (fulfilled) subcondition.

This will automatically parse the URI and call setSubfulfillment.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| Subfulfillment | <code>String</code> | URI. |

<a name="module_types..PrefixSha256+setPrefix"></a>

#### prefixSha256.setPrefix(prefix)
Set the prefix.

The prefix will be prepended to the message during validation before the
message is passed on to the subcondition.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| prefix | <code>Buffer</code> | Prefix to apply to the message. |

<a name="module_types..PrefixSha256+getBitmask"></a>

#### prefixSha256.getBitmask() ⇒ <code>Number</code>
Get full bitmask.

This is a type of condition that contains a subcondition. A complete
bitmask must contain the set of types that must be supported in order to
validate this fulfillment. Therefore, we need to calculate the bitwise OR
of this condition's TYPE_BIT and the subcondition's bitmask.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  
**Returns**: <code>Number</code> - Complete bitmask for this fulfillment.  
<a name="module_types..PrefixSha256+validate"></a>

#### prefixSha256.validate(message) ⇒ <code>Boolean</code>
Check whether this fulfillment meets all validation criteria.

This will validate the subfulfillment. The message will be prepended with
the prefix before being passed to the subfulfillment's validation routine.

**Kind**: instance method of <code>[PrefixSha256](#module_types..PrefixSha256)</code>  
**Returns**: <code>Boolean</code> - Whether this fulfillment is valid.  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to validate against. |

<a name="module_types..PreimageSha256"></a>

### types~PreimageSha256
PREIMAGE-SHA-256: Hashlock condition using SHA-256.

This type of condition is also called a hashlock. By creating a hash
of a difficult-to-guess 256-bit random or pseudo-random integer it
is possible to create a condition which the creator can trivially
fulfill by publishing the random value. However, for anyone else,
the condition is cryptgraphically hard to fulfill, because they
would have to find a preimage for the given condition hash.

PREIMAGE-SHA-256 is assigned the type ID 0. It relies on the SHA-256
and PREIMAGE feature suites which corresponds to a feature bitmask
of 0x03.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~PreimageSha256](#module_types..PreimageSha256)
    * [.setPreimage(preimage)](#module_types..PreimageSha256+setPreimage)
    * [.validate()](#module_types..PreimageSha256+validate) ⇒ <code>Boolean</code>

<a name="module_types..PreimageSha256+setPreimage"></a>

#### preimageSha256.setPreimage(preimage)
Provide a preimage.

The preimage is the only input to a SHA256 hashlock condition.

Note that the preimage should contain enough (pseudo-random) data in order
to be difficult to guess. A sufficiently large secret seed and a
cryptographically secure pseudo-random number generator (CSPRNG) can be
used to avoid having to store each individual preimage.

**Kind**: instance method of <code>[PreimageSha256](#module_types..PreimageSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| preimage | <code>Buffer</code> | Secret data that will be hashed to form the condition. |

<a name="module_types..PreimageSha256+validate"></a>

#### preimageSha256.validate() ⇒ <code>Boolean</code>
Validate this fulfillment.

For a SHA256 hashlock fulfillment, successful parsing implies that the
fulfillment is valid, so this method is a no-op.

**Kind**: instance method of <code>[PreimageSha256](#module_types..PreimageSha256)</code>  
**Returns**: <code>Boolean</code> - Validation result  
<a name="module_types..RsaSha256"></a>

### types~RsaSha256
RSA-SHA-256: RSA signature condition using SHA-256.

This RSA condition uses RSA-PSS padding with SHA-256. The salt length is set
equal the digest length of 32 bytes.

The public exponent is fixed at 65537 and the public modulus must be between
128 (1017 bits) and 512 bytes (4096 bits) long.

RSA-SHA-256 is assigned the type ID 3. It relies on the SHA-256 and RSA-PSS
feature suites which corresponds to a feature bitmask of 0x11.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~RsaSha256](#module_types..RsaSha256)
    * [.setPublicModulus(modulus)](#module_types..RsaSha256+setPublicModulus)
    * [.setSignature(signature)](#module_types..RsaSha256+setSignature)
    * [.sign(message, privateKey)](#module_types..RsaSha256+sign)
    * [.validate(message)](#module_types..RsaSha256+validate) ⇒ <code>Boolean</code>

<a name="module_types..RsaSha256+setPublicModulus"></a>

#### rsaSha256.setPublicModulus(modulus)
Set the public modulus.

This is the modulus of the RSA public key. It has to be provided as a raw
buffer with no leading zeros.

**Kind**: instance method of <code>[RsaSha256](#module_types..RsaSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| modulus | <code>Buffer</code> | Public RSA modulus |

<a name="module_types..RsaSha256+setSignature"></a>

#### rsaSha256.setSignature(signature)
Set the signature manually.

The signature must be a valid RSA-PSS siganture.

**Kind**: instance method of <code>[RsaSha256](#module_types..RsaSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| signature | <code>Buffer</code> | RSA signature. |

<a name="module_types..RsaSha256+sign"></a>

#### rsaSha256.sign(message, privateKey)
Sign the message.

This method will take the provided message and create a signature using the
provided RSA private key. The resulting signature is stored in the
fulfillment.

The key should be provided as a PEM encoded private key string.

The message is padded using RSA-PSS with SHA256.

**Kind**: instance method of <code>[RsaSha256](#module_types..RsaSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to sign. |
| privateKey | <code>String</code> | RSA private key |

<a name="module_types..RsaSha256+validate"></a>

#### rsaSha256.validate(message) ⇒ <code>Boolean</code>
Verify the signature of this RSA fulfillment.

The signature of this RSA fulfillment is verified against the provided
message and the condition's public modulus.

**Kind**: instance method of <code>[RsaSha256](#module_types..RsaSha256)</code>  
**Returns**: <code>Boolean</code> - Whether this fulfillment is valid.  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to verify. |

<a name="module_types..ThresholdSha256"></a>

### types~ThresholdSha256
THRESHOLD-SHA-256: Threshold gate condition using SHA-256.

Threshold conditions can be used to create m-of-n multi-signature groups.

Threshold conditions can represent the AND operator by setting the threshold
to equal the number of subconditions (n-of-n) or the OR operator by setting
the thresold to one (1-of-n).

Threshold conditions allows each subcondition to carry an integer weight.

Since threshold conditions operate on conditions, they can be nested as well
which allows the creation of deep threshold trees of public keys.

By using Merkle trees, threshold fulfillments do not need to to provide the
structure of unfulfilled subtrees. That means only the public keys that are
actually used in a fulfillment, will actually appear in the fulfillment,
saving space.

One way to formally interpret threshold conditions is as a boolean weighted
threshold gate. A tree of threshold conditions forms a boolean weighted
threhsold circuit.

THRESHOLD-SHA-256 is assigned the type ID 2. It relies on the SHA-256 and
THRESHOLD feature suites which corresponds to a feature bitmask of 0x09.

**Kind**: inner class of <code>[types](#module_types)</code>  

* [~ThresholdSha256](#module_types..ThresholdSha256)
    * [.addSubcondition(subcondition, [weight])](#module_types..ThresholdSha256+addSubcondition)
    * [.addSubconditionUri(Subcondition)](#module_types..ThresholdSha256+addSubconditionUri)
    * [.addSubfulfillment(Fulfillment, [weight])](#module_types..ThresholdSha256+addSubfulfillment)
    * [.addSubfulfillmentUri(Subfulfillment)](#module_types..ThresholdSha256+addSubfulfillmentUri)
    * [.setThreshold(threshold)](#module_types..ThresholdSha256+setThreshold)
    * [.getBitmask()](#module_types..ThresholdSha256+getBitmask) ⇒ <code>Number</code>
    * [.validate(message)](#module_types..ThresholdSha256+validate) ⇒ <code>Boolean</code>

<a name="module_types..ThresholdSha256+addSubcondition"></a>

#### thresholdSha256.addSubcondition(subcondition, [weight])
Add a subcondition (unfulfilled).

This can be used to generate a new threshold condition from a set of
subconditions or to provide a non-fulfilled subcondition when creating a
threshold fulfillment.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| subcondition | <code>Condition</code> |  | Condition to add |
| [weight] | <code>Number</code> | <code>1</code> | Integer weight of the subcondition. |

<a name="module_types..ThresholdSha256+addSubconditionUri"></a>

#### thresholdSha256.addSubconditionUri(Subcondition)
Add a subcondition (unfulfilled).

This will automatically parse the URI and call addSubcondition.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| Subcondition | <code>String</code> | URI. |

<a name="module_types..ThresholdSha256+addSubfulfillment"></a>

#### thresholdSha256.addSubfulfillment(Fulfillment, [weight])
Add a fulfilled subcondition.

When constructing a threshold fulfillment, this method allows you to
provide a fulfillment for one of the subconditions.

Note that you do **not** have to add the subcondition if you're adding the
fulfillment. The condition can be calculated from the fulfillment and will
be added automatically.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| Fulfillment | <code>Fulfillment</code> |  | to add |
| [weight] | <code>Number</code> | <code>1</code> | Integer weight of the subcondition. |

<a name="module_types..ThresholdSha256+addSubfulfillmentUri"></a>

#### thresholdSha256.addSubfulfillmentUri(Subfulfillment)
Add a fulfilled subcondition.

This will automatically parse the URI and call addSubfulfillment.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| Subfulfillment | <code>String</code> | URI. |

<a name="module_types..ThresholdSha256+setThreshold"></a>

#### thresholdSha256.setThreshold(threshold)
Set the threshold.

Determines the weighted threshold that is used to consider this condition
fulfilled. If the added weight of all valid subfulfillments is greater or
equal to this number, the threshold condition is considered to be
fulfilled.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  

| Param | Type | Description |
| --- | --- | --- |
| threshold | <code>Number</code> | Integer threshold |

<a name="module_types..ThresholdSha256+getBitmask"></a>

#### thresholdSha256.getBitmask() ⇒ <code>Number</code>
Get full bitmask.

This is a type of condition that can contain subconditions. A complete
bitmask must contain the set of types that must be supported in order to
validate this fulfillment. Therefore, we need to calculate the bitwise OR
of this condition's FEATURE_BITMASK and all subcondition's and
subfulfillment's bitmasks.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  
**Returns**: <code>Number</code> - Complete bitmask for this fulfillment.  
<a name="module_types..ThresholdSha256+validate"></a>

#### thresholdSha256.validate(message) ⇒ <code>Boolean</code>
Check whether this fulfillment meets all validation criteria.

This will validate the subfulfillments and verify that there are enough
subfulfillments to meet the threshold.

**Kind**: instance method of <code>[ThresholdSha256](#module_types..ThresholdSha256)</code>  
**Returns**: <code>Boolean</code> - Whether this fulfillment is valid.  

| Param | Type | Description |
| --- | --- | --- |
| message | <code>Buffer</code> | Message to validate against. |


<a name="module_util..BaseError"></a>

### util~BaseError
Extensible error class.

The built-in Error class is not actually a constructor, but a factory. It
doesn't operate on `this`, so if we call it as `super()` it doesn't do
anything useful.

Nonetheless it does create objects that are instanceof Error. In order to
easily subclass error we need our own base class which mimics that behavior
but with a true constructor.

Note that this code is specific to V8 (due to `Error.captureStackTrace`).

**Kind**: inner class of <code>[util](#module_util)</code>  
<a name="module_util..Base64Url"></a>

### util~Base64Url
Utility class for encoding and decoding Base64Url.

**Kind**: inner class of <code>[util](#module_util)</code>  

* [~Base64Url](#module_util..Base64Url)
    * [.decode(base64urlString)](#module_util..Base64Url.decode) ⇒ <code>Buffer</code>
    * [.encode(buffer)](#module_util..Base64Url.encode) ⇒ <code>String</code>

<a name="module_util..Base64Url.decode"></a>

#### Base64Url.decode(base64urlString) ⇒ <code>Buffer</code>
Convert a base64url encoded string to a Buffer.

**Kind**: static method of <code>[Base64Url](#module_util..Base64Url)</code>  
**Returns**: <code>Buffer</code> - Decoded data.  

| Param | Type | Description |
| --- | --- | --- |
| base64urlString | <code>String</code> | base64url-encoded string |

<a name="module_util..Base64Url.encode"></a>

#### Base64Url.encode(buffer) ⇒ <code>String</code>
Encode a buffer as base64url.

**Kind**: static method of <code>[Base64Url](#module_util..Base64Url)</code>  
**Returns**: <code>String</code> - base64url-encoded data.  

| Param | Type | Description |
| --- | --- | --- |
| buffer | <code>Buffer</code> | Data to encode. |

<a name="module_util..Pem"></a>

### util~Pem
Utilities for RSA-related DER/PEM encoding.

**Kind**: inner class of <code>[util](#module_util)</code>  

* [~Pem](#module_util..Pem)
    * [.modulusToPem(modulus)](#module_util..Pem.modulusToPem) ⇒ <code>String</code>
    * [.modulusFromPrivateKey(privateKey)](#module_util..Pem.modulusFromPrivateKey) ⇒ <code>Buffer</code>

<a name="module_util..Pem.modulusToPem"></a>

#### Pem.modulusToPem(modulus) ⇒ <code>String</code>
Convert an RSA modulus to a PEM-encoded RSAPublicKey.

Encodes the public using the RSAPublicKey format given in
RFC 3447, appendix C.

This function assumes that the exponent is 65537.

**Kind**: static method of <code>[Pem](#module_util..Pem)</code>  
**Returns**: <code>String</code> - PEM-encoded RSA public key.  

| Param | Type | Description |
| --- | --- | --- |
| modulus | <code>Buffer</code> | RSA public modulus. |

<a name="module_util..Pem.modulusFromPrivateKey"></a>

#### Pem.modulusFromPrivateKey(privateKey) ⇒ <code>Buffer</code>
Retrieve a modulus from a PEM-encoded private key.

**Kind**: static method of <code>[Pem](#module_util..Pem)</code>  
**Returns**: <code>Buffer</code> - modulus RSA public modulus.  

| Param | Type | Description |
| --- | --- | --- |
| privateKey | <code>String</code> | PEM-encoded RSA private key. |
