'use strict'

const crypto = require('crypto')
const util = require('../util')
const varuint = util.varuint
const BaseSha256 = require('./base-sha256')
const ParseError = require('../errors/parse-error')
const MissingDataError = require('../errors/missing-data-error')
const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

class RsaSha256 extends BaseSha256 {
  constructor () {
    super()
    this.messagePrefix = new Buffer('')
    this.maxMessageLength = 0
  }

  parseConditionPayload (payload) {
    if (payload[0] !== RsaSha256.BITMASK) {
      throw new UnsupportedBitmaskError('Unexpected bitmask in payload')
    }

    if (payload.length < 34) {
      throw new ParseError('Payload too short for a SHA256 condition')
    }

    this.setHash(payload.slice(1, 33))
    const maxFulfillmentLength = varuint.decode(payload, 33)
    // TODO check for invalid preimage length
    this.setMaxFulfillmentLength(maxFulfillmentLength)
  }

  parseFulfillmentPayload (payload) {
    if (payload[0] !== RsaSha256.BITMASK) {
      throw new UnsupportedBitmaskError('Unexpected bitmask in payload')
    }

    if (payload.length < 2) {
      throw new ParseError('Payload too short for an RSA-SHA256 fulfillment')
    }
  }

  generateHash () {
    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    const hash = crypto.createHash('sha256')
      .update(new Buffer([RsaSha256.BITMASK]))
      .update(varuint.encode(this.modulus.length))
      .update(this.modulus)
      .update(varuint.encode(this.messagePrefix.length))
      .update(this.messagePrefix)
      .digest()

    return hash
  }

  setMessagePrefix (messagePrefix) {
    this.hash = null

    this.messagePrefix = messagePrefix
  }

  getMaxFulfillmentLength () {
    if (!this.maxFulfillmentLength) {
      this.maxFulfillmentLength = this.calculateMaxFulfillmentLength()
    }

    return this.maxFulfillmentLength
  }

  setMaxFulfillmentLength (fulfillmentLength) {
    this.maxFulfillmentLength = fulfillmentLength
  }

  calculateMaxFulfillmentLength () {
    let maxFulfillmentLength = 0

    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    // Modulus
    maxFulfillmentLength += util.varstr.predictLength(this.modulus)

    // Message Prefix
    maxFulfillmentLength += util.varstr.predictLength(this.messagePrefix)

    // Message
    maxFulfillmentLength += util.varstr.predictLength(this.maxMessageLength)

    // Signature
    maxFulfillmentLength += this.modulus.length

    // Bytes unused
    maxFulfillmentLength += 1

    return maxFulfillmentLength
  }

  setMaxMessageLength (messageLength) {
    this.maxMessageLength = messageLength
  }

  setPublicModulus (modulus) {
    this.hash = null

    this.modulus = modulus
  }

  setMessage (message) {
    this.message = message
  }

  sign (privateKey) {
    this.signature = crypto.createSign('RSA-SHA256')
      .update(this.messagePrefix)
      .update(this.message)
      .sign(privateKey)
  }

  validate () {
    return true
  }

  validateFulfillment () {
    return true
  }

  serializeFulfillmentPayload () {
    const payloadComponents = [
      varuint.encode(this.modulus.length),
      this.modulus,
      varuint.encode(this.messagePrefix.length),
      this.messagePrefix,
      varuint.encode(this.message.length),
      this.message,
      this.signature
    ]

    const innerPayloadLength = payloadComponents.reduce((sum, len) => sum + len, 0)
    const bytesUnused = this.getMaxFulfillmentLength() - innerPayloadLength

    if (bytesUnused < 1) {
      throw new Error('Insufficient space for message')
    }

    payloadComponents.push(util.varuint.encode(bytesUnused))

    return Buffer.concat(payloadComponents)
  }
}

RsaSha256.BITMASK = 0x02

module.exports = RsaSha256
