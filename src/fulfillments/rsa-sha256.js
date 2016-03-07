'use strict'

const crypto = require('crypto')
const RsaSha256Condition = require('../conditions/rsa-sha256')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const MissingDataError = require('../errors/missing-data-error')

class RsaSha256Fulfillment extends BaseSha256Fulfillment {
  constructor () {
    super()
    this.messagePrefix = new Buffer('')
    this.maxSuffixLength = 0
  }

  writeCommonHeader (writer) {
    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    writer.writeVarBytes(this.modulus)
    writer.writeVarBytes(this.messagePrefix)
    writer.writeVarUInt(this.maxSuffixLength)
  }

  setMessagePrefix (messagePrefix) {
    this.messagePrefix = messagePrefix
  }

  setMaxSuffixLength (suffixLength) {
    this.maxSuffixLength = suffixLength
  }

  setPublicModulus (modulus) {
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

  writeHashPayload (hasher) {
    hasher.writeVarUInt(RsaSha256Fulfillment.BITMASK)
    this.writeCommonHeader(hasher)
  }

  parsePayload (reader) {
    this.setPublicModulus(reader.readVarBytes())
    this.setMessagePrefix(reader.readVarBytes())
    this.setMaxSuffixLength(reader.readVarUInt())
    this.setMessage(reader.readVarBytes())
    this.setSignature(reader.readVarBytes())
  }

  writePayload (writer) {
    this.writeCommonHeader(writer)
    writer.writeVarBytes(this.message)
    writer.writeVarBytes(this.signature)
  }

  calculateMaxFulfillmentLength () {
    const predictor = new Predictor()

    if (!this.modulus) {
      throw new MissingDataError('Requires a public modulus')
    }

    this.writeCommonHeader(predictor)

    // Message suffix
    predictor.writeVarUInt(this.maxSuffixLength)
    predictor.skip(this.maxSuffixLength)

    // Signature
    predictor.writeVarBytes(this.modulus)

    return predictor.getSize()
  }

  validate () {
    // TODO: Validate signature
    return true
  }
}

RsaSha256Fulfillment.BITMASK = 0x02
RsaSha256Fulfillment.ConditionClass = RsaSha256Condition

module.exports = RsaSha256Fulfillment
