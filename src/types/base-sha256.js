'use strict'

const util = require('../util')
const MissingDataError = require('../errors/missing-data-error')

class BaseSha256 {
  getBitmask () {
    return this.constructor.BITMASK
  }

  getHash () {
    if (!this.hash) {
      this.hash = this.generateHash()
    }

    return this.hash
  }

  setHash (hash) {
    this.hash = hash
  }

  getMaxFulfillmentLength () {
    if (typeof this.maxFulfillmentLength !== 'number') {
      throw new MissingDataError('Could not generate condition, no maximum fulfillment length provided')
    }

    return this.maxFulfillmentLength
  }

  setMaxFulfillmentLength (maxFulfillmentLength) {
    this.maxFulfillmentLength = maxFulfillmentLength
  }

  parseConditionBinary (payload) {
    this.setHash(payload.slice(1, 33))
    this.setMaxFulfillmentLength(util.varuint.decode(payload, 33))
  }

  serializeConditionUri () {
    return 'cc:1:' + this.getBitmask().toString(16) +
      ':' + util.encodeBase64url(this.getHash()) +
      ':' + this.getMaxFulfillmentLength()
  }

  serializeConditionBinary () {
    return Buffer.concat([
      new Buffer([this.getBitmask()]),
      this.getHash(),
      util.varuint.encode(this.getMaxFulfillmentLength())
    ])
  }

  serializeFulfillmentUri () {
    return 'cf:1:' + this.getBitmask().toString(16) + ':' +
      util.encodeBase64url(this.serializeFulfillmentPayload())
  }

  serializeFulfillmentBinary () {
    return Buffer.concat([
      new Buffer([this.getBitmask()]),
      this.serializeFulfillmentPayload()
    ])
  }
}

module.exports = BaseSha256
