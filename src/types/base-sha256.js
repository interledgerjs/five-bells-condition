'use strict'

const util = require('../util')
class BaseSha256 {
  getHash () {
    if (!this.hash) {
      this.hash = this.generateHash()
    }

    return this.hash
  }

  setHash (hash) {
    this.hash = hash
  }

  serializeCondition () {
    return 'cc:1:' + util.encodeBase64url(this.serializeConditionPayload())
  }

  serializeConditionPayload () {
    return Buffer.concat([
      new Buffer([this.constructor.BITMASK]),
      this.getHash(),
      util.varuint.encode(this.getMaxFulfillmentLength())
    ])
  }

  serializeFulfillment () {
    return 'cf:1:' + util.encodeBase64url(this.serializeFulfillmentPayload())
  }
}

module.exports = BaseSha256
