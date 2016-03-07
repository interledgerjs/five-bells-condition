'use strict'

const Fulfillment = require('../lib/fulfillment')
const Hasher = require('../lib/hasher')

class BaseSha256Fulfillment extends Fulfillment {
  generateHash () {
    const hasher = new Hasher('sha256')
    this.writeHashPayload(hasher)
    return hasher.getDigest()
  }
}

module.exports = BaseSha256Fulfillment
