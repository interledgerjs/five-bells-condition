'use strict'

const crypto = require('crypto')
const tv4 = require('tv4')

const schemaJson = require('../../schemas/Condition.json')

class Condition {
  static validate (condition) {
    return tv4.validateMultiple(condition, schemaJson)
  }

  static testFulfillment (condition, fulfillment) {
    switch (condition.type) {
      case 'sha256':
        return this.testSha256Fulfillment(condition, fulfillment)
      default:
        return false
    }
  }

  static testSha256Fulfillment (condition, fulfillment) {
    const hash = crypto.createHash('sha256')
    hash.update(fulfillment.message)
    const digest = hash.digest('hex')
    return condition.digest === digest
  }
}

module.exports = Condition
