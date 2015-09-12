'use strict'

const crypto = require('crypto')
const skeemas = require('skeemas')()

const schemaJson = require('../../schemas/Condition.json')
skeemas.addRef('Condition.json', schemaJson)

class Condition {
  static validate (condition) {
    return skeemas.validate(condition, 'Condition.json')
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
