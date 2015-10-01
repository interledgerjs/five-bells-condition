'use strict'

const _ = require('lodash')
const crypto = require('crypto')
const tv4 = require('tv4')
const formats = require('tv4-formats')

const schemaJson = require('../../schemas/Condition.json')

tv4.addFormat(formats)
class Condition {
  static validate (condition) {
    return tv4.validateMultiple(condition, schemaJson)
  }

  static testFulfillment (condition, fulfillment) {
    switch (condition.type) {
      case 'sha256':
        return this.testHashSha256(condition, fulfillment)
      case 'before':
        return this.testTimeBefore(condition)
      case 'and':
        return this.testBooleanAnd(condition, fulfillment)
      default:
        return false
    }
  }

  static testHashSha256 (condition, fulfillment) {
    const hash = crypto.createHash('sha256')
    hash.update(fulfillment.message)
    const digest = hash.digest('hex')
    return condition.digest.toUpperCase() === digest.toUpperCase()
  }

  static testTimeBefore (condition) {
    return Number(new Date()) < Number(new Date(condition.date))
  }

  static testBooleanAnd (condition, fulfillment) {
    return _(condition.subconditions)
      .zip(fulfillment.subfulfillments)
      .map(_.spread(this.testFulfillment.bind(this)))
      .every()
  }
}

module.exports = Condition
