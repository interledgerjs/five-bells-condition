'use strict'

const BaseError = require('./base-error')

class UnsupportedBitmaskError extends BaseError {
  constructor (message) {
    super(message)
  }
}

module.exports = UnsupportedBitmaskError
