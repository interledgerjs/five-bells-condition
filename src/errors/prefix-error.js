'use strict'

const BaseError = require('./base-error')

class PrefixError extends BaseError {
  constructor (message) {
    super(message)
  }
}

module.exports = PrefixError
