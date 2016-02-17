'use strict'

const BaseError = require('./base-error')

class MissingDataError extends BaseError {
  constructor (message) {
    super(message)
  }
}

module.exports = MissingDataError
