'use strict'

const BaseError = require('./base-error')

class UnderflowError extends BaseError {
  constructor (message) {
    super(message)
  }
}

module.exports = UnderflowError
