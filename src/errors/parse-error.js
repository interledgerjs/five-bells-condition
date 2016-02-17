'use strict'

const BaseError = require('./base-error')

class ParseError extends BaseError {
  constructor (message) {
    super(message)
  }
}

module.exports = ParseError
