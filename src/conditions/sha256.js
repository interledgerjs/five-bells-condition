'use strict'

const BaseSha256Condition = require('./base-sha256')

class Sha256Condition extends BaseSha256Condition {
}

Sha256Condition.BITMASK = 0x01

module.exports = Sha256Condition
