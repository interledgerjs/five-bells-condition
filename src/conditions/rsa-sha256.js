'use strict'

const BaseSha256Condition = require('./base-sha256')

class RsaSha256Condition extends BaseSha256Condition {
}

RsaSha256Condition.BITMASK = 0x02

module.exports = RsaSha256Condition
