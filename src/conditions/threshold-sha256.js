'use strict'

const BaseSha256 = require('./base-sha256')

class ThresholdSha256 extends BaseSha256 {
}

ThresholdSha256.BITMASK = 0x04

module.exports = ThresholdSha256
