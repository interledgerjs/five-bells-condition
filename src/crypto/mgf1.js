'use strict'

const crypto = require('crypto')
const Hasher = require('../lib/hasher')

class Mgf1 {
  constructor (opts) {
    opts = opts || {}

    this.hashAlgorithm = opts.hashAlgorithm || 'sha256'
    this.hashLength = Hasher.getLength(this.hashAlgorithm)
    this.saltLength = this.hashLength
  }

  /**
   * Generate MGF1 full domain hash.
   *
   * Implementation of RFC 3447, section B.2.1.
   *
   * @param {Buffer} seed Seed from which mask is generated.
   * @param {Number} maskLength Intended length of the mask in bytes.
   * @return {Buffer} Mask
   */
  generate (seed, maskLength) {
    const result = new Buffer(maskLength)

    const len = Math.ceil(maskLength / this.hashLength)
    for (let i = 0; i < len; i++) {
      const counter = new Buffer(4)
      counter.writeInt32BE(i, 0)

      const hash = crypto.createHash(this.hashAlgorithm)
        .update(seed)
        .update(counter)
        .digest()

      hash.copy(result, i * this.hashLength)
    }

    return result
  }
}

module.exports = Mgf1
