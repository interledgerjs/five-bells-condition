'use strict'

const crypto = require('crypto')
const Writer = require('./writer')

class Hasher extends Writer {
  constructor (algorithm) {
    super()

    this.hash = crypto.createHash(algorithm)
  }

  write (bytes) {
    this.hash.update(bytes)
  }

  getDigest () {
    return this.hash.digest()
  }
}

module.exports = Hasher
