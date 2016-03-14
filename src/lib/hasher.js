'use strict'

const crypto = require('crypto')
const Writer = require('./writer')

class Hasher extends Writer {
  constructor (algorithm) {
    super()

    this.hash = crypto.createHash(algorithm)
  }

  /**
   * Adds bytes to the hash input.
   *
   * The hasher will pass these bytes into the hashing function. By overriding
   * the Writer class and implementing this method, the Hasher supports any of
   * the datatypes that a Writer can write.
   *
   * @param {Buffer} bytes Bytes to add to the hash.
   */
  write (bytes) {
    this.hash.update(bytes)
  }

  /**
   * Return the hash.
   *
   * Returns the finished hash based on what has been written to the Hasher so
   * far.
   *
   * @return {Buffer} Resulting hash.
   */
  getDigest () {
    return this.hash.digest()
  }

  /**
   * Get digest length for hashing algorithm.
   *
   * @param {String} algorithm Hashing algorithm identifier.
   * @return {Number} Digest length in bytes.
   */
  static getLength (algorithm) {
    return crypto.createHash(algorithm).digest().length
  }
}

module.exports = Hasher
