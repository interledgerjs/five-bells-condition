'use strict'

class Predictor {
  constructor () {
    this.size = 0
  }

  /**
   * Add one byte to the predicted size.
   */
  writeUInt8 () {
    this.size++
  }

  /**
   * Calculate the size of a VARUINT.
   *
   * A VARUINT is a variable length integer encoded as base128 where the highest
   * bit indicates that another byte is following. The first byte contains the
   * seven least significant bits of the number represented.
   *
   * @param {Number} val Integer to be encoded
   */
  writeVarUInt (val) {
    if (val === 0) {
      this.size++
    } else if (val < 0) {
      throw new Error('Variable length integer cannot be negative')
    } else if (val > Math.MAX_SAFE_INTEGER) {
      throw new Error('Variable length integer too large')
    } else {
      // Calculate number of bits divided by seven
      this.size += Math.ceil((Math.floor(Math.log2(val)) + 1) / 7)
    }
  }

  /**
   * Calculate the size of a VARBYTES.
   *
   * A VARBYTES field consists of a VARUINT followed by that many bytes.
   *
   * @param {Buffer} val Contents for VARBYTES
   */
  writeVarBytes (val) {
    this.writeVarUInt(val.length)
    this.size += val.length
  }

  /**
   * Pretend to write a series of bytes.
   *
   * @param {Buffer} Bytes to write.
   */
  write (bytes) {
    this.size += bytes.length
  }

  /**
   * Add this many bytes to the predicted size.
   *
   * @param {Number} Number of bytes to pretend to write.
   */
  skip (bytes) {
    this.size += bytes
  }

  /**
   * Get the size the buffer would have if this was a real writer.
   *
   * @return {Number} Size in bytes.
   */
  getSize () {
    return this.size
  }
}

module.exports = Predictor
