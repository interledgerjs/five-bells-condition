'use strict'

class Predictor {
  constructor () {
    this.size = 0
  }

  writeUInt8 () {
    this.size++
  }

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

  writeVarBytes (val) {
    this.writeVarUInt(val.length)
    this.size += val.length
  }

  skip (bytes) {
    this.size += bytes
  }

  getSize () {
    return this.size
  }
}

module.exports = Predictor
