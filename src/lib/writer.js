'use strict'

const MSB = 0x80
const REST = 0x7F
const MSBALL = ~REST
const INT = Math.pow(2, 31)

class Writer {
  constructor () {
    this.components = []
  }

  writeUInt8 (byte) {
    if (typeof byte !== 'number') {
      throw new Error('UInt8 must be a number')
    } else if (byte < 0) {
      throw new Error('UInt8 must be positive')
    } else if (byte > 0xff) {
      throw new Error('UInt8 must be less than or equal to 0xff')
    } else if (!Number.isInteger(byte)) {
      throw new Error('UInt8 must be an integer')
    }

    this.write(new Buffer([byte]))
  }

  writeVarUInt (value) {
    const out = []
    let offset = 0

    while (value >= INT) {
      out[offset++] = (value & 0xff) | MSB
      value /= 128
    }

    while (value & MSBALL) {
      out[offset++] = (value & 0xff) | MSB
      value >>>= 7
    }

    out[offset] = value | 0

    this.write(new Buffer(out))
  }

  writeVarBytes (buffer) {
    this.writeVarUInt(buffer.length)
    this.write(buffer)
  }

  write (buffer) {
    this.components.push(buffer)
  }

  getBuffer () {
    return Buffer.concat(this.components)
  }
}

module.exports = Writer
