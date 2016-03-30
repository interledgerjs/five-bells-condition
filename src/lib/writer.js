'use strict'

const MSB = 0x80
const REST = 0x7F
const MSBALL = ~REST
const INT = Math.pow(2, 31)

class Writer {
  constructor () {
    this.components = []
  }

  /**
   * Write a byte to the stream.
   *
   * @param {Number} Data to write. Must be in range 0x00 - 0xff (0 to 255)
   */
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

  /**
   * Write a VARUINT to the stream.
   *
   * A VARUINT is a variable length integer encoded as base128 where the highest
   * bit indicates that another byte is following. The first byte contains the
   * seven least significant bits of the number represented.
   *
   * @param {Number} value Integer to represent.
   */
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

  /**
   * Write a VARBYTES.
   *
   * A VARBYTES field consists of a VARUINT followed by that many bytes.
   *
   * @param {Buffer} buffer Contents of the VARBYTES.
   */
  writeVarBytes (buffer) {
    this.writeVarUInt(buffer.length)
    this.write(buffer)
  }

  /**
   * Write a series of raw bytes.
   *
   * Adds the given bytes to the output buffer.
   *
   * @param {Buffer} buffer Bytes to write.
   */
  write (buffer) {
    this.components.push(buffer)
  }

  /**
   * Return the resulting buffer.
   *
   * Returns the buffer containing the serialized data that was written using
   * this writer.
   *
   * @return {Buffer} Result data.
   */
  getBuffer () {
    // ST: The following debug statement is very useful, so I finally decided to
    // commit it...
    // console.log(this.components.map((x) => x.toString('hex')).join(' '))

    return Buffer.concat(this.components)
  }
}

module.exports = Writer
