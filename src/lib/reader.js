'use strict'

const UnderflowError = require('../errors/underflow-error')
const ParseError = require('../errors/parse-error')

class Reader {
  constructor (buffer) {
    this.buffer = buffer
    this.cursor = 0
    this.bookmarks = []
  }

  /**
   * Create a Reader from a source of bytes.
   *
   * Currently, this method only allows the creation of a Reader from a Buffer.
   *
   * If the object provided is already a Reader, that reader is returned as is.
   *
   * @param {Reader|Buffer} source Source of binary data.
   * @return {Reader} Instance of Reader
   */
  static from (source) {
    if (Buffer.isBuffer(source)) {
      return new Reader(source)
    } else if (source instanceof Reader) {
      return source
    } else {
      throw new Error('Reader must be given a Buffer')
    }
  }

  /**
   * Store the current cursor position on a stack.
   */
  bookmark () {
    this.bookmarks.push(this.cursor)
  }

  /**
   * Pop the most recently bookmarked cursor position off the stack.
   */
  restore () {
    this.cursor = this.bookmarks.pop()
  }

  /**
   * Ensure this number of bytes is buffered.
   *
   * This method checks that the given number of bytes is buffered and available
   * for reading. If insufficient bytes are available, the method throws an
   * `UnderflowError`.
   *
   * @param {Number} bytes Number of bytes that should be available.
   */
  ensureAvailable (bytes) {
    if (this.buffer.length < (this.cursor + bytes)) {
      throw new UnderflowError('Tried to read ' + bytes + ' bytes, but only ' +
        (this.buffer.length - this.cursor) + ' bytes available')
    }
  }

  /**
   * Read a single unsigned 8 byte integer.
   *
   * @return {Number} Contents of next byte.
   */
  readUInt8 () {
    this.ensureAvailable(1)
    const value = this.buffer.readUInt8(this.cursor)
    this.cursor++
    return value
  }

  /**
   * Look at the next byte, but don't advance the cursor.
   *
   * @return {Number} Contents of the next byte.
   */
  peekUInt8 () {
    this.ensureAvailable(1)
    return this.buffer.readUInt8(this.cursor)
  }

  /**
   * Advance cursor by one byte.
   */
  skipUInt8 () {
    this.cursor++
  }

  /**
   * Read a VARUINT at the cursor position.
   *
   * A VARUINT is a variable length integer encoded as base128 where the highest
   * bit indicates that another byte is following. The first byte contains the
   * seven least significant bits of the number represented.
   *
   * Return the VARUINT and advances the cursor accordingly.
   *
   * @return {Number} Value of the VARUINT.
   */
  readVarUInt () {
    const MSB = 0x80
    const REST = 0x7F

    let byte = 0
    let shift = 0
    let result = 0
    do {
      byte = this.readUInt8()

      result += shift < 28
        ? (byte & REST) << shift
        : (byte & REST) * Math.pow(2, shift)

      shift += 7

      // Don't allow numbers greater than Number.MAX_SAFE_INTEGER
      if (shift > 45) {
        throw new ParseError('Too large variable integer')
      }
    } while (byte & MSB)

    return result
  }

  /**
   * Read the next VARUINT, but don't advance the cursor.
   *
   * @return {Number} VARUINT at the cursor position.
   */
  peekVarUInt () {
    this.bookmark()
    const value = this.readVarUInt()
    this.restore()

    return value
  }

  /**
   * Skip past the VARUINT at the cursor position.
   */
  skipVarUInt () {
    // Read variable integer and ignore output
    this.readVarUInt()
  }

  /**
   * Read a VARBYTES.
   *
   * A VARBYTES field consists of a VARUINT followed by that many bytes.
   *
   * @return {Buffer} Contents of the VARBYTES.
   */
  readVarBytes () {
    const len = this.readVarUInt()
    return this.read(len)
  }

  /**
   * Read a VARBYTES, but do not advance cursor position.
   *
   * @return {Buffer} Contents of the VARBYTES.
   */
  peekVarBytes () {
    this.bookmark()
    const value = this.readVarBytes()
    this.restore()

    return value
  }

  /**
   * Skip a VARBYTES.
   */
  skipVarBytes () {
    const len = this.readVarUInt()
    this.skip(len)
  }

  /**
   * Read a given number of bytes.
   *
   * Returns this many bytes starting at the cursor position and advances the
   * cursor.
   *
   * @param {Number} bytes Number of bytes to read.
   * @return {Buffer} Contents of bytes read.
   */
  read (bytes) {
    this.ensureAvailable(bytes)

    const value = this.buffer.slice(this.cursor, this.cursor + bytes)
    this.cursor += bytes

    return value
  }

  /**
   * Read bytes, but do not advance cursor.
   *
   * @param {Number} bytes Number of bytes to read.
   * @return {Buffer} Contents of bytes read.
   */
  peek (bytes) {
    this.ensureAvailable(bytes)

    return this.buffer.slice(this.cursor, this.cursor + bytes)
  }

  /**
   * Skip a number of bytes.
   *
   * Advances the cursor by this many bytes.
   *
   * @param {Number} bytes Number of bytes to advance the cursor by.
   */
  skip (bytes) {
    this.ensureAvailable(bytes)

    this.cursor += bytes
  }
}

module.exports = Reader
