'use strict'

const UnderflowError = require('../errors/underflow-error')
const ParseError = require('../errors/parse-error')

class Reader {
  constructor (buffer) {
    this.buffer = buffer
    this.cursor = 0
    this.bookmarks = []
  }

  static from (source) {
    if (Buffer.isBuffer(source)) {
      return new Reader(source)
    } else if (source instanceof Reader) {
      return source
    } else {
      throw new Error('Reader must be given a Buffer')
    }
  }

  bookmark () {
    this.bookmarks.push(this.cursor)
  }

  restore () {
    this.cursor = this.bookmarks.pop()
  }

  ensureAvailable (bytes) {
    if (this.buffer.length < (this.cursor + bytes)) {
      throw new UnderflowError('Tried to read ' + bytes + ' bytes, but only ' +
        (this.buffer.length - this.cursor) + ' bytes available')
    }
  }

  readUInt8 () {
    this.ensureAvailable(1)
    const value = this.buffer.readUInt8(this.cursor)
    this.cursor++
    return value
  }

  peekUInt8 () {
    this.ensureAvailable(1)
    return this.buffer.readUInt8(this.cursor)
  }

  skipUInt8 () {
    this.cursor++
  }

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

  peekVarUInt () {
    this.bookmark()
    const value = this.readVarUInt()
    this.restore()

    return value
  }

  skipVarUInt () {
    // Read variable integer and ignore output
    this.readVarUInt()
  }

  readVarBytes () {
    const len = this.readVarUInt()
    return this.read(len)
  }

  peekVarBytes () {
    this.bookmark()
    const value = this.readVarBytes()
    this.restore()

    return value
  }

  skipVarBytes () {
    const len = this.readVarUInt()
    this.skip(len)
  }

  read (bytes) {
    this.ensureAvailable(bytes)

    const value = this.buffer.slice(this.cursor, this.cursor + bytes)
    this.cursor += bytes

    return value
  }

  peek (bytes) {
    this.ensureAvailable(bytes)

    return this.buffer.slice(this.cursor, this.cursor + bytes)
  }

  skip (bytes) {
    this.ensureAvailable(bytes)

    this.cursor += bytes
  }
}

module.exports = Reader
