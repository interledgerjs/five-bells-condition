'use strict'

const varint = require('varint')

const encode = (num) => {
  return new Buffer(varint.encode(num))
}

const decode = (buffer, offset) => {
  const num = varint.decode(buffer, offset)

  // JavaScript supports a lower range of numbers than what can be expressed
  // as a varint. So we need to be careful when decoding.
  if (!varint.decode.bytes || varint.decode.bytes > 7) {
    return void 0
  }

  return num
}

const predictLength = varint.encodingLength

module.exports = {
  encode,
  decode,
  predictLength
}
