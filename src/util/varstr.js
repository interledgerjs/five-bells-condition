'use strict'

const varuint = require('./varuint')

const predictLength = function (len) {
  if (len.length) len = len.length

  return varuint.predictLength(len) + len
}

module.exports = {
  predictLength
}
