'use strict'

const varuint = require('./varuint')
const varstr = require('./varstr')

const decodeBase64url = (base64urlString) => {
  const base64String = base64urlString
    .replace(/\-/g, '+')
    .replace(/_/g, '/')
  return new Buffer(base64String, 'base64')
}

const encodeBase64url = (buffer) => {
  return buffer.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

module.exports = {
  varuint,
  varstr,
  decodeBase64url,
  encodeBase64url
}
