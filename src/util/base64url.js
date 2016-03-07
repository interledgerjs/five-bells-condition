'use strict'

const decode = (base64urlString) => {
  const base64String = base64urlString
    .replace(/\-/g, '+')
    .replace(/_/g, '/')
  return new Buffer(base64String, 'base64')
}

const encode = (buffer) => {
  return buffer.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

module.exports = {
  decode,
  encode
}
