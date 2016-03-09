'use strict'

/**
 * Convert a base64url encoded string to a Buffer.
 *
 * @param {String} base64urlString base64url-encoded string
 * @return {Buffer} Decoded data.
 */
const decode = (base64urlString) => {
  const base64String = base64urlString
    .replace(/\-/g, '+')
    .replace(/_/g, '/')
  return new Buffer(base64String, 'base64')
}

/**
 * Encode a buffer as base64url.
 *
 * @param {Buffer} buffer Data to encode.
 * @return {String} base64url-encoded data.
 */
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
