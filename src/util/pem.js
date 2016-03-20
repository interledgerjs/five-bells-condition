'use strict'

// 02          ; tag (0x02 = INTEGER)
// 03          ; length (0x03 = 3 bytes)
// 01 00 01    ; value (0x010001 = 65537)
const RSA_EXPONENT_65537 = new Buffer('0203010001', 'hex')

/**
 * Create a DER field header.
 *
 * @param {Number} tag DER field tag.
 * @param {Number} contentLength Length of the following content.
 * @return {Buffer} Encoded header bytes.
 */
function encodeHeader (tag, contentLength) {
  if (contentLength < 0x80) {
    const header = new Buffer(2)
    header[0] = tag
    header[1] = contentLength
    return header
  }

  const lengthBytes = Math.ceil(contentLength.toString(2).length / 8)

  const header = new Buffer(2 + lengthBytes)
  header[0] = tag
  header[1] = 0x80 | lengthBytes
  for (let i = 1 + lengthBytes, j = contentLength; j > 0; i--, j >>= 8) {
    header[i] = j & 0xff
  }

  return header
}

/**
 * Convert an RSA modulus to a PEM-encoded RSAPublicKey.
 *
 * Encodes the public using the RSAPublicKey format given in
 * RFC 3447, appendix C.
 *
 * This function assumes that the exponent is 65537.
 *
 * @param {Buffer} modulus RSA public modulus.
 * @return {String} PEM-encoded RSA public key.
 */
function modulusToPem (modulus) {
  // We expect the modulus with no leading zeros
  if (modulus[0] === 0) {
    throw new Error('Modulus may not start with zero')
  }

  // If the high bit is set, we need to prefix a zero
  if (modulus[0] & 0x80) {
    modulus = Buffer.concat([new Buffer([0]), modulus])
  }

  const modulusHeader = encodeHeader(0x02, modulus.length)

  const sequenceLength =
    modulusHeader.length +
    modulus.length +
    RSA_EXPONENT_65537.length
  const sequenceHeader = encodeHeader(0x30, sequenceLength)

  return (
    '-----BEGIN RSA PUBLIC KEY-----\n' +
    Buffer.concat([
      sequenceHeader,
      modulusHeader,
      modulus,
      RSA_EXPONENT_65537
    ]).toString('base64').match(/.{1,64}/g).join('\n') + '\n' +
    '-----END RSA PUBLIC KEY-----\n'
  )
}

module.exports = {
  encodeHeader,
  modulusToPem
}
