'use strict'

/**
 * @module util
 */

const asn1 = require('asn1.js')

// Crypto-conditions always use the same RSA exponent, namely 65537
const RSA_EXPONENT = 65537

/**
 * ASN.1 schema for RSA public key.
 *
 * From RFC 3447, section A.1.1.
 *
 *    RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *    }
 *
 * @type {asn1.Entity}
 */
const RsaPublicKey = asn1.define('RsaPublicKey', function () {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  )
})

/**
 * ASN.1 schema for RSA private key.
 *
 * From RFC 3447, section A.1.2.
 *
 *    RSAPrivateKey ::= SEQUENCE {
 *      version           Version,
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER,  -- e
 *      privateExponent   INTEGER,  -- d
 *      prime1            INTEGER,  -- p
 *      prime2            INTEGER,  -- q
 *      exponent1         INTEGER,  -- d mod (p-1)
 *      exponent2         INTEGER,  -- d mod (q-1)
 *      coefficient       INTEGER,  -- (inverse of q) mod p
 *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
 *    }
 *
 *    Version ::= INTEGER { two-prime(0), multi(1) }
 *      (CONSTRAINED BY {
 *        -- version must be multi if otherPrimeInfos present --
 *      })
 *
 *    OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
 *
 *    OtherPrimeInfo ::= SEQUENCE {
 *      prime             INTEGER,  -- ri
 *      exponent          INTEGER,  -- di
 *      coefficient       INTEGER   -- ti
 *    }
 *
 * @type {asn1.Entity}
 */
const RsaPrivateKey = asn1.define('RsaPrivateKey', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int(),
    this.optional().key('otherPrimeInfos').seqof(this.obj(
      this.key('prime').int(),
      this.key('exponent').int(),
      this.key('coefficient').int()
    ))
  )
})

/**
 * Utilities for RSA-related DER/PEM encoding.
 */
class Pem {
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
  static modulusToPem (modulus) {
    // We expect the modulus with no leading zeros
    if (modulus[0] === 0) {
      throw new Error('Modulus may not start with zero')
    }

    // If the high bit is set, we need to prefix a zero
    if (modulus[0] & 0x80) {
      modulus = Buffer.concat([new Buffer([0]), modulus])
    }

    const derPublicKey = RsaPublicKey.encode({
      modulus,
      publicExponent: RSA_EXPONENT
    })

    return (
      '-----BEGIN RSA PUBLIC KEY-----\n' +
      derPublicKey.toString('base64').match(/.{1,64}/g).join('\n') + '\n' +
      '-----END RSA PUBLIC KEY-----\n'
    )
  }

  /**
   * Retrieve a modulus from a PEM-encoded private key.
   *
   * @param {String} privateKey PEM-encoded RSA private key.
   * @return {Buffer} modulus RSA public modulus.
   */
  static modulusFromPrivateKey (privateKey) {
    const pem = privateKey
      .replace('-----BEGIN RSA PRIVATE KEY-----', '')
      .replace('-----END RSA PRIVATE KEY-----', '')
      .replace(/\s+|\n\r|\n|\r$/gm, '')
    const buffer = new Buffer(pem, 'base64')

    const decodedPrivateKey = RsaPrivateKey.decode(buffer)
    const modulus = decodedPrivateKey.modulus.toArrayLike(Buffer)
    return modulus
  }
}

module.exports = Pem
