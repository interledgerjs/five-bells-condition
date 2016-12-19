'use strict'

const asn1 = require('asn1.js')

const RsaPublicKey = asn1.define('RSAPublicKey', function () {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  )
})

module.exports = {
  RsaPublicKey
}
