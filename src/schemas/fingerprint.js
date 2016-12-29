'use strict'

const asn1 = require('asn1.js')

const Condition = require('./condition').Condition

const PrefixFingerprintContents = asn1.define('PrefixFingerprintContents', function () {
  this.seq().obj(
    this.key('prefix').implicit(0).octstr(),
    this.key('maxMessageLength').implicit(1).int(),
    this.key('subcondition').explicit(2).use(Condition)
  )
})

const ThresholdFingerprintContents = asn1.define('ThresholdFingerprintContents', function () {
  this.seq().obj(
    this.key('threshold').implicit(0).int(),
    this.key('subconditions').implicit(1).setof(Condition)
  )
})

const RsaFingerprintContents = asn1.define('RsaFingerprintContents', function () {
  this.seq().obj(
    this.key('modulus').implicit(0).octstr()
  )
})

const Ed25519FingerprintContents = asn1.define('Ed25519FingerprintContents', function () {
  this.seq().obj(
    this.key('publicKey').implicit(0).octstr()
  )
})

module.exports = {
  PrefixFingerprintContents,
  ThresholdFingerprintContents,
  RsaFingerprintContents,
  Ed25519FingerprintContents
}
