import asn1 from 'asn1.js'

import { Condition } from './condition'

export const PrefixFingerprintContents = asn1.define('PrefixFingerprintContents', function () {
  this.seq().obj(
    this.key('prefix').implicit(0).octstr(),
    this.key('maxMessageLength').implicit(1).int(),
    this.key('subcondition').explicit(2).use(Condition)
  )
})

export const ThresholdFingerprintContents = asn1.define('ThresholdFingerprintContents', function () {
  this.seq().obj(
    this.key('threshold').implicit(0).int(),
    this.key('subconditions').implicit(1).setof(Condition)
  )
})

export const RsaFingerprintContents = asn1.define('RsaFingerprintContents', function () {
  this.seq().obj(
    this.key('modulus').implicit(0).octstr()
  )
})

export const Ed25519FingerprintContents = asn1.define('Ed25519FingerprintContents', function () {
  this.seq().obj(
    this.key('publicKey').implicit(0).octstr()
  )
})
