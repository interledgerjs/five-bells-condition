'use strict'

const asn = require('asn1.js')

exports.Simple256Condition = asn.define('Simple256Condition', function () {
  this.seq().obj(
    this.key('fingerprint').implicit(0).octstr(),
    this.key('cost').implicit(1).int()
  )
})

exports.Compound256Condition = asn.define('Compound256Condition', function () {
  this.seq().obj(
    this.key('fingerprint').implicit(0).octstr(),
    this.key('cost').implicit(1).int(),
    this.key('subtypes').implicit(2).bitstr()
  )
})

exports.Condition = asn.define('Condition', function () {
  this.choice({
    preimageSha256Condition: this.implicit(0).use(exports.Simple256Condition),
    prefixSha256Condition: this.implicit(1).use(exports.Compound256Condition),
    thresholdSha256Condition: this.implicit(2).use(exports.Compound256Condition),
    rsaSha256Condition: this.implicit(3).use(exports.Simple256Condition),
    ed25519Sha256Condition: this.implicit(4).use(exports.Simple256Condition)
  })
})
