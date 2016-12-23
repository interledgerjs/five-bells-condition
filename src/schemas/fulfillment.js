'use strict'

const asn = require('asn1.js')

const Condition = require('./condition').Condition

const PreimageFulfillment = asn.define('PreimageFulfillment', function () {
  this.seq().obj(
    this.key('preimage').implicit(0).octstr()
  )
})

const PrefixFulfillment = asn.define('PrefixFulfillment', function () {
  this.seq().obj(
    this.key('prefix').implicit(0).octstr(),
    this.key('maxMessageLength').implicit(1).int(),
    this.key('subfulfillment').explicit(2).use(Fulfillment)
  )
})

const ThresholdFulfillment = asn.define('ThresholdFulfillment', function () {
  this.seq().obj(
    this.key('subfulfillments').implicit(0).setof(Fulfillment),
    this.key('subconditions').implicit(1).setof(Condition)
  )
})

const RsaSha256Fulfillment = asn.define('RsaSha256Fulfillment', function () {
  this.seq().obj(
    this.key('modulus').implicit(0).octstr(),
    this.key('signature').implicit(1).octstr()
  )
})

const Ed25519Sha256Fulfillment = asn.define('Ed25519Sha256Fulfillment', function () {
  this.seq().obj(
    this.key('publicKey').implicit(0).octstr(),
    this.key('signature').implicit(1).octstr()
  )
})

const Fulfillment = asn.define('Fulfillment', function () {
  this.choice({
    preimageSha256Fulfillment: this.implicit(0).use(PreimageFulfillment),
    prefixSha256Fulfillment: this.implicit(1).use(PrefixFulfillment),
    thresholdSha256Fulfillment: this.implicit(2).use(ThresholdFulfillment),
    rsaSha256Fulfillment: this.implicit(3).use(RsaSha256Fulfillment),
    ed25519Sha256Fulfillment: this.implicit(4).use(Ed25519Sha256Fulfillment)
  })
})

module.exports = {
  PreimageFulfillment,
  PrefixFulfillment,
  ThresholdFulfillment,
  RsaSha256Fulfillment,
  Ed25519Sha256Fulfillment,
  Fulfillment
}
