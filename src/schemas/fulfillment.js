import asn from 'asn1.js'

import { Condition } from './condition'

export const PreimageFulfillment = asn.define('PreimageFulfillment', function () {
  this.seq().obj(
    this.key('preimage').implicit(0).octstr()
  )
})

export const PrefixFulfillment = asn.define('PrefixFulfillment', function () {
  this.seq().obj(
    this.key('prefix').implicit(0).octstr(),
    this.key('maxMessageLength').implicit(1).int(),
    this.key('subfulfillment').explicit(2).use(Fulfillment)
  )
})

export const ThresholdFulfillment = asn.define('ThresholdFulfillment', function () {
  this.seq().obj(
    this.key('subfulfillments').implicit(0).setof(Fulfillment),
    this.key('subconditions').implicit(1).setof(Condition)
  )
})

export const RsaSha256Fulfillment = asn.define('RsaSha256Fulfillment', function () {
  this.seq().obj(
    this.key('modulus').implicit(0).octstr(),
    this.key('signature').implicit(1).octstr()
  )
})

export const Ed25519Sha256Fulfillment = asn.define('Ed25519Sha256Fulfillment', function () {
  this.seq().obj(
    this.key('publicKey').implicit(0).octstr(),
    this.key('signature').implicit(1).octstr()
  )
})

export const Fulfillment = asn.define('Fulfillment', function () {
  this.choice({
    preimageSha256Fulfillment: this.implicit(0).use(PreimageFulfillment),
    prefixSha256Fulfillment: this.implicit(1).use(PrefixFulfillment),
    thresholdSha256Fulfillment: this.implicit(2).use(ThresholdFulfillment),
    rsaSha256Fulfillment: this.implicit(3).use(RsaSha256Fulfillment),
    ed25519Sha256Fulfillment: this.implicit(4).use(Ed25519Sha256Fulfillment)
  })
})
