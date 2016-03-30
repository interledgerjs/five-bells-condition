'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('PrefixSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:0:AA',
    tinySha256: 'cf:1:0:AQA',
    ed: 'cf:1:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    prefixSha256: 'cf:1:1:AAEAAAA'
  }

  testFromFulfillment(
    ex.emptySha256,
    new Buffer(0),
    'cf:1:1:AAEAAAA',
    'cc:1:1:7:eZeeXBscqmLWm-xbJoR2tAx-7Oy6aQuk8xsEtb4yZp0:2'
  )

  testFromFulfillment(
    ex.prefixSha256,
    new Buffer(0),
    'cf:1:1:AAEAAQABAAAA',
    'cc:1:1:7:fJKlj9znSC6h4N6Wevr7hv8eD81ziHmWLRwmtb1O740:3'
  )

  testFromFulfillment(
    ex.ed,
    new Buffer('ff00ff00abab', 'hex'),
    'cf:1:1:Bv8A_wCrqwEABCB2oVkgRKbk9REmW8pzpgTZCwUp0d9gK-MKGakldmDR9UCuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NQ',
    'cc:1:1:25:vKu8fV0nuLlK9Pfgpvj0MxBoZ1MZeAnBWY3jWvCjhlc:103'
  )

  function testFromFulfillment (subfulfillment, prefix, fulfillmentUri, conditionUri) {
    describe(conditionUri, function () {
      it('generates the correct fulfillment uri', function () {
        const f = new condition.PrefixSha256Fulfillment()
        f.setSubfulfillment(condition.fromFulfillmentUri(subfulfillment))
        f.setPrefix(prefix)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates the correct condition uri', function () {
        const f = new condition.PrefixSha256Fulfillment()
        f.setSubfulfillment(condition.fromFulfillmentUri(subfulfillment))
        f.setPrefix(prefix)
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })
    })
  }
})
