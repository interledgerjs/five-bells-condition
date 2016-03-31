'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('PrefixSha256', function () {
  const ex = {
    emptySha256: 'cf:0:',
    tinySha256: 'cf:0:AA',
    ed: 'cf:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    prefixSha256: 'cf:1:AAAAAA'
  }

  testFromFulfillment(
    ex.emptySha256,
    new Buffer(0),
    'cf:1:AAAAAA',
    'cc:1:7:Yja3qFj7NS_VwwE7aJjPJos-uFCzStJlJLD4VsNy2XM:1'
  )

  testFromFulfillment(
    ex.prefixSha256,
    new Buffer(0),
    'cf:1:AAABBAAAAAA',
    'cc:1:7:Mp5A0CLrJOMAUMe0-qFb-_5U2C0X-iuwwfvumOT0go8:2'
  )

  testFromFulfillment(
    ex.ed,
    new Buffer('ff00ff00abab', 'hex'),
    'cf:1:Bv8A_wCrqwAEYCB2oVkgRKbk9REmW8pzpgTZCwUp0d9gK-MKGakldmDR9UCuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NQ',
    'cc:1:25:XkflBmyISKuevH8-850LuMrzN-HT1Ds9zKUEzaZ2Wk0:103'
  )

  function testFromFulfillment (subfulfillment, prefix, fulfillmentUri, conditionUri) {
    describe(conditionUri, function () {
      it('generates the correct fulfillment uri', function () {
        const f = new condition.PrefixSha256()
        f.setSubfulfillment(condition.fromFulfillmentUri(subfulfillment))
        f.setPrefix(prefix)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates the correct condition uri', function () {
        const f = new condition.PrefixSha256()
        f.setSubfulfillment(condition.fromFulfillmentUri(subfulfillment))
        f.setPrefix(prefix)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })
    })
  }
})
