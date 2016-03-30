'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('PrefixSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:0:AA',
    tinySha256: 'cf:1:0:AQA',
    ed: 'cf:1:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    prefixSha256: 'cf:1:1:AAAA'
  }

  testFromFulfillment(
    ex.emptySha256,
    new Buffer(0),
    'cf:1:1:AAAA',
    'cc:1:7:dnZSIsFJ4wlvL8mwczOioDg4-2HIeAGuzkJcxf1zC3o:2'
  )

  testFromFulfillment(
    ex.prefixSha256,
    new Buffer(0),
    'cf:1:1:AAEAAAA',
    'cc:1:7:e3L1o9UiNqIaTjJB90MvTk9VlL3aU_YAjjO08VOVAY8:3'
  )

  testFromFulfillment(
    ex.ed,
    new Buffer('ff00ff00abab', 'hex'),
    'cf:1:1:Bv8A_wCrqwQgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fVArsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQ',
    'cc:1:25:uFskYklOQ41h5M5D-EnyaKLGhpsQt5DXl5RQRDHC3is:105'
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
