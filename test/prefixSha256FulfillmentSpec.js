'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('PrefixSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:1:AA',
    tinySha256: 'cf:1:1:AQA',
    edSha256_1: 'cf:1:10:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    prefixSha256: 'cf:1:4:AAEA'
  }

  testFromFulfillment(
    ex.emptySha256,
    new Buffer(0),
    'cf:1:4:AAEA',
    'cc:1:5:7NQijAwz6sx7532aTpkJaSNsIO9n3wVgEsJuisnFsF4:2'
  )

  testFromFulfillment(
    ex.prefixSha256,
    new Buffer(0),
    'cf:1:4:AAQAAQA',
    'cc:1:5:DGFIsZxWQY1feKU3cvISywI09Wii8paUlcyCuFgZnZU:3'
  )

  testFromFulfillment(
    ex.edSha256_1,
    new Buffer('ff00ff00abab', 'hex'),
    'cf:1:4:Bv8A_wCrqxAgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fVArsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQ',
    'cc:1:14:dzCmFAhWuhSio1KZLJ8001ABRadI-mwqdqsBVjhxwK8:73'
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
