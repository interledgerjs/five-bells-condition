'use strict'

const assert = require('chai').assert
const cc = require('..')
require('./helpers/hooks')

describe('PrefixSha256', function () {
  const ex = {
    emptySha256: 'cf:0:',
    tinySha256: 'cf:0:AA',
    ed: 'cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB',
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
    new Buffer('abc', 'utf8'),
    'cf:1:A2FiYwAEYHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1rsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQ',
    'cc:1:25:KHqL2K2uisoMhxznwl-6pai-ENDk2x9Wru6Ls63O5Vs:100'
  )

  function testFromFulfillment (subfulfillment, prefix, fulfillmentUri, conditionUri) {
    describe(conditionUri, function () {
      it('generates the correct fulfillment uri', function () {
        const f = new cc.PrefixSha256()
        f.setSubfulfillment(cc.fromFulfillmentUri(subfulfillment))
        f.setPrefix(prefix)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
        assert.equal(f.getConditionUri(), conditionUri)
      })

      it('generates the correct condition uri', function () {
        const f = new cc.PrefixSha256()
        f.setSubcondition(cc.fromFulfillmentUri(subfulfillment).getCondition())
        f.setPrefix(prefix)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })

      it('validates the fulfillment', function () {
        const result = cc.validateFulfillment(fulfillmentUri, conditionUri)

        assert.equal(result, true)
      })
    })
  }
})
