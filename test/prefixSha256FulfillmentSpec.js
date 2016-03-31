'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('PrefixSha256', function () {
  const ex = {
    emptySha256: 'cf:0:AA',
    tinySha256: 'cf:0:AQA',
    ed: 'cf:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    prefixSha256: 'cf:1:AAAAAA'
  }

  testFromFulfillment(
    ex.emptySha256,
    new Buffer(0),
    'cf:1:AAAAAA',
    'cc:1:7:VhqujFlBilDFqhnMFTTZJblEpv6y5GbYJ9snpD8oFtc:2'
  )

  testFromFulfillment(
    ex.prefixSha256,
    new Buffer(0),
    'cf:1:AAABAAAAAA',
    'cc:1:7:5N-jxaILtDFf-Eqc67MLQD2MAo7yWp5xq4or1QK8pA8:3'
  )

  testFromFulfillment(
    ex.ed,
    new Buffer('ff00ff00abab', 'hex'),
    'cf:1:Bv8A_wCrqwAEIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1',
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
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })
    })
  }
})
