'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('ThresholdSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:1:AA',
    tinySha256: 'cf:1:1:AQA',
    edSha256_1: 'cf:1:10:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1AAADYWJjQK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE'
  }

  testFromFulfillments(
    [
      ex.emptySha256
    ],
    1,
    'cf:1:8:AQEBAQABAA',
    'cc:1:9:Atmus9zDi-5XDQwkSx41ABwBpWP04aXlsdc5Nrdjqss:39'
  )

  testFromFulfillments(
    [
      ex.edSha256_1,
      ex.tinySha256
    ],
    1,
    'cf:1:8:AQIBAQABAQAAAQAQIIwJDpTAx9JoRObgShxmqyyG3a9luI7sZMV2r8sWaIzxRQ',
    'cc:1:19:2Alprb_bzlblF72lV02fpBtJTanxN9WzMs_39To7gmA:112'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    1,
    'cf:1:8:AQIBAQABAQAAAQAQIIwJDpTAx9JoRObgShxmqyyG3a9luI7sZMV2r8sWaIzxRQ',
    'cc:1:19:2Alprb_bzlblF72lV02fpBtJTanxN9WzMs_39To7gmA:112'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    2,
    'cf:1:8:AgIBAQABAQABAQAQIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1AAADYWJjQK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    'cc:1:19:7yPwI9XYVJ_L2pksHMAEFRzsMyPgFEJO5FygnmOgw70:79'
  )

  function testFromFulfillments (fulfillments, threshold, fulfillmentUri, conditionUri) {
    describe('with ' + fulfillments.length + ' subfulfillments', function () {
      it('generates the correct fulfillment uri', function () {
        const f = new condition.ThresholdSha256Fulfillment()
        f.setThreshold(threshold)
        for (let sub of fulfillments) {
          f.addSubfulfillment(condition.fromFulfillmentUri(sub))
        }
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates the correct condition uri', function () {
        const f = new condition.ThresholdSha256Fulfillment()
        f.setThreshold(threshold)
        for (let sub of fulfillments) {
          f.addSubfulfillment(condition.fromFulfillmentUri(sub))
        }
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })
    })
  }
})
