'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('ThresholdSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:1:AA',
    tinySha256: 'cf:1:1:AQA',
    edSha256_1: 'cf:1:8:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1AAADYWJjQK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE'
  }

  testFromFulfillments(
    [
      ex.emptySha256
    ],
    1,
    'cf:1:4:AQEBAQABAA',
    'cc:1:5:CaJYyo39mSX6quE5jv02oEOA_N9ndveslAIwhLdE7HA:39'
  )

  testFromFulfillments(
    [
      ex.edSha256_1,
      ex.tinySha256
    ],
    1,
    'cf:1:4:AQIBAQABAQAAAQAIIEByjlF5XW_Ipmc0--RYHX5PZkNBoIqBcqQApj2TvnnDRQ',
    'cc:1:d:y44E4RIulAHJnhddCBctahn7t6EQc_n4JDp2nJsWXZk:112'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    1,
    'cf:1:4:AQIBAQABAQAAAQAIIEByjlF5XW_Ipmc0--RYHX5PZkNBoIqBcqQApj2TvnnDRQ',
    'cc:1:d:y44E4RIulAHJnhddCBctahn7t6EQc_n4JDp2nJsWXZk:112'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    2,
    'cf:1:4:AgIBAQABAQABAQAIIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1AAADYWJjQK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    'cc:1:d:-a00tN0yMjvhEeP8laTb3RJgFbeSyJfPTNfLuiawIYQ:79'
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
