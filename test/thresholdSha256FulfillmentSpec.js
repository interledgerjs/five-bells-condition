'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('ThresholdSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:1:AA',
    tinySha256: 'cf:1:1:AQA',
    edSha256_1: 'cf:1:10:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE'
  }

  testFromFulfillments(
    [
      ex.emptySha256
    ],
    1,
    'cf:1:8:AQEBAgEAAA',
    'cc:1:9:vM9AH5sVJ-OTnSVZljFwlr4uhJ__YipcXbePy5YNCzs:8'
  )

  testFromFulfillments(
    [
      ex.edSha256_1,
      ex.tinySha256
    ],
    1,
    'cf:1:8:AQIBAwEBAAABACMQIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1Yg',
    'cc:1:19:EnS4cr9N9Um_oGTFkdK_Nzr7YqGAOfaMhu2gqLD39u0:145'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    1,
    'cf:1:8:AQIBAwEBAAABACMQIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1Yg',
    'cc:1:19:EnS4cr9N9Um_oGTFkdK_Nzr7YqGAOfaMhu2gqLD39u0:145'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.edSha256_1
    ],
    2,
    'cf:1:8:AgIBAwEBAAABYxAgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fVArsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQA',
    'cc:1:19:CVevdzZHieWsxiV1epSgQKzSQEh8LjTE35rJUP_HMlM:112'
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

  describe('calculateWorstCaseLength', function () {
    const calc = condition.ThresholdSha256Fulfillment.calculateWorstCaseLength
      .bind(condition.ThresholdSha256Fulfillment)

    testWith(3, [1, 4], [2, 3], 3)
    testWith(200, [115, 300], [52, 9001], 9001)
    testWith(200, [115, 142, 300], [52, 18, 9001], 9001)
    testWith(400, [162, 210, 143, 195, 43], [768, 514, 350, 382, 57], 1632)
    testWith(100, [15, 31, 12, 33, 8], [139, 134, 314, 133, 464], -Infinity)

    function testWith (threshold, weights, costs, expectedResult) {
      it(`when given threshold=${threshold} weights=${weights} costs=${costs} returns ${expectedResult}`, function () {
        const subconditions = []
        for (let i = 0; i < weights.length; i++) {
          subconditions.push({
            weight: weights[i],
            size: costs[i]
          })
        }
        subconditions.sort((a, b) => b.weight - a.weight)

        const worstCase = calc(threshold, subconditions)

        assert.equal(worstCase, expectedResult)
      })
    }
  })
})
