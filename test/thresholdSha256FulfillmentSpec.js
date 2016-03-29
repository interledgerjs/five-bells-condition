'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('ThresholdSha256Fulfillment', function () {
  const ex = {
    emptySha256: 'cf:1:0:AA',
    tinySha256: 'cf:1:0:AQA',
    ed: 'cf:1:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE'
  }

  testFromFulfillments(
    [
      ex.emptySha256
    ],
    1,
    'cf:1:2:AQEBAgAAAA',
    'cc:1:2:b:K1NEnoehHjSXJVTaBdNIzxCtMUd-Lrm6xfSVaL80_RA:8'
  )

  testFromFulfillments(
    [
      ex.ed,
      ex.tinySha256
    ],
    1,
    'cf:1:2:AQIBAwABAAABACQEICB2oVkgRKbk9REmW8pzpgTZCwUp0d9gK-MKGakldmDR9WI',
    'cc:1:2:2b:XYOwrhFlcbkhGmL3sVYu-DpZWLa-AutCS_6t6hQJlFE:146'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.ed
    ],
    1,
    'cf:1:2:AQIBAwABAAABACQEICB2oVkgRKbk9REmW8pzpgTZCwUp0d9gK-MKGakldmDR9WI',
    'cc:1:2:2b:XYOwrhFlcbkhGmL3sVYu-DpZWLa-AutCS_6t6hQJlFE:146'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.ed
    ],
    2,
    'cf:1:2:AgIBAwABAAABYwQgdqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fVArsarapEir_D33Llmf_YTE2iUcytueMJvW2cxAeJn_i4rZfpNU9rUeKGtpk1Q_R39t9lJINw-GlZKZHscujVgAQA',
    'cc:1:2:2b:PW9ih5SJDULR3PU7qA487g9pdxsaZrT_jwllFLqVHSw:112'
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
