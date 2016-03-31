'use strict'

const assert = require('chai').assert
const condition = require('..')

describe('ThresholdSha256', function () {
  const ex = {
    emptySha256: 'cf:0:',
    tinySha256: 'cf:0:AA',
    ed: 'cf:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE'
  }

  testFromFulfillments(
    [
      ex.emptySha256
    ],
    1,
    'cf:2:AQEBAQEBAwAAAAA',
    'cc:2:b:x07W1xU1_oBcV9zUheOzspx6Beq8vgy0vYgBVifNV1Q:10'
  )

  // Having the same subfulfillment appear twice is allowed, but note
  // how it results in a different condition URI, that is why this
  // behavior is safe.
  testFromFulfillments(
    [
      ex.emptySha256,
      ex.emptySha256
    ],
    2,
    'cf:2:AQIBAgEBAwAAAAABAQMAAAAA',
    'cc:2:b:y93kXzLJ49Qdn3CeCe6Qtuzmdg9LhPHQIESn8H4ghE0:14'
  )

  testFromFulfillments(
    [
      ex.ed,
      ex.tinySha256
    ],
    1,
    'cf:2:AQEBAgEBBAAAAQAAAQEAJwAEASAgIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNEBYA',
    'cc:2:2b:d3O4epRCo_3rj17Bf3v8hp5ig7vq84ivPok07T9Rdl0:146'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.ed
    ],
    1,
    'cf:2:AQEBAgEBBAAAAQAAAQEAJwAEASAgIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNEBYA',
    'cc:2:2b:d3O4epRCo_3rj17Bf3v8hp5ig7vq84ivPok07T9Rdl0:146'
  )

  testFromFulfillments(
    [
      ex.tinySha256,
      ex.ed
    ],
    2,
    'cf:2:AQIBAgEBBAAAAQAAAQFjAARgIHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1AA',
    'cc:2:2b:AbeLZtZPtdSb6Hw488R_fpYjEjlV7RW2jFrp5Dr-WS0:111'
  )

  function testFromFulfillments (fulfillments, threshold, fulfillmentUri, conditionUri) {
    describe('with ' + fulfillments.length + ' subfulfillments', function () {
      it('generates the correct fulfillment uri', function () {
        const f = new condition.ThresholdSha256()
        f.setThreshold(threshold)
        for (let sub of fulfillments) {
          f.addSubfulfillment(condition.fromFulfillmentUri(sub))
        }
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates the correct condition uri', function () {
        const f = new condition.ThresholdSha256()
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
    const calc = condition.ThresholdSha256.calculateWorstCaseLength
      .bind(condition.ThresholdSha256)

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
