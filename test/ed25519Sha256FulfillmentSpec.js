const assert = require('chai').assert
const crypto = require('crypto')
const condition = require('..')

describe('Ed25519Sha256Fulfillment', function () {
  testFromParams(
    {
      key: new Buffer(32).fill(0),
      message: new Buffer(0)
    },
    'cf:1:10:IDtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdopQI-JWzyv4slQYDnQ4qZjglaABGdP6NI3eFCS5A1qr0g-T8YBaHBfMfEBWWE4ziGqNXwNMqBk9CPcPuSqOr9T-AM',
    'cc:1:10:d1wPecc4TXuP4VzcnzYTEpxZRCuWBOjuVppsiLew1KE:66'
  )

  testFromParams(
    {
      key: new Buffer(32).fill(0xff),
      message: new Buffer('616263', 'hex')
    },
    'cf:1:10:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    'cc:1:10:To4nTGObg1sgrKQkgH-MnZLY9cE_iWVyRhyE0gt5Z0g:66'
  )

  testFromParams(
    {
      key: crypto.createHash('sha256').update('example').digest(),
      message: new Buffer(512).fill(0x21)
    },
    'cf:1:10:IEQpkwZQBKoeTEj03QFYGUwCNJvMZkzZbkAOommRio1RQJ9NvOCWyjlSjeLY7ZZU_ppsfV3PmTQfkMvKWLNN4vlQLRVKm1Q3hUKSG1vDHcHTSkJ5Y3LUfvyuro5NfOiT4Qc',
    'cc:1:10:Q69RQ_AwluAfB04-gFoIJvC5EG6uKJQ0Lhbx-kJGsOY:66'
  )

  function testFromParams (params, fulfillmentUri, conditionUri) {
    describe('key ' + params.key.toString('hex'), function () {
      it('generates correct fulfillment uri', function () {
        const f = new condition.Ed25519Sha256Fulfillment()
        f.sign(params.message, params.key)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates correct condition uri', function () {
        const f = new condition.Ed25519Sha256Fulfillment()
        f.sign(params.message, params.key)
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })

      it('parsing fulfillment generates condition', function () {
        const f = condition.fromFulfillmentUri(fulfillmentUri)
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })

      it('parsed condition matches generated condition', function () {
        const f = new condition.Ed25519Sha256Fulfillment()
        f.sign(params.message, params.key)
        const generatedCondition = f.getCondition()
        const parsedCondition = condition.fromConditionUri(conditionUri)

        assert.deepEqual(generatedCondition, parsedCondition)
      })
    })
  }
})
