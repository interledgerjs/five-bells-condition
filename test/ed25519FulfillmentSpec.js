const assert = require('chai').assert
const crypto = require('crypto')
const condition = require('..')

describe('Ed25519Fulfillment', function () {
  testFromParams(
    {
      key: new Buffer(32).fill(0),
      message: new Buffer(0)
    },
    'cf:1:4:IDtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdopQI-JWzyv4slQYDnQ4qZjglaABGdP6NI3eFCS5A1qr0g-T8YBaHBfMfEBWWE4ziGqNXwNMqBk9CPcPuSqOr9T-AM',
    'cc:1:20:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik:98'
  )

  testFromParams(
    {
      key: new Buffer(32).fill(0xff),
      message: new Buffer('616263', 'hex')
    },
    'cf:1:4:IHahWSBEpuT1ESZbynOmBNkLBSnR32Ar4woZqSV2YNH1QK7Gq2qRIq_w99y5Zn_2ExNolHMrbnjCb1tnMQHiZ_4uK2X6TVPa1HihraZNUP0d_bfZSSDcPhpWSmR7HLo1YAE',
    'cc:1:20:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU:98'
  )

  testFromParams(
    {
      key: crypto.createHash('sha256').update('example').digest(),
      message: new Buffer(512).fill(0x21)
    },
    'cf:1:4:IEQpkwZQBKoeTEj03QFYGUwCNJvMZkzZbkAOommRio1RQJ9NvOCWyjlSjeLY7ZZU_ppsfV3PmTQfkMvKWLNN4vlQLRVKm1Q3hUKSG1vDHcHTSkJ5Y3LUfvyuro5NfOiT4Qc',
    'cc:1:20:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVE:98'
  )

  function testFromParams (params, fulfillmentUri, conditionUri) {
    describe('key ' + params.key.toString('hex'), function () {
      it('generates correct fulfillment uri', function () {
        const f = new condition.Ed25519Fulfillment()
        f.sign(params.message, params.key)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates correct condition uri', function () {
        const f = new condition.Ed25519Fulfillment()
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
        const f = new condition.Ed25519Fulfillment()
        f.sign(params.message, params.key)
        const generatedCondition = f.getCondition()
        const parsedCondition = condition.fromConditionUri(conditionUri)

        assert.deepEqual(generatedCondition, parsedCondition)
      })
    })
  }
})
