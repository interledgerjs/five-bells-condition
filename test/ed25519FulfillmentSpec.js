'use strict'

const assert = require('chai').assert
const crypto = require('crypto')
const cc = require('..')
require('./helpers/hooks')

describe('Ed25519', function () {
  describe('setPublicKey', function () {
    it('should set the public key', function () {
      const publicKey = new Buffer(32).fill(0)
      const cond = new cc.Ed25519()

      cond.setPublicKey(publicKey)

      assert.equal(cond.publicKey.toString('hex'), publicKey.toString('hex'))
    })

    it('should throw if passed a string', function () {
      const publicKey = new Buffer(32).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setPublicKey(publicKey.toString('hex')), 'Public key must be a Buffer')
    })

    it('should throw if the public key is too short', function () {
      const publicKey = new Buffer(31).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setPublicKey(publicKey), 'Public key must be 32 bytes')
    })

    it('should throw if the public key is too long', function () {
      const publicKey = new Buffer(33).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setPublicKey(publicKey), 'Public key must be 32 bytes')
    })
  })

  describe('setSignature', function () {
    it('should set the signature', function () {
      const signature = new Buffer(64).fill(0)
      const cond = new cc.Ed25519()

      cond.setSignature(signature)

      assert.equal(cond.signature.toString('hex'), signature.toString('hex'))
    })

    it('should throw if passed a string', function () {
      const signature = new Buffer(64).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setSignature(signature.toString('hex')), 'Signature must be a Buffer')
    })

    it('should throw if the signature is too short', function () {
      const signature = new Buffer(63).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setSignature(signature), 'Signature must be 64 bytes')
    })

    it('should throw if the signature is too long', function () {
      const signature = new Buffer(65).fill(0)
      const cond = new cc.Ed25519()

      assert.throws(() => cond.setSignature(signature), 'Signature must be 64 bytes')
    })
  })

  describe('sign', function () {
    it('should sign a message and store the signature', function () {
      const cond = new cc.Ed25519()
      cond.sign(new Buffer(0), new Buffer(32).fill(0))

      assert.equal(cond.signature.toString('hex'), '8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803')
    })

    it('should throw if the message is a string', function () {
      const cond = new cc.Ed25519()
      assert.throws(() => cond.sign('test', new Buffer(32).fill(0)), 'Message must be a Buffer')
    })

    it('should throw if the private key is a string', function () {
      const cond = new cc.Ed25519()
      assert.throws(() => cond.sign(new Buffer(0), new Buffer(32).fill(0).toString('hex')),
        'Private key must be a Buffer')
    })

    it('should throw if the private key is the wrong length', function () {
      const cond = new cc.Ed25519()
      assert.throws(() => cond.sign(new Buffer(0), new Buffer(31).fill(0)), 'Private key must be 32 bytes')
    })
  })

  describe('generateHash', function () {
    it('should return the public Key as the hash', function () {
      const publicKey = new Buffer(32).fill(0)
      const cond = new cc.Ed25519()
      cond.setPublicKey(publicKey)

      const hash = cond.generateHash()

      assert.equal(hash.toString('hex'), publicKey.toString('hex'))
    })
  })

  describe('validate', function () {
    it('should accept a valid signature', function () {
      const cond = cc.fromFulfillmentUri('cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD')

      const result = cond.validate(new Buffer(0))

      assert.isTrue(result)
    })

    it('should throw if the signature is invalid', function () {
      const cond = cc.fromFulfillmentUri('cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD')

      cond.signature[4] |= 0x40

      assert.throws(() => cond.validate(new Buffer(0)), 'Invalid ed25519 signature')
    })

    it('should throw if the message is not a Buffer', function () {
      const cond = cc.fromFulfillmentUri('cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD')

      assert.throws(() => cond.validate(), 'Message must be a Buffer')
    })
  })

  testFromParams(
    {
      key: new Buffer(32).fill(0),
      message: new Buffer(0)
    },
    'cf:4:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2imPiVs8r-LJUGA50OKmY4JWgARnT-jSN3hQkuQNaq9IPk_GAWhwXzHxAVlhOM4hqjV8DTKgZPQj3D7kqjq_U_gD',
    'cc:4:20:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik:96'
  )

  testFromParams(
    {
      key: new Buffer(32).fill(0xff),
      message: new Buffer('616263', 'hex')
    },
    'cf:4:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fWuxqtqkSKv8PfcuWZ_9hMTaJRzK254wm9bZzEB4mf-Litl-k1T2tR4oa2mTVD9Hf232Ukg3D4aVkpkexy6NWAB',
    'cc:4:20:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU:96'
  )

  testFromParams(
    {
      key: crypto.createHash('sha256').update('example').digest(),
      message: new Buffer(512).fill(0x21)
    },
    'cf:4:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVGfTbzglso5Uo3i2O2WVP6abH1dz5k0H5DLylizTeL5UC0VSptUN4VCkhtbwx3B00pCeWNy1H78rq6OTXzok-EH',
    'cc:4:20:RCmTBlAEqh5MSPTdAVgZTAI0m8xmTNluQA6iaZGKjVE:96'
  )

  function testFromParams (params, fulfillmentUri, conditionUri) {
    describe('key ' + params.key.toString('hex'), function () {
      it('generates correct fulfillment uri', function () {
        const f = new cc.Ed25519()
        f.sign(params.message, params.key)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates correct condition uri', function () {
        const f = new cc.Ed25519()
        f.sign(params.message, params.key)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })

      it('parsing fulfillment generates condition', function () {
        const f = cc.fromFulfillmentUri(fulfillmentUri)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })

      it('parsed condition matches generated condition', function () {
        const f = new cc.Ed25519()
        f.sign(params.message, params.key)
        const generatedCondition = f.getCondition()
        const parsedCondition = cc.fromConditionUri(conditionUri)

        assert.deepEqual(generatedCondition, parsedCondition)
      })

      it('validates the fulfillment', function () {
        const result = cc.validateFulfillment(fulfillmentUri, conditionUri, params.message)

        assert.equal(result, true)
      })
    })
  }
})
