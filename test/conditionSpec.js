'use strict'

const assert = require('chai').assert

const Condition = require('..').Condition

describe('Condition', function () {
  describe('fromUri', function () {
    it('should parse a condition', function () {
      const cond = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      assert.instanceOf(cond, Condition)
      assert.equal(cond.getTypeId(), 0)
      assert.equal(cond.getBitmask(), 3)
      assert.equal(cond.getHash().toString('hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      assert.equal(cond.getMaxFulfillmentLength(), 0)
    })

    it('rejects a condition with invalid prefix af:', function () {
      assert.throws(() => Condition.fromUri('ac:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with invalid prefix ce:', function () {
      assert.throws(() => Condition.fromUri('ca:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with invalid prefix cf;', function () {
      assert.throws(() => Condition.fromUri('cc;0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with invalid prefix cc:', function () {
      assert.throws(() => Condition.fromUri('cf:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with too many segments', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0:'))
    })

    it('rejects a condition with too few segments', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU'))
    })

    it.skip('rejects a condition with an invalid version', function () {
      assert.throws(() => Condition.fromUri('cc:9:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with base64 padding', function () {
      assert.throws(() => Condition.fromUri('cc:9:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=:0'))
    })

    // Input MUST be base64url, so this should fail
    it('rejects a condition with regular base64 characters', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition with invalid characters', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47D.Qpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 1', function () {
      assert.throws(() => Condition.fromUri(' cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 2', function () {
      assert.throws(() => Condition.fromUri('cc :0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 3', function () {
      assert.throws(() => Condition.fromUri('cc: 0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 4', function () {
      assert.throws(() => Condition.fromUri('cc:0 :3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 5', function () {
      assert.throws(() => Condition.fromUri('cc:0: 3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 6', function () {
      assert.throws(() => Condition.fromUri('cc:0:3 :47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 7', function () {
      assert.throws(() => Condition.fromUri('cc:0:3: 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 8', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47D EQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'))
    })

    it('rejects a condition containing a space 9', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU :0'))
    })

    it('rejects a condition containing a space 10', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU: 0'))
    })

    it('rejects a condition containing a space 11', function () {
      assert.throws(() => Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0 '))
    })

    it('should return a condition object that is passed in', function () {
      const cond = new Condition()

      const cond2 = Condition.fromUri(cond)

      assert.equal(cond2, cond)
    })

    it('should throw when given a Buffer', function () {
      assert.throws(() => Condition.fromUri(new Buffer('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0', 'utf8')),
        'Serialized condition must be a string')
    })
  })

  describe('fromBinary', function () {
    it('successfully parses the minimal condition', function () {
      const condition = Condition.fromBinary(new Buffer('0000010320e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550102', 'hex'))

      assert.instanceOf(condition, Condition)
      assert.equal(condition.getHash().toString('hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })

    it('rejects a condition with less than two bytes', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('00', 'hex')))
    })

    it('rejects a condition containing no fingerprint', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('0000', 'hex')))
    })

    it.skip('rejects a condition containing extra bytes', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('000000010000', 'hex')))
    })

    it('rejects a condition with non-canonical zero byte length prefix', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('000080', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a condition with non-canonical single byte length prefix', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('0000810100', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a condition with non-canonical two byte length prefix', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('000082000100', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a condition with too large of a length prefix', function () {
      assert.throws(() => Condition.fromBinary(new Buffer('00008700000000000000', 'hex')), 'Tried to read too large integer (requested: 7, max: 6)')
    })
  })

  describe('getHash', function () {
    it('should return the hash', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      const hash = condition.getHash()

      assert.equal(hash.toString('hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })

    it('should throw if no hash was defined', function () {
      const condition = new Condition()

      assert.throws(() => condition.getHash(), 'Hash not set')
    })
  })

  describe('setHash', function () {
    it('should set the hash', function () {
      const hash = new Buffer('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex')
      const condition = new Condition()

      condition.setHash(hash)

      assert.equal(condition.hash.toString('hex'), hash.toString('hex'))
    })

    it('should throw when given a string', function () {
      const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      const condition = new Condition()

      assert.throws(() => condition.setHash(hash), 'Hash must be a Buffer')
    })
  })

  describe('getMaxFulfillmentLength', function () {
    it('should return the fulfillment length', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      const length = condition.getMaxFulfillmentLength()

      assert.equal(length, 0)
    })

    it('should throw if no fulfillment length was defined', function () {
      const condition = new Condition()

      assert.throws(() => condition.getMaxFulfillmentLength(), 'Maximum fulfillment length not set')
    })
  })

  describe('setMaxFulfillmentLength', function () {
    it('should set the fulfillment length', function () {
      const condition = new Condition()

      condition.setMaxFulfillmentLength(42)

      assert.equal(condition.maxFulfillmentLength, 42)
    })

    it('should throw when given a string', function () {
      const condition = new Condition()

      assert.throws(() => condition.setMaxFulfillmentLength('42'), 'Fulfillment length must be an integer')
    })

    it('should throw when given a negative number', function () {
      const condition = new Condition()

      assert.throws(() => condition.setMaxFulfillmentLength(-42), 'Fulfillment length must be positive or zero')
    })
  })

  describe('validate', function () {
    it('should return true for a valid condition', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      const result = condition.validate()

      assert.isTrue(result)
    })

    it('should throw if the bitmask exceeds the safe bitmask', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      condition.bitmask = 0x100000000

      assert.throws(() => condition.validate(), 'Bitmask too large to be safely represented')
    })

    it('should throw if the bitmask is not fully supported', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      condition.bitmask = 0x5f

      assert.throws(() => condition.validate(), 'Condition requested unsupported feature suites')
    })

    it('should throw if the fulfillment size exceeds the local limit', function () {
      const condition = Condition.fromUri('cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')

      condition.maxFulfillmentLength = 0x100000000

      assert.throws(() => condition.validate(), 'Condition requested too large of a max fulfillment size')
    })
  })
})
