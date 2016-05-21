'use strict'

const assert = require('chai').assert
const cc = require('..')

describe('Fulfillment', function () {
  const Fulfillment = cc.Fulfillment
  describe('fromUri', function () {
    it('successfully parses the minimal fulfillment', function () {
      const fulfillment = Fulfillment.fromUri('cf:0:')

      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), '')
    })

    it('successfully parses a basic fulfillment', function () {
      const fulfillment = Fulfillment.fromUri('cf:0:UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw')

      const expectedPreimage = new Buffer('UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=', 'base64')
      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it('successfully parses a fulfillment with base64url characters', function () {
      const fulfillment = Fulfillment.fromUri('cf:0:-u_6')

      const expectedPreimage = new Buffer('+u/6', 'base64')
      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it('rejects a fulfillment with invalid prefix af:', function () {
      assert.throws(() => Fulfillment.fromUri('af:0:'))
    })

    it('rejects a fulfillment with invalid prefix ce:', function () {
      assert.throws(() => Fulfillment.fromUri('ce:0:'))
    })

    it('rejects a fulfillment with invalid prefix cf;', function () {
      assert.throws(() => Fulfillment.fromUri('cf;0:'))
    })

    it('rejects a fulfillment with invalid prefix cc:', function () {
      assert.throws(() => Fulfillment.fromUri('cc:0:'))
    })

    it('rejects a fulfillment with too many segments', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0::'))
    })

    it('rejects a fulfillment with too few segments', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0'))
    })

    it('rejects a fulfillment with an invalid version', function () {
      assert.throws(() => Fulfillment.fromUri('cf:9:'))
    })

    it('rejects a fulfillment with base64 padding', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0:AAA='))
    })

    // Input MUST be base64url, so this should fail
    it('rejects a fulfillment with regular base64 characters', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0:+u/6'))
    })

    it('rejects a fulfillment with invalid characters', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0:Abc.'))
    })

    it('rejects a fulfillment containing a space 1', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0: AAAA'))
    })

    it('rejects a fulfillment containing a space 2', function () {
      assert.throws(() => Fulfillment.fromUri('cf:0:AAAA '))
    })

    it('rejects a fulfillment containing a space 3', function () {
      assert.throws(() => Fulfillment.fromUri(' cf:0:AAAA'))
    })

    it('returns anything that is already a fulfillment object', function () {
      const fulfillment = new Fulfillment()

      const parsed = Fulfillment.fromUri(fulfillment)

      assert.equal(fulfillment, parsed)
    })

    it('rejects a buffer', function () {
      assert.throws(() => Fulfillment.fromUri(new Buffer(3)))
    })
  })

  describe('fromBinary', function () {
    it('successfully parses the minimal fulfillment', function () {
      const fulfillment = Fulfillment.fromBinary(new Buffer('000000', 'hex'))

      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), '')
    })

    it('successfully parses a basic fulfillment', function () {
      const fulfillmentBinary = new Buffer('00002050d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c', 'hex')
      const fulfillment = Fulfillment.fromBinary(fulfillmentBinary)

      const expectedPreimage = new Buffer('UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=', 'base64')
      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it('successfully parses a fulfillment with base64url characters', function () {
      const fulfillment = Fulfillment.fromBinary(new Buffer('000003faeffa', 'hex'))

      const expectedPreimage = new Buffer('+u/6', 'base64')
      assert.equal(fulfillment.constructor.name, 'PreimageSha256')
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it('rejects a fulfillment with less than two bytes', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('00', 'hex')))
    })

    it('rejects a fulfillment containing no payload', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('0000', 'hex')))
    })

    it.skip('rejects a fulfillment containing extra bytes', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('00000000', 'hex')))
    })

    it('rejects a fulfillment with non-canonical zero byte length prefix', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('000080', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a fulfillment with non-canonical single byte length prefix', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('0000810100', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a fulfillment with non-canonical two byte length prefix', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('000082000100', 'hex')), 'Length prefix encoding is not canonical')
    })

    it('rejects a fulfillment with too large of a length prefix', function () {
      assert.throws(() => Fulfillment.fromBinary(new Buffer('00008700000000000000', 'hex')), 'Tried to read too large integer (requested: 7, max: 6)')
    })
  })

  describe('generateHash', function () {
    beforeEach(function () {
      this.fulfillment = new Fulfillment()
    })

    it('throws', function () {
      assert.throws(() => this.fulfillment.generateHash(), 'This method should be implemented by a subclass')
    })
  })

  describe('validate', function () {
    beforeEach(function () {
      this.fulfillment = new Fulfillment()
    })

    it('throws', function () {
      assert.throws(() => this.fulfillment.validate(), 'Not implemented')
    })
  })
})
