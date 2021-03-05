'use strict'

const assert = require('chai').assert
const cc = require('..')

describe('Fulfillment', function () {
  const Fulfillment = cc.Fulfillment
  describe('fromUri', function () {
    it('successfully parses the minimal fulfillment', function () {
      const fulfillment = Fulfillment.fromUri('oAKAAA')

      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), '')
    })

    it('successfully parses a basic fulfillment', function () {
      const fulfillment = Fulfillment.fromUri('oCKAIFDYWOCYXsx_YEGKrwzFq1h_QsJXCohAlanozKzQ9lRc')

      const expectedPreimage = Buffer.from('UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=', 'base64')
      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it('successfully parses a fulfillment with base64 padding', function () {
      const fulfillment = Fulfillment.fromUri('oAKAAA==')

      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), '')
    })

    it('successfully parses a fulfillment with regular base64 characters', function () {
      const fulfillment = Fulfillment.fromUri('oCKAIFDYWOCYXsx/YEGKrwzFq1h/QsJXCohAlanozKzQ9lRc')

      const expectedPreimage = Buffer.from('UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=', 'base64')
      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it.skip('rejects a fulfillment with invalid characters', function () {
      assert.throws(() => Fulfillment.fromUri('oAKAAA.'))
    })

    it.skip('rejects a fulfillment containing a space 1', function () {
      assert.throws(() => Fulfillment.fromUri('oAK AAA'))
    })

    it.skip('rejects a fulfillment containing a space 2', function () {
      assert.throws(() => Fulfillment.fromUri('oAKAAA '))
    })

    it.skip('rejects a fulfillment containing a space 3', function () {
      assert.throws(() => Fulfillment.fromUri(' oAKAAA'))
    })

    it('returns anything that is already a fulfillment object', function () {
      const fulfillment = new Fulfillment()

      const parsed = Fulfillment.fromUri(fulfillment)

      assert.equal(fulfillment, parsed)
    })

    it('rejects a buffer', function () {
      assert.throws(() => Fulfillment.fromUri(Buffer.alloc(3)), 'Serialized fulfillment must be a string')
    })
  })

  describe('fromBinary', function () {
    it('successfully parses the minimal fulfillment', function () {
      const fulfillment = Fulfillment.fromBinary(Buffer.from('oAKAAA', 'base64'))

      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), '')
    })

    it.skip('successfully parses a basic fulfillment', function () {
      const fulfillmentBinary = Buffer.from('00002050d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c', 'hex')
      const fulfillment = Fulfillment.fromBinary(fulfillmentBinary)

      const expectedPreimage = Buffer.from('UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=', 'base64')
      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    it.skip('successfully parses a fulfillment with base64url characters', function () {
      const fulfillment = Fulfillment.fromBinary(Buffer.from('000003faeffa', 'hex'))

      const expectedPreimage = Buffer.from('+u/6', 'base64')
      assert.equal(fulfillment.constructor, cc.PreimageSha256)
      assert.equal(fulfillment.preimage.toString('hex'), expectedPreimage.toString('hex'))
    })

    // it('rejects a fulfillment with less than two bytes', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('00', 'hex')))
    // })
    //
    // it('rejects a fulfillment containing no payload', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('0000', 'hex')))
    // })
    //
    // it.skip('rejects a fulfillment containing extra bytes', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('00000000', 'hex')))
    // })
    //
    // it('rejects a fulfillment with non-canonical zero byte length prefix', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('000080', 'hex')), 'Length prefix encoding is not canonical')
    // })
    //
    // it('rejects a fulfillment with non-canonical single byte length prefix', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('0000810100', 'hex')), 'Length prefix encoding is not canonical')
    // })
    //
    // it('rejects a fulfillment with non-canonical two byte length prefix', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('000082000100', 'hex')), 'Length prefix encoding is not canonical')
    // })
    //
    // it('rejects a fulfillment with too large of a length prefix', function () {
    //   assert.throws(() => Fulfillment.fromBinary(Buffer.from('00008700000000000000', 'hex')), 'Tried to read too large integer (requested: 7, max: 6)')
    // })
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
