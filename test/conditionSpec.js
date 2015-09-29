const expect = require('chai').expect
const sinon = require('sinon')
const Condition = require('..').Condition

describe('Condition', function () {
  describe('validate', function () {
    it('should return valid: true for a valid `sha256` condition', function () {
      const condition = {
        type: 'sha256',
        digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(true)
    })

    it('should return valid: false and validation errors for an invalid type', function () {
      const condition = {
        type: 'invalid',
        digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(false)
      expect(validationResult.errors).to.be.an('array')
      expect(validationResult.errors).to.have.length.above(0)
    })

    it('should return valid: true for a valid `before` condition', function () {
      const condition = {
        type: 'before',
        date: '2015-09-13T05:43:23.508Z'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(true)
    })

    it('should return valid: false for an invalid `before` condition', function () {
      const condition = {
        type: 'before',
        date: '2015-09_13T05:43:23.508Z'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(false)
      expect(validationResult.errors).to.be.an('array')
      expect(validationResult.errors).to.have.length.above(0)
    })

    it('should return valid: false for an invalid `before` condition #2', function () {
      const condition = {
        type: 'before',
        date: '2015-09-33T05:43:23.508Z'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(false)
      expect(validationResult.errors).to.be.an('array')
      expect(validationResult.errors).to.have.length.above(0)
    })

    it('should return valid: true for a valid `and` condition', function () {
      const condition = {
        type: 'and',
        subconditions: [{
          type: 'sha256',
          digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
        }]
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(true)
    })
  })

  it('should return valid: false for an `and` condition with an invalid subcondition', function () {
    const condition = {
      type: 'and',
      subconditions: [{
        type: 'sha256',
        digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F65451C'
      }]
    }

    const validationResult = Condition.validate(condition)

    expect(validationResult).to.be.an('object')
    expect(validationResult.valid).to.equal(false)
    expect(validationResult.errors).to.be.an('array')
    expect(validationResult.errors).to.have.length.above(0)
  })

  it('should return valid: true for a valid `ed25519-sha512` condition', function () {
    const condition = {
      type: 'ed25519-sha512',
      message_hash: 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw==',
      signer: 'http://ledger.example',
      public_key: 'Lvf3YtnHLMER+VHT0aaeEJF+7WQcvp4iKZAdvMVto7c='
    }

    const validationResult = Condition.validate(condition)
    expect(validationResult).to.be.an('object')
    expect(validationResult.valid).to.equal(true)
  })

  it('should return valid: false for an invalid `ed25519-sha512` message_hash', function () {
    const condition = {
      type: 'ed25519-sha512',
      signer: 'http://ledger.example',
      public_key: 'Lvf3YtnHLMER+VHT0aaeEJF+7WQcvp4iKZAdvMVto7c='
    }

    const validationResult = Condition.validate(condition)
    expect(validationResult).to.be.an('object')
    expect(validationResult.valid).to.equal(false)
  })

  describe('testFulfillment', function () {
    it('should return true for a valid fulfillment of a `sha256` condition', function () {
      const condition = {
        type: 'sha256',
        digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
      }
      const fulfillment = {
        type: 'sha256',
        message: 'example'
      }

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(true)
    })

    it('should return false for an invalid fulfillment of a `sha256` condition', function () {
      const condition = {
        type: 'sha256',
        digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545d'
      }
      const fulfillment = {
        type: 'sha256',
        message: 'example'
      }

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(false)
    })

    it('should return true for a `before` condition if the target date has not been reached', function () {
      const condition = {
        type: 'before',
        date: '2015-09-13T05:43:23.508Z'
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:20.000Z')))

      const result = Condition.testFulfillment(condition)

      expect(result).to.equal(true)

      clock.restore()
    })

    it('should return false for a `before` condition if the target date has been exactly reached', function () {
      const condition = {
        type: 'before',
        date: '2015-09-13T05:43:23.508Z'
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:23.508Z')))

      const result = Condition.testFulfillment(condition)

      expect(result).to.equal(false)

      clock.restore()
    })

    it('should return false for a `before` condition if the target date is in the past', function () {
      const condition = {
        type: 'before',
        date: '2015-09-13T05:43:23.508Z'
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:24.000Z')))

      const result = Condition.testFulfillment(condition)

      expect(result).to.equal(false)

      clock.restore()
    })

    it('should return true for an `and` condition with two valid subconditions', function () {
      const condition = {
        type: 'and',
        subconditions: [{
          type: 'before',
          date: '2015-09-13T05:43:23.508Z'
        }, {
          type: 'sha256',
          digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
        }]
      }

      const fulfillment = {
        type: 'and',
        subfulfillments: [{}, {
          type: 'sha256',
          message: 'example'
        }]
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:20.000Z')))

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(true)

      clock.restore()
    })

    it('should return true for an `and` condition with one invalid subcondition', function () {
      const condition = {
        type: 'and',
        subconditions: [{
          type: 'before',
          date: '2015-09-13T05:43:23.508Z'
        }, {
          type: 'sha256',
          digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
        }]
      }

      const fulfillment = {
        type: 'and',
        subfulfillments: [{}, {
          type: 'sha256',
          message: 'example1'
        }]
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:20.000Z')))

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(false)

      clock.restore()
    })

    it('should return true for an `and` condition with two invalid subconditions', function () {
      const condition = {
        type: 'and',
        subconditions: [{
          type: 'before',
          date: '2015-09-13T05:43:13.508Z'
        }, {
          type: 'sha256',
          digest: '50D858E0985ECC7F60418AAF0CC5AB587F42C2570A884095A9E8CCACD0F6545C'
        }]
      }

      const fulfillment = {
        type: 'and',
        subfulfillments: [{}, {
          type: 'sha256',
          message: 'example1'
        }]
      }

      const clock = sinon.useFakeTimers(Number(new Date('2015-09-13T05:43:20.000Z')))

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(false)

      clock.restore()
    })

    it('should return true for a valid fulfillment of a `ed25519-sha512` condition', function () {
      const condition = {
        type: 'ed25519-sha512',
        message_hash: 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw==',
        signer: 'http://ledger.example',
        public_key: 'Lvf3YtnHLMER+VHT0aaeEJF+7WQcvp4iKZAdvMVto7c='
      }
      const fulfillment = {
        type: 'ed25519-sha512',
        signature: 'sd0RahwuJJgeNfg8HvWHtYf4uqNgCOqIbseERacqs8G0kXNQQnhfV6gWAnMb+0RIlY3e0mqbrQiUwbRYJvRBAw=='
      }

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(true)
    })

    it('should return false for an invalid fulfillment of a `ed25519-sha512` condition', function () {
      const condition = {
        type: 'ed25519-sha512',
        message_hash: 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw==',
        signer: 'http://ledger.example',
        public_key: 'Lvf3YtnHLMER+VHT0aaeEJF+7WQcvp4iKZAdvMVto7c='
      }
      const fulfillment = {
        type: 'ed25519-sha512',
        signature: 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw=='
      }

      const result = Condition.testFulfillment(condition, fulfillment)

      expect(result).to.equal(false)
    })
  })
})
