const expect = require('chai').expect
const sinon = require('sinon')
const Condition = require('..').Condition

describe('Condition', function () {
  describe('validate', function () {
    it('should return valid: true for a valid `sha256` condition', function () {
      const condition = {
        type: 'sha256',
        digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
      }

      const validationResult = Condition.validate(condition)

      expect(validationResult).to.be.an('object')
      expect(validationResult.valid).to.equal(true)
    })

    it('should return valid: false and validation errors for an invalid type', function () {
      const condition = {
        type: 'invalid',
        digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
          digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
        digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f65451c'
      }]
    }

    const validationResult = Condition.validate(condition)

    expect(validationResult).to.be.an('object')
    expect(validationResult.valid).to.equal(false)
    expect(validationResult.errors).to.be.an('array')
    expect(validationResult.errors).to.have.length.above(0)
  })

  describe('testFulfillment', function () {
    it('should return true for a valid fulfillment of a `sha256` condition', function () {
      const condition = {
        type: 'sha256',
        digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
        digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545d'
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
          digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
          digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
          digest: '50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c'
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
  })
})
