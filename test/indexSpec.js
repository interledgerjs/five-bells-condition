'use strict'

const assert = require('chai').assert

const cc = require('..')

describe('five-bells-condition', function () {
  it('is an object', function () {
    assert.isObject(cc)
  })

  describe('validateCondition', function () {
    it('should return true when validating a valid condition', function () {
      const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'

      const result = cc.validateCondition(condition)

      assert.isTrue(result)
    })

    it('should throw when validating an invalid condition', function () {
      assert.throws(() => cc.validateCondition('cc:0:abc'))
    })
  })

  describe('validateFulfillment', function () {
    it('should return true when validating a valid fulfillment without message', function () {
      const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
      const fulfillment = 'cf:0:'
      const validationResult = cc.validateFulfillment(fulfillment, condition)

      assert.isTrue(validationResult)
    })

    it('should throw when condition and fulfillment do not match', function () {
      const condition = 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
      const fulfillment = 'cf:0:'

      assert.throws(() => cc.validateFulfillment(fulfillment, condition),
        'Fulfillment does not match condition')
    })

    it('should throw when message is not a buffer', function () {
      const condition = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
      const fulfillment = 'cf:0:'

      assert.throws(() => cc.validateFulfillment(fulfillment, condition, 'test'),
        'Message must be provided as a Buffer')
    })
  })

  describe('fulfillmentToCondition', function () {
    it('should turn a fulfillment into a condition', function () {
      const fulfillment = 'cf:0:'

      const condition = cc.fulfillmentToCondition(fulfillment)

      assert.equal(condition, 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0')
    })
  })
})
