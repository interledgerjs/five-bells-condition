'use strict'

const cc = require('../..')

if (process.env.GENERATE_TEST_SUITE === 'true') {
  const tests = []

  const actualValidateFulfillment = cc.validateFulfillment
  cc.validateFulfillment = (fulfillment, condition, message) => {
    const test = {
      fulfillment,
      condition
    }
    if (message) test.message = message.toString('base64')

    tests.push(test)

    try {
      const result = actualValidateFulfillment(fulfillment, condition, message)
      test.result = result
      return result
    } catch (err) {
      test.result = err.name
      throw err
    }
  }

  process.on('exit', () => {
    console.log(tests)
  })
}
