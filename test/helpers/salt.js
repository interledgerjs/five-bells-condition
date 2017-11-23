'use strict'

const crypto = require('crypto')
const sinon = require('sinon')

if (process.browser) {
  // In the browser tests
  exports.getSaltHelper = function (salt) {
    const stub = sinon.stub(global.crypto, 'getRandomValues').callsFake((arr) => {
      if (arr.length !== salt.byteLength) {
        // throw new Error('Unexpected call to getRandomValues with length ' +
        //   arr.length + ', expected: ' + salt.byteLength)
        arr[arr.length - 1] = 1
      } else {
        salt.copy(arr)
      }
    })

    return { verify: () => {
      sinon.assert.called(stub)
      stub.restore()
    }}
  }
} else {
  // In the Node.js tests
  exports.getSaltHelper = function (salt) {
    const stub = sinon.stub(crypto, 'randomBytes')
    stub.withArgs(salt.length).returns(salt)

    return { verify: () => {
      sinon.assert.calledOnce(stub)
      sinon.assert.calledWith(stub, salt.length)
      stub.restore()
    }}
  }
}
