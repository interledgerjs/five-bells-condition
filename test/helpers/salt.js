'use strict'

const crypto = require('crypto')
const sinon = require('sinon')

exports.getSaltHelper = function (salt) {
  const stub = sinon.stub(crypto, 'randomBytes')
  stub.withArgs(salt.length).returns(salt)

  return { verify: () => {
    sinon.assert.calledOnce(stub)
    sinon.assert.calledWith(stub, salt.length)
    stub.restore()
  }}
}
