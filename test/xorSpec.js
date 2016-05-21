'use strict'

const assert = require('chai').assert

const xor = require('../src/util/xor')

describe('xor', function () {
  it('should return an xored buffer', function () {
    const buffer1 = new Buffer('2989ab24b9e79f729d27649f39b4109a30226b1a', 'hex')
    const buffer2 = new Buffer('2a96fb974403f406d57857424ee7c62a1c6d4723', 'hex')

    const xored = xor(buffer1, buffer2)

    assert.equal(xored.toString('hex'), '031f50b3fde46b74485f33dd7753d6b02c4f2c39')
  })

  it('should throw if the first parameter is a string', function () {
    assert.throws(() => xor('test', new Buffer(4)), 'Arguments must be buffers')
  })

  it('should throw if the buffers are different lengths first parameter is a string', function () {
    assert.throws(() => xor(new Buffer(3), new Buffer(4)), 'Buffers must be the same length')
  })
})
