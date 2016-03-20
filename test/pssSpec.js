'use strict'

const Pss = require('../src/crypto/pss')
const assert = require('chai').assert

describe('Pss', function () {
  describe('sha-1', function () {
    beforeEach(function () {
      this.pss = new Pss({ hashAlgorithm: 'sha1' })
    })

    describe('encode', function () {
      it('generates the correct padded message', function () {
        this.pss.forceSalt = new Buffer('e3b5d5d002c1bce50c2b65ef88a188d83bce7e61', 'hex')
        const message = new Buffer('859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc', 'hex')

        const encodedMessage = this.pss.encode(message, 1023)

        assert.equal(encodedMessage.toString('hex'), '66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc')
      })
    })

    describe('verify', function () {
      it('considers a correctly padded message valid', function () {
        const encodedMessage = new Buffer('66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc', 'hex')
        const message = new Buffer('859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc', 'hex')

        const valid = this.pss.verify(message, encodedMessage, 1023)

        assert.isTrue(valid)
      })
    })
  })
})
