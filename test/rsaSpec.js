'use strict'

const assert = require('chai').assert
const Rsa = require('../src/crypto/rsa')
const getSaltHelper = require('./helpers/salt').getSaltHelper

describe('Rsa', function () {
  // Test vectors from RSA Security
  // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
  describe('with SHA-1', function () {
    beforeEach(function () {
      this.rsa = new Rsa({
        hashAlgorithm: 'sha1'
      })
    })

    testExample(require('./data/rsa/sha1.json'))
  })

  // Test vectors generated using OpenSSL
  // https://gist.github.com/justmoon/3566a1108685706f3e1a8e5e6028eb9d
  describe('with SHA-256', function () {
    beforeEach(function () {
      this.rsa = new Rsa({
        hashAlgorithm: 'sha256'
      })
    })

    testExample(require('./data/rsa/sha256.json'))
  })
})

function testExample (specs) {
  specs.forEach(function (spec, i) {
    const modulus = Buffer.from(spec.modulus, 'hex')

    spec.cases.forEach(function (caseSpec, j) {
      describe('Example ' + (i + 1) + '.' + (j + 1), function () {
        beforeEach(function () {
          this.modulus = Buffer.alloc(modulus.length)
          modulus.copy(this.modulus)
          this.message = Buffer.from(caseSpec.message, 'hex')
          this.salt = Buffer.from(caseSpec.salt, 'hex')
          this.signature = Buffer.from(caseSpec.signature, 'hex')
        })

        it('signs correctly', function () {
          const saltHelper = getSaltHelper(this.salt)
          const signature = this.rsa.sign(spec.privateKey, this.message)

          assert.equal(signature.toString('hex'), this.signature.toString('hex'))
          saltHelper.verify()
        })

        it('verifies correctly', function () {
          const valid = this.rsa.verify(this.modulus, this.message, this.signature)

          assert(valid, 'signature should be valid')
        })
      })
    })
  })
}
