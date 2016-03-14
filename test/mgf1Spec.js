'use strict'

const Mgf1 = require('../src/crypto/mgf1')
const assert = require('chai').assert

describe('Mgf1', function () {
  describe('with sha-1', function () {
    beforeEach(function () {
      this.mgf1 = new Mgf1({ hashAlgorithm: 'sha1' })
    })

    it('generates the correct padding', function () {
      const seed = new Buffer('f39b0bb49750b5a7e6bddad09a52bea021c490b6', 'hex')

      const padding = this.mgf1.generate(seed, 120)

      assert.equal(padding.toString('hex'), '104376726cdea00e7751fb58398a36e1632bc917560c4b46a407a43b8e334dd165f1acc859213216442b7fb2a8a7265de802be8edc34eb1076168cdd90923d2990984611735347b12cd483789b932f5bfc26ff42081f7066404be7223a56106d4d290bcea621b55c71662f7035d88a9233f016d40e438a14')
    })
  })
})
