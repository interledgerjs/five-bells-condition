'use strict'

const Pss = require('../src/crypto/pss')
const assert = require('chai').assert
const getSaltHelper = require('./helpers/salt').getSaltHelper

describe('Pss', function () {
  // Test vectors from RSA Security
  // ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
  describe('with SHA-1', function () {
    beforeEach(function () {
      this.pss = new Pss({ hashAlgorithm: 'sha1' })
    })

    describe('encode', function () {
      it('generates the correct padded message', function () {
        const saltHelper = getSaltHelper(Buffer.from('e3b5d5d002c1bce50c2b65ef88a188d83bce7e61', 'hex'))
        const message = Buffer.from('859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc', 'hex')

        const encodedMessage = this.pss.encode(message, 1023)

        assert.equal(encodedMessage.toString('hex'), '66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc')
        saltHelper.verify()
      })
    })

    describe('verify', function () {
      it('considers a correctly padded message valid', function () {
        const encodedMessage = Buffer.from('66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24ba1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37ea4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8cfebc', 'hex')
        const message = Buffer.from('859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e6478ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c02712e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca74ff77a53cb729802f6ed4a5ffa8ba159890fc', 'hex')

        const valid = this.pss.verify(message, encodedMessage, 1023)

        assert.isTrue(valid)
      })
    })
  })

  // Test vectors generated using OpenSSL
  //
  // openssl genrsa -out priv.pem
  // openssl rsa -pubout -in priv.pem -out pub.pem
  // echo -n test123 > test.txt
  // openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt \
  //   rsa_pss_saltlen:-1 -sign priv.pem -out test.txt.sig test.txt
  describe('with SHA-256', function () {
    beforeEach(function () {
      this.pss = new Pss({ hashAlgorithm: 'sha256' })
    })

    describe('encode', function () {
      it('generates the correct padded message', function () {
        const saltHelper = getSaltHelper(Buffer.from('35f7e3d5b4968631f8730eee53bd407852b4695333b27c8345e554cd9b58b97d', 'hex'))
        const message = Buffer.from('cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0', 'hex')

        const encodedMessage = this.pss.encode(message, 1023)

        assert.equal(encodedMessage.toString('hex'), '1d4fcb12edfa4d39a827802069e0ba94f0d642273660e0fa7a2e530fea02f91c94c9abff776858e7edf111b0e59638fb2ef7e658b7555c52c2a4f6a2b422cec72aa006c041ad779acd3e3fa0c5f72db22e17a75dfa66a9073cda36f6bcba69f540257f98d237a52d4517169d2084735902fcd039beb04a50d6fa0c2e059ca4bc')
        saltHelper.verify()
      })
    })

    describe('verify', function () {
      it('considers a correctly padded message valid', function () {
        const encodedMessage = Buffer.from('1d4fcb12edfa4d39a827802069e0ba94f0d642273660e0fa7a2e530fea02f91c94c9abff776858e7edf111b0e59638fb2ef7e658b7555c52c2a4f6a2b422cec72aa006c041ad779acd3e3fa0c5f72db22e17a75dfa66a9073cda36f6bcba69f540257f98d237a52d4517169d2084735902fcd039beb04a50d6fa0c2e059ca4bc', 'hex')
        const message = Buffer.from('cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0', 'hex')

        const valid = this.pss.verify(message, encodedMessage, 1023)

        assert.isTrue(valid)
      })
    })
  })
})
