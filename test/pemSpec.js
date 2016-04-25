'use strict'

const Pem = require('../src/util/pem')
const assert = require('chai').assert

describe('Pem', function () {
  describe('modulusToPem', function () {
    it('generates the correct PEM', function () {
      const modulus = new Buffer('cc9142d717b4a1bea8e6b613b50ddb5a0ee699fcbaefbd6c2ced6e0616e260f7e31067c74b430f64d2fa05cae01087e5a11267b6bff6dfb9c8c19602499e91849670ec9dabee56b6262e18ccd6ae613872c6f3dd17094f8ca292bd198e02ae68328fa34971787a435fb59d3b6babec95d93d63b1eeb934f40e66ff677048891457f3df03740ae35ceb33ea278929acd25374ec05271b82ea83904d3aa93fe3a40abab5fa4ebcec5d4b7615e105a89029aa80d0c824d7daded8821679f4f5c190e995303d42456bd4d8a7562d718ce1ad2c58920b3c283c56e78854a971561ed48de9930397a66ea18fcb72a9dc02ecdcd918a5d0603fd01921b42f98c20627bf', 'hex')

      const pem = Pem.modulusToPem(modulus)

      assert.equal(pem, '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAzJFC1xe0ob6o5rYTtQ3bWg7mmfy6771sLO1uBhbiYPfjEGfHS0MP\nZNL6BcrgEIfloRJntr/237nIwZYCSZ6RhJZw7J2r7la2Ji4YzNauYThyxvPdFwlP\njKKSvRmOAq5oMo+jSXF4ekNftZ07a6vsldk9Y7HuuTT0Dmb/Z3BIiRRX898DdArj\nXOsz6ieJKazSU3TsBScbguqDkE06qT/jpAq6tfpOvOxdS3YV4QWokCmqgNDIJNfa\n3tiCFnn09cGQ6ZUwPUJFa9TYp1YtcYzhrSxYkgs8KDxW54hUqXFWHtSN6ZMDl6Zu\noY/LcqncAuzc2Ril0GA/0BkhtC+YwgYnvwIDAQAB\n-----END RSA PUBLIC KEY-----\n')
    })
  })
})
