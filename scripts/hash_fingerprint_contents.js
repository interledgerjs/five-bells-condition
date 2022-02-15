'use strict'

const crypto = require('crypto')
const base64url = require('../src/util/base64url')

const fingerprintContents = Buffer.from(process.argv[2], 'base64')

const fingerprint = crypto.createHash('sha256')
  .update(fingerprintContents)
  .digest()

console.log(base64url.encode(fingerprint))
console.log(fingerprint.toString('hex').toUpperCase())
