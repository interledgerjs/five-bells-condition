'use strict'

const base64url = require('../src/util/base64url')

console.log(base64url.encode(Buffer.from(process.argv.slice(2).join(''), 'hex')))
