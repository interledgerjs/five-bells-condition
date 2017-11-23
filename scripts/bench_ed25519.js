'use strict'

const crypto = require('crypto')
const ed25519 = require('ed25519')
const tweetnacl = require('tweetnacl')

const seed = crypto.randomBytes(32)
const message = Buffer.from('Hello World!', 'utf8')
const keypairEd25519 = ed25519.MakeKeypair(seed)
const sigEd25519 = ed25519.Sign(message, keypairEd25519)

const keypairTweetnacl = tweetnacl.sign.keyPair.fromSeed(seed)
const sigTweetnacl = tweetnacl.sign.detached(message, keypairTweetnacl.secretKey)

require('do-you-even-bench')([
  {
    name: 'ed25519-keypair',
    fn: () => {
      this.keypair = ed25519.MakeKeypair(seed)
    }
  },
  {
    name: 'tweetnacl-keypair',
    fn: () => {
      this.keypair = tweetnacl.sign.keyPair.fromSeed(seed)
    }
  },
  {
    name: 'ed25519-sign',
    fn: () => {
      ed25519.Sign(message, keypairEd25519)
    }
  },
  {
    name: 'tweetnacl-sign',
    fn: () => {
      tweetnacl.sign.detached(message, keypairTweetnacl.secretKey)
    }
  },
  {
    name: 'ed25519-verify',
    fn: () => {
      ed25519.Verify(message, sigEd25519, keypairEd25519.publicKey)
    }
  },
  {
    name: 'tweetnacl-verify',
    fn: () => {
      tweetnacl.sign.detached.verify(message, sigTweetnacl, keypairTweetnacl.publicKey)
    }
  }
])
