'use strict'

const assert = require('chai').assert
const cc = require('..')
const Writer = require('oer-utils/writer')
const Reader = require('oer-utils/reader')
require('./helpers/hooks')

describe('PreimageSha256', function () {
  beforeEach(function () {
    this.example = new cc.PreimageSha256()
  })

  describe('writeHashPayload', function () {
    it('should contain just the preimage', function () {
      const writer = new Writer()
      this.example.setPreimage(new Buffer('010203fdfeff', 'hex'))
      this.example.writeHashPayload(writer)

      assert.equal(writer.getBuffer().toString('hex'), '010203fdfeff')
    })

    it('should throw if no preimage was provided', function () {
      const writer = new Writer()

      assert.throws(() => this.example.writeHashPayload(writer),
        'Could not calculate hash, no preimage provided')
    })
  })

  describe('setPreimage', function () {
    it('should set the preimage property', function () {
      const buffer = new Buffer('010203fdfeff', 'hex')
      this.example.setPreimage(buffer)

      assert.equal(this.example.preimage, buffer)
    })

    it('should throw if the preimage is a string', function () {
      assert.throws(() => this.example.setPreimage('test'),
        'Preimage must be a buffer, was')
    })

    it('should throw if the preimage is an array', function () {
      assert.throws(() => this.example.setPreimage([0, 1, 2, 3]),
        'Preimage must be a buffer, was')
    })

    it('should throw if the preimage is a UInt8Array', function () {
      assert.throws(() => this.example.setPreimage(new Uint8Array([0, 1, 2, 3])),
        'Preimage must be a buffer, was')
    })
  })

  describe('parsePayload', function () {
    it('should set the preimage property', function () {
      const reader = new Reader(new Buffer('010203fdfeff', 'hex'))

      this.example.parsePayload(reader, 6)

      assert.equal(this.example.preimage.toString('hex'), '010203fdfeff')
    })

    it('should throw when passed too large of a length property', function () {
      const reader = new Reader(new Buffer('010203fdfeff', 'hex'))

      assert.throws(() => this.example.parsePayload(reader, 8),
        'Tried to read 8 bytes, but only 6 bytes available')
    })
  })

  describe('writePayload', function () {
    it('should contain just the preimage', function () {
      const writer = new Writer()
      this.example.setPreimage(new Buffer('010203fdfeff', 'hex'))
      this.example.writePayload(writer)

      assert.equal(writer.getBuffer().toString('hex'), '010203fdfeff')
    })

    it('should throw if no preimage was provided', function () {
      const writer = new Writer()

      assert.throws(() => this.example.writePayload(writer),
        'Preimage must be specified')
    })
  })

  testFromPreimage(
    '',
    'cf:0:',
    'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
  )

  testFromPreimage(
    '00',
    'cf:0:AA',
    'cc:0:3:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0:1'
  )

  testFromPreimage(
    'ff',
    'cf:0:_w',
    'cc:0:3:qBAK5qoZQNC2Y7sxzUZhQuu9vVGHExuS2TgYmHgy64k:1'
  )

  testFromPreimage(
    'feff',
    'cf:0:_v8',
    'cc:0:3:8ZdpKBDUV-KX_OnFZTsCWB_5mlCFI3DynX5f5H2dN-Y:2'
  )

  testFromPreimage(
    'fffe',
    'cf:0:__4',
    'cc:0:3:s9UQ7wQnXKjmmOWzy7Ds45Se-SUvDNyDnp7jR0CaIgk:2'
  )

  testFromPreimage(
    '00ff',
    'cf:0:AP8',
    'cc:0:3:But9amnuGeX733SQGNPSq_oEvL0TZdsxLrhtxxaTibg:2'
  )

  testFromPreimage(
    '0001',
    'cf:0:AAE',
    'cc:0:3:tBP0fRPuL-bIRbLuFBr4HehY307FSaWLeXC7lmRbyNI:2'
  )

  testFromPreimage(
    '616263',
    'cf:0:YWJj',
    'cc:0:3:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0:3'
  )

  testFromPreimage(
    'f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    'cf:0:8fLz9PX29_j5-vv8_f7_',
    'cc:0:3:ipyQ4jcC1AbAYiuzYDZ1YkAr4O1IxOe5XBKJdJ17nPA:15'
  )

  testFromPreimage(
    new Buffer(256).fill(0x00).toString('hex'),
    'cf:0:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'cc:0:3:U0HmsmRpeacOV2UwB6HzEBaUIeyb3Z8aVkj3Wt4AWvE:256'
  )

  testFromPreimage(
    new Buffer(256).fill(0xff).toString('hex'),
    'cf:0:_____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________w',
    'cc:0:3:PWh2oBRt6FdusjlahY3hIT0bksZbd53zozHP1aRYRUY:256'
  )

  testFromPreimage(
    new Buffer(Array.prototype.map.call(new Buffer(256), (v, i) => i % 256)).toString('hex'),
    'cf:0:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w',
    'cc:0:3:QK_y6dLYki5Hr9RkjmlnSXFYeF-9Hahw5xECZr-USIA:256'
  )

  testFromPreimage(
    new Buffer(Array.prototype.map.call(new Buffer(4096), (v, i) => i % 256)).toString('hex'),
    'cf:0:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8DBwsPExcbHyMnKy8zNzs_Q0dLT1NXW19jZ2tvc3d7f4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr_AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u_w8fLz9PX29_j5-vv8_f7_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8DBwsPExcbHyMnKy8zNzs_Q0dLT1NXW19jZ2tvc3d7f4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr_AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u_w8fLz9PX29_j5-vv8_f7_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8DBwsPExcbHyMnKy8zNzs_Q0dLT1NXW19jZ2tvc3d7f4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr_AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u_w8fLz9PX29_j5-vv8_f7_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8DBwsPExcbHyMnKy8zNzs_Q0dLT1NXW19jZ2tvc3d7f4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr_AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u_w8fLz9PX29_j5-vv8_f7_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-v8DBwsPExcbHyMnKy8zNzs_Q0dLT1NXW19jZ2tvc3d7f4OHi4-Tl5ufo6err7O3u7_Dx8vP09fb3-Pn6-_z9_v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr_AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3-Dh4uPk5ebn6Onq6-zt7u_w8fLz9PX29_j5-vv8_f7_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w',
    'cc:0:3:yPXQNB1U2VGnGxNubir8sU0R7YSJp64Sao_uDfbs8ZM:4096'
  )

  function testFromPreimage (preimageHex, fulfillmentUri, conditionUri) {
    const preimageLength = preimageHex.length / 2
    const preimageHexFormatted = preimageLength > 8
      ? preimageHex.slice(0, 16) + '... '
      : preimageLength >= 1 ? preimageHex + ' ' : ''

    describe('with preimage ' + preimageHexFormatted + '(length ' + preimageLength + ')', function () {
      beforeEach(function () {
        this.preimage = new Buffer(preimageHex, 'hex')
      })

      it('generates correct fulfillment', function () {
        const f = new cc.PreimageSha256()
        f.setPreimage(this.preimage)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })

      it('generates condition ' + conditionUri, function () {
        const f = new cc.PreimageSha256()
        f.setPreimage(this.preimage)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })

      it('parsing fulfillment generates condition', function () {
        const f = cc.fromFulfillmentUri(fulfillmentUri)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })

      it('parsed condition matches generated condition', function () {
        const f = new cc.PreimageSha256()
        f.setPreimage(this.preimage)
        const generatedCondition = f.getCondition()
        const parsedCondition = cc.fromConditionUri(conditionUri)

        assert.deepEqual(generatedCondition, parsedCondition)
      })

      it('validates the fulfillment', function () {
        const result = cc.validateFulfillment(fulfillmentUri, conditionUri)

        assert.equal(result, true)
      })
    })
  }
})
