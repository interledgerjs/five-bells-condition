'use strict'

const assert = require('chai').assert
const condition = require('..')

require('crypto').randomBytes = function (len) {
  return new Buffer(len).fill(0)
}

describe('RsaSha256Fulfillment', function () {
  testFromParams(
    {
      key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA4e+LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdB\nU+Pu89ZmFoQ+DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl/cExIPlnL/f1bPue8gNdA\nxeDwR/PoX8DXWBV3am8/I8XcXnlxOaaILjgzakpfs2E3Yg/zZj264yhHKAGGL3Ly\n+HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04+V99eTgcv\n8s5MZutFIzlzh1J1ljnwJXv1fb1cRD+1FYzOCj02rce6AfM6C7bbsr+YnWBxEvI0\nTZk+d+VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQIDAQABAoIBAAF1UVmYhZpMQt1o\nGJqA19CjMUXZ37bK0rjqk4nV0JlhNTaMkMBg3T73qEsG6XugEwhuG9iNC1NbnXGB\nvVLIW5ie4inc7tSjuWelnrpx8y/RwRa3zPQ6AnMEcQCFNx6bbNzkAO1TLpvxfriX\niZN6y2IpPrriqr/YSILlbRpgPS1V6hLre0wewFyyX6/REtutApRiEe2oiklYvznz\n8Zf4wCvtrv6K1+r0Eeq6VgjcgGgi1xWOI8TXyCwWGAOQ9TKVOSw6/jpo6pELRWYS\npVwsR8U/0L4ZeyYm/w5AGwmQKrlI/uL9vauGKRg55Bj7DjzXOgcRuTuTFZSM/+w/\nz1XpdPECgYEA/ZJGAD61SplbvSsfmI3KxupBnT5c0vxdVpLpc6JXpeHJmnJZvIpN\ndssuTjJlD+LgTb03DSGmVWTpyvAS6L7Xx0OgB0YQbiQHjcLJpbrREv9XAohH1+Al\nW11Cx7ukKpA9tmPM76BBKInhZqfrG0ihfbBBG5i5PNdd97WstjQOdRUCgYEA5BmC\nwVcYdHfIvKj+AE0GNWOM1RGaeJisVF7BQOCBXxmjEUHSqjf+ddDsTODvrSnNTg6P\nLu56Q1fIhx1hY7kYLlnDZBcC192+AvM2QHw8rDJ851ZiruluujhXdZpjRnCO9Mqa\n4d53yXC/Z7G4VSyn15DDylIahyLRueILErr/cxUCgYBVPqdpzasEuSmuHqEwl/pj\nhL0qL5zlERIP2LPCvADbM1yjH24rhBMmrIeUojx3ar4dZE7tizJv4sz1/F9e/0lr\nI8DYsSU04cfoUGOZ44QF7vFBWK9OU3w7is64dsxpwrP8bPCoXieJiVDNQgY31eL0\nbhx1OpKLcZuVeu3lEvsJQQKBgQCAHqAmDtCqopl69oTtEFZ7aHYzO5cDQ+YP4cU0\ntqWUECdayxkUCS2BaZ9As1uMbR1nSaA9ITBFYSo+Uk9gnxeo+TxZnN849tECgS+o\n2t+NbTJhElGNo4pRSNI/OT+n0hNKBf8m/TlVSWIJUXaTSOjhmOuQWbuSygj5GrFT\njPts3QKBgQCnjsKTyZmtRPz0PeJniSsp22njYM7EuE69OtItGxq/N7SA/zxowo3z\nzcAXbOIsnmoLCKGoIB9Cw7wO5OWSkB3fkaT6zUHzxpxBGtlROWtLAsflX0amCp4f\n7CKh5blJ1yGJtNc+Q5qyUbyntoIzFGCibva+xz3UqhJt5Q4TlCy+5Q==\n-----END RSA PRIVATE KEY-----\n',
      message: new Buffer('aaa'),
      modulus: new Buffer('e1ef8b24d6f76b09c81ed7752aa262f044f04a874d43809d31cea612f99b0c97a8b4374153e3eef3d66616843e0e41c293264b71b6173db1cf0d6cd558c58657706fcf097f704c483e59cbfdfd5b3ee7bc80d740c5e0f047f3e85fc0d75815776a6f3f23c5dc5e797139a6882e38336a4a5fb36137620ff3663dbae328472801862f72f2f87b202b9c89add7cd5b0a076f7c53e35039f67ed17ec815e5b4305cc63197068d5e6e579ba6de5f4e3e57df5e4e072ff2ce4c66eb452339738752759639f0257bf57dbd5c443fb5158cce0a3d36adc7ba01f33a0bb6dbb2bf989d607112f2344d993e77e563c1d361dedf57da96ef2cfc685f002b638246a5b309b9', 'hex'),
      signature: new Buffer('48e8945efe007556d5bf4d5f249e4808f7307e29511d3262daef61d88098f9aa4a8bc0623a8c975738f65d6bf459d543f289d73cbc7af4ea3a33fbf3ec4440447911d72294091e561833628e49a772ed608de6c44595a91e3e17d6cf5ec3b2528d63d2add6463989b12eec577df6470960df6832a9d84c360d1c217ad64c8625bdb594fb0ada086cdecbbde580d424bf9746d2f0c312826dbbb00ad68b52c4cb7d47156ba35e3a981c973863792cc80d04a180210a52415865b64b3a61774b1d3975d78a98b0821ee55ca0f86305d42529e10eb015cefd402fb59b2abb8deee52a6f2447d2284603d219cd4e8cf9cffdd5498889c3780b59dd6a57ef7d732620', 'hex')
    },
    'cf:1:2:gALh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5AAMDYWFhgAJI6JRe_gB1VtW_TV8knkgI9zB-KVEdMmLa72HYgJj5qkqLwGI6jJdXOPZda_RZ1UPyidc8vHr06joz-_PsREBEeRHXIpQJHlYYM2KOSady7WCN5sRFlakePhfWz17DslKNY9Kt1kY5ibEu7Fd99kcJYN9oMqnYTDYNHCF61kyGJb21lPsK2ghs3su95YDUJL-XRtLwwxKCbbuwCtaLUsTLfUcVa6NeOpgclzhjeSzIDQShgCEKUkFYZbZLOmF3Sx05ddeKmLCCHuVcoPhjBdQlKeEOsBXO_UAvtZsqu43u5SpvJEfSKEYD0hnNToz5z_3VSYiJw3gLWd1qV-99cyYg',
    'cc:1:2:xlMkEgW10lARWn8Fbogl1xsYaQk50Q55S89g9KP-DI8:522'
  )

  testInvalid('insufficient MAX_DYNAMIC_MESSAGE_LENGTH', 'cf:1:2:gALh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5AAADYWFhgAJI6JRe_gB1VtW_TV8knkgI9zB-KVEdMmLa72HYgJj5qkqLwGI6jJdXOPZda_RZ1UPyidc8vHr06joz-_PsREBEeRHXIpQJHlYYM2KOSady7WCN5sRFlakePhfWz17DslKNY9Kt1kY5ibEu7Fd99kcJYN9oMqnYTDYNHCF61kyGJb21lPsK2ghs3su95YDUJL-XRtLwwxKCbbuwCtaLUsTLfUcVa6NeOpgclzhjeSzIDQShgCEKUkFYZbZLOmF3Sx05ddeKmLCCHuVcoPhjBdQlKeEOsBXO_UAvtZsqu43u5SpvJEfSKEYD0hnNToz5z_3VSYiJw3gLWd1qV-99cyYg')

  function testFromParams (params, fulfillmentUri, conditionUri) {
    describe('valid: ' + conditionUri, function () {
      it('generates the correct signature', function () {
        const f = new condition.RsaSha256Fulfillment()
        f.setPublicModulus(params.modulus)
        f.setMaxDynamicMessageLength(3)
        f.setMessage(params.message)
        f.sign(params.key)

        assert.equal(f.signature.toString('hex'), params.signature.toString('hex'))
      })
      it('generates the correct fulfillment', function () {
        const f = new condition.RsaSha256Fulfillment()
        f.setPublicModulus(params.modulus)
        f.setMaxDynamicMessageLength(3)
        f.setMessage(params.message)
        f.sign(params.key)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })
      it('generates the correct condition', function () {
        const f = new condition.RsaSha256Fulfillment()
        f.setPublicModulus(params.modulus)
        f.setMaxDynamicMessageLength(3)
        f.setMessage(params.message)
        f.sign(params.key)
        const uri = f.getCondition().serializeUri()

        assert.equal(uri, conditionUri)
      })
      it('validates the fulfillment', function () {
        const result = condition.validateFulfillment(fulfillmentUri)

        assert.deepEqual(result, {
          valid: true,
          condition: conditionUri,
          error: null
        })
      })
    })
  }

  function testInvalid (name, fulfillmentUri) {
    describe(name, function () {
      it('does not validate', function () {
        const result = condition.validateFulfillment(fulfillmentUri)

        assert.equal(result.valid, false)
      })
    })
  }
})
