'use strict'

const assert = require('chai').assert
const condition = require('..')

require('crypto').randomBytes = function (len) {
  return new Buffer(len).fill(0)
}

describe('RsaSha256', function () {
  testFromParams(
    {
      key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA4e+LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdB\nU+Pu89ZmFoQ+DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl/cExIPlnL/f1bPue8gNdA\nxeDwR/PoX8DXWBV3am8/I8XcXnlxOaaILjgzakpfs2E3Yg/zZj264yhHKAGGL3Ly\n+HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04+V99eTgcv\n8s5MZutFIzlzh1J1ljnwJXv1fb1cRD+1FYzOCj02rce6AfM6C7bbsr+YnWBxEvI0\nTZk+d+VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQIDAQABAoIBAAF1UVmYhZpMQt1o\nGJqA19CjMUXZ37bK0rjqk4nV0JlhNTaMkMBg3T73qEsG6XugEwhuG9iNC1NbnXGB\nvVLIW5ie4inc7tSjuWelnrpx8y/RwRa3zPQ6AnMEcQCFNx6bbNzkAO1TLpvxfriX\niZN6y2IpPrriqr/YSILlbRpgPS1V6hLre0wewFyyX6/REtutApRiEe2oiklYvznz\n8Zf4wCvtrv6K1+r0Eeq6VgjcgGgi1xWOI8TXyCwWGAOQ9TKVOSw6/jpo6pELRWYS\npVwsR8U/0L4ZeyYm/w5AGwmQKrlI/uL9vauGKRg55Bj7DjzXOgcRuTuTFZSM/+w/\nz1XpdPECgYEA/ZJGAD61SplbvSsfmI3KxupBnT5c0vxdVpLpc6JXpeHJmnJZvIpN\ndssuTjJlD+LgTb03DSGmVWTpyvAS6L7Xx0OgB0YQbiQHjcLJpbrREv9XAohH1+Al\nW11Cx7ukKpA9tmPM76BBKInhZqfrG0ihfbBBG5i5PNdd97WstjQOdRUCgYEA5BmC\nwVcYdHfIvKj+AE0GNWOM1RGaeJisVF7BQOCBXxmjEUHSqjf+ddDsTODvrSnNTg6P\nLu56Q1fIhx1hY7kYLlnDZBcC192+AvM2QHw8rDJ851ZiruluujhXdZpjRnCO9Mqa\n4d53yXC/Z7G4VSyn15DDylIahyLRueILErr/cxUCgYBVPqdpzasEuSmuHqEwl/pj\nhL0qL5zlERIP2LPCvADbM1yjH24rhBMmrIeUojx3ar4dZE7tizJv4sz1/F9e/0lr\nI8DYsSU04cfoUGOZ44QF7vFBWK9OU3w7is64dsxpwrP8bPCoXieJiVDNQgY31eL0\nbhx1OpKLcZuVeu3lEvsJQQKBgQCAHqAmDtCqopl69oTtEFZ7aHYzO5cDQ+YP4cU0\ntqWUECdayxkUCS2BaZ9As1uMbR1nSaA9ITBFYSo+Uk9gnxeo+TxZnN849tECgS+o\n2t+NbTJhElGNo4pRSNI/OT+n0hNKBf8m/TlVSWIJUXaTSOjhmOuQWbuSygj5GrFT\njPts3QKBgQCnjsKTyZmtRPz0PeJniSsp22njYM7EuE69OtItGxq/N7SA/zxowo3z\nzcAXbOIsnmoLCKGoIB9Cw7wO5OWSkB3fkaT6zUHzxpxBGtlROWtLAsflX0amCp4f\n7CKh5blJ1yGJtNc+Q5qyUbyntoIzFGCibva+xz3UqhJt5Q4TlCy+5Q==\n-----END RSA PRIVATE KEY-----\n',
      message: new Buffer('aaa'),
      modulus: new Buffer('e1ef8b24d6f76b09c81ed7752aa262f044f04a874d43809d31cea612f99b0c97a8b4374153e3eef3d66616843e0e41c293264b71b6173db1cf0d6cd558c58657706fcf097f704c483e59cbfdfd5b3ee7bc80d740c5e0f047f3e85fc0d75815776a6f3f23c5dc5e797139a6882e38336a4a5fb36137620ff3663dbae328472801862f72f2f87b202b9c89add7cd5b0a076f7c53e35039f67ed17ec815e5b4305cc63197068d5e6e579ba6de5f4e3e57df5e4e072ff2ce4c66eb452339738752759639f0257bf57dbd5c443fb5158cce0a3d36adc7ba01f33a0bb6dbb2bf989d607112f2344d993e77e563c1d361dedf57da96ef2cfc685f002b638246a5b309b9', 'hex'),
      signature: new Buffer('48e8945efe007556d5bf4d5f249e4808f7307e29511d3262daef61d88098f9aa4a8bc0623a8c975738f65d6bf459d543f289d73cbc7af4ea3a33fbf3ec4440447911d72294091e561833628e49a772ed608de6c44595a91e3e17d6cf5ec3b2528d63d2add6463989b12eec577df6470960df6832a9d84c360d1c217ad64c8625bdb594fb0ada086cdecbbde580d424bf9746d2f0c312826dbbb00ad68b52c4cb7d47156ba35e3a981c973863792cc80d04a180210a52415865b64b3a61774b1d3975d78a98b0821ee55ca0f86305d42529e10eb015cefd402fb59b2abb8deee52a6f2447d2284603d219cd4e8cf9cffdd5498889c3780b59dd6a57ef7d732620', 'hex')
    },
    'cf:3:ggEA4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuYIBAEjolF7-AHVW1b9NXySeSAj3MH4pUR0yYtrvYdiAmPmqSovAYjqMl1c49l1r9FnVQ_KJ1zy8evTqOjP78-xEQER5EdcilAkeVhgzYo5Jp3LtYI3mxEWVqR4-F9bPXsOyUo1j0q3WRjmJsS7sV332Rwlg32gyqdhMNg0cIXrWTIYlvbWU-wraCGzey73lgNQkv5dG0vDDEoJtu7AK1otSxMt9RxVro146mByXOGN5LMgNBKGAIQpSQVhltks6YXdLHTl114qYsIIe5Vyg-GMF1CUp4Q6wFc79QC-1myq7je7lKm8kR9IoRgPSGc1OjPnP_dVJiInDeAtZ3WpX731zJiA',
    'cc:3:11:uKkFs6dhGZCwD51c69vVvHYSp25cRi9IlvXfFaxhMjo:518'
  )

  testFromParams(
    {
      key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAqTZmL9HMlSCCTGE5g0DXh8IP8Zy8HCAjb/dxUp87w1Yg3VvV\nMgLqtik2MF8n9DnIaeUEEi5ZSqcv1Lzp2ACWH3rG7RT/z+uj0Dv8j5S/uiuoJARm\nSnEqJWVYY7R4M7r68TjRZ6lqOV5SNMursNj8YoUqzAtKS4o0VsgKSdF9MPphpy7N\nb/RbcQlrTO14MBR/DpR2IUij5LaS++WhRayS+NewYHItqv6uy5PsFwiG9U6t43UX\nrJ0E2zjefSREg1BKR2qQM5cBrWdIuouLJ0K+mIJetJ2hBF6KuDPW6r1FoUSk76kt\nadpxWkamZvF2QkgD9n0Es3O5PeNxwGKRgma9/QIDAQABAoIBAB0X4VHvfIFXaY/A\nV6cdivEoiJ0+GYmsbOtfW/icsCXRtSzaETncDobrZwnCEpiHJtIuMhj+JxQS0sJ9\nCKe+0hDvhyxUI/eXyD6RUcdOB/j2cJ5gs0WxV1G+rwfVi6U5TNQUtMxh8IWUlgXF\nzutFI3+87bLPbiK2zHDvS/WNMz0sR+sSL4kx/oI1hztN+qi5lrpvpN48puWx8iyF\nGBD5rabYimzP7tNapqfUfhDm2tOwKsO/owAfz/g/+4fWIk5zb6AJ7b9KmR2hLawk\neh0mTOvMqmgBCAZ9/bK6xwgAdf8UBI6AnvIXh1pCveY5Qnm2o+FHkoHTWKll3Pks\n5agCnoECgYEA1rhSeeR2PaKVmmnMEj/MYxhKXVHb9S19IydehnTJl6T41z3bSDYQ\nAxwUM28RsG8d38jbjnTM2C5rvpIMXN8Re0AY97QZluCOlSDxR486jokk9MfVZie7\n64tA3xJOELw8uVJqGt4FtEwyHZ/kS6FRpS4U/piZ4fFBzgrSaEPx7JUCgYEAyb5g\nIR9QgMRF+zeHC3RpM2hgd+phY1NU4nXxDcYIXQIfV4OXoa3Jo1wAoee9IyqcEywV\nnH1FIX7o2NtVeHxm1pVS6xPLBEk0aYFhai34JXh5LAXJOpmc+6v77MlE/o+Pm5Xb\nzVPLb62cwUfvEgZDwtcMydJhSCbE78uDSHwnyckCgYEAqsPSzCA3LVOVeUW0x7q3\neQQDeG426amwwPl5gqN1BEZupPgL4kUkvORi6Hjn75Kfhq9+dbBMjY11oQ0UCfRa\nOdRDRxST2Vtj6hRV75xobJ2Dp60Z+XGWUYDhKcesEEE0Zgq2WgHDNZ33qXnVHZUB\nksWwar7Ae2Hc/Nm8drG6wHUCgYAZFc/0LmWfLUiaXSQwm2/9UWw1XPJxHEqAwjOQ\nB+DAV+Q3yIgRNX/ODUGS4DLXbZPsml2xkK4I5TPkyxkMm0NaSUT/L/3dcZDP0aOg\nRUkGt70xaSLFY5ZugMsZfUlT8dvkd7TWCiZQo6DLM7uZXSgN0Rmo+rzX8OIqAv83\nAyEbaQKBgBer6410OTi6+pTkoCaj9icDSweZ6223IkGGKTnsT4gwgB+BpdgjcfN1\nBV+BCy5/MbapE8j5ludDZJQvfu1ei6AAYXMmiqtesOZtGc+wzDbTsKak9G+c28Cq\n5IgzZTp9ISv9dD/cvihEvpvjYUpP5jWX97tJm3Me71n9tKiPzosB\n-----END RSA PRIVATE KEY-----',
      message: new Buffer('test'),
      modulus: new Buffer('a936662fd1cc9520824c61398340d787c20ff19cbc1c20236ff771529f3bc35620dd5bd53202eab62936305f27f439c869e504122e594aa72fd4bce9d800961f7ac6ed14ffcfeba3d03bfc8f94bfba2ba82404664a712a25655863b47833bafaf138d167a96a395e5234cbabb0d8fc62852acc0b4a4b8a3456c80a49d17d30fa61a72ecd6ff45b71096b4ced7830147f0e94762148a3e4b692fbe5a145ac92f8d7b060722daafeaecb93ec170886f54eade37517ac9d04db38de7d244483504a476a90339701ad6748ba8b8b2742be98825eb49da1045e8ab833d6eabd45a144a4efa92d69da715a46a666f176424803f67d04b373b93de371c062918266bdfd', 'hex'),
      signature: new Buffer('0baf5adf3281e861b2fac8fbec85c8c6259df88f6a3c4574866594fc3d71a9293f1f239213356a52ddd709101738d43d08046ca501a9ad08c057617ed7bb758c5b4d6152ace8b692be0a831681070f5783fbc8573ec15dfe46d0e845b79ab2a691ba1368eae1b9dfc6c38b89cbc7ba5fbe0d65c8b73ac60a046b2889480a592b208a797eec18338233587d9a666de077dcfb70abee79a4b5d7632e79f85c1d874cb997ec04344111b1536f6c78ab308ec4c8a6d4877f2b05b74c6869b98fc021be1ee8e083d8c1d0eb8a33db7a4b428b869098f3c1a4b1aab8879a8b7b0b847d9104420009b2d0e665a4a032534b32de638083a80076cbb344b6cb45402b4486', 'hex')
    },
    'cf:3:ggEAqTZmL9HMlSCCTGE5g0DXh8IP8Zy8HCAjb_dxUp87w1Yg3VvVMgLqtik2MF8n9DnIaeUEEi5ZSqcv1Lzp2ACWH3rG7RT_z-uj0Dv8j5S_uiuoJARmSnEqJWVYY7R4M7r68TjRZ6lqOV5SNMursNj8YoUqzAtKS4o0VsgKSdF9MPphpy7Nb_RbcQlrTO14MBR_DpR2IUij5LaS--WhRayS-NewYHItqv6uy5PsFwiG9U6t43UXrJ0E2zjefSREg1BKR2qQM5cBrWdIuouLJ0K-mIJetJ2hBF6KuDPW6r1FoUSk76ktadpxWkamZvF2QkgD9n0Es3O5PeNxwGKRgma9_YIBAAuvWt8ygehhsvrI--yFyMYlnfiPajxFdIZllPw9cakpPx8jkhM1alLd1wkQFzjUPQgEbKUBqa0IwFdhfte7dYxbTWFSrOi2kr4KgxaBBw9Xg_vIVz7BXf5G0OhFt5qyppG6E2jq4bnfxsOLicvHul--DWXItzrGCgRrKIlIClkrIIp5fuwYM4IzWH2aZm3gd9z7cKvueaS112MuefhcHYdMuZfsBDRBEbFTb2x4qzCOxMim1Id_KwW3TGhpuY_AIb4e6OCD2MHQ64oz23pLQouGkJjzwaSxqriHmot7C4R9kQRCAAmy0OZlpKAyU0sy3mOAg6gAdsuzRLbLRUArRIY',
    'cc:3:11:Mjmrcm06fOo-3WOEZu9YDSNfqmn0lj4iOsTVEurtCdI:518'
  )

  function testFromParams (params, fulfillmentUri, conditionUri) {
    describe('valid: ' + conditionUri, function () {
      it('generates the correct signature', function () {
        const f = new condition.RsaSha256()
        f.sign(params.message, params.key)

        assert.equal(f.signature.toString('hex'), params.signature.toString('hex'))
      })
      it('generates the correct fulfillment', function () {
        const f = new condition.RsaSha256()
        f.sign(params.message, params.key)
        const uri = f.serializeUri()

        assert.equal(uri, fulfillmentUri)
      })
      it('generates the correct condition', function () {
        const f = new condition.RsaSha256()
        f.sign(params.message, params.key)
        const uri = f.getConditionUri()

        assert.equal(uri, conditionUri)
      })
      it('validates the fulfillment', function () {
        const result = condition.validateFulfillment(fulfillmentUri, conditionUri, params.message)

        assert.equal(result, true)
      })
    })
  }
})
