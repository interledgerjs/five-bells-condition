'use strict'

const assert = require('chai').assert
const cc = require('..')

describe('valid', function () {
  describe('01-preimage-empty.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":""}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('oCWAIOOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVgQEA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"preimage-sha-256","preimage":""}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('oAKAAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":""}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('oCWAIOOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVgQEA', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('oAKAAA')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('oAKAAA', 'base64').toString('hex'))
    })
  })
  describe('02-prefix-empty.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"prefix-sha-256","prefix":"","maxMessageLength":0,"subfulfillment":{"type":"preimage-sha-256","preimage":""}}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('MC6AAIEBAKInoCWAIOOwxEKY_BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVgQEA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('oSqAILsaxSYMAUG35Usm7CMwY3xVl7-BGVGsCedErSD_d-KHgQIEAIICB4A', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"prefix-sha-256","prefix":"","maxMessageLength":0,"subfulfillment":{"type":"preimage-sha-256","preimage":""}}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('oQuAAIEBAKIEoAKAAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"prefix-sha-256","prefix":"","maxMessageLength":0,"subfulfillment":{"type":"preimage-sha-256","preimage":""}}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('oSqAILsaxSYMAUG35Usm7CMwY3xVl7-BGVGsCedErSD_d-KHgQIEAIICB4A', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('oQuAAIEBAKIEoAKAAA')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('oQuAAIEBAKIEoAKAAA', 'base64').toString('hex'))
    })
  })
  describe('03-threshold-minimal.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('MCyAAQGhJ6AlgCDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VYEBAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('oiqAILS4QTbfSKcdc_SYXATGdnp3jstlunAjtFBoI77udjG5gQIEAIICB4A', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('ogigBKACgAChAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('oiqAILS4QTbfSKcdc_SYXATGdnp3jstlunAjtFBoI77udjG5gQIEAIICB4A', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('ogigBKACgAChAA')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('ogigBKACgAChAA', 'base64').toString('hex'))
    })
  })
  describe('04-threshold-1-of-2.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('MFOAAQGhTqAlgCB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaYEBDKAlgCDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VYEBAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('oiqAIFohjs56xLx3FX8Ey0vI381cnSJaVb0Kp2C8oqTxdz3GgQIIDIICB4A', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('oi-gBKACgAChJ6AlgCB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaYEBDA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('oiqAIFohjs56xLx3FX8Ey0vI381cnSJaVb0Kp2C8oqTxdz3GgQIIDIICB4A', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('oi-gBKACgAChJ6AlgCB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaYEBDA')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('oi-gBKACgAChJ6AlgCB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaYEBDA', 'base64').toString('hex'))
    })
  })
  describe('05-rsa-2048.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('MIIBBICCAQDh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('oyeAILMfqCBuTqflFTN7OzMIK4d2UYAQhe2E-02uske_aY1_gQMBAAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('o4ICCICCAQDh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5gYIBAEjolF7-AHVW1b9NXySeSAj3MH4pUR0yYtrvYdiAmPmqSovAYjqMl1c49l1r9FnVQ_KJ1zy8evTqOjP78-xEQER5EdcilAkeVhgzYo5Jp3LtYI3mxEWVqR4-F9bPXsOyUo1j0q3WRjmJsS7sV332Rwlg32gyqdhMNg0cIXrWTIYlvbWU-wraCGzey73lgNQkv5dG0vDDEoJtu7AK1otSxMt9RxVro146mByXOGN5LMgNBKGAIQpSQVhltks6YXdLHTl114qYsIIe5Vyg-GMF1CUp4Q6wFc79QC-1myq7je7lKm8kR9IoRgPSGc1OjPnP_dVJiInDeAtZ3WpX731zJiA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('oyeAILMfqCBuTqflFTN7OzMIK4d2UYAQhe2E-02uske_aY1_gQMBAAA', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('o4ICCICCAQDh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5gYIBAEjolF7-AHVW1b9NXySeSAj3MH4pUR0yYtrvYdiAmPmqSovAYjqMl1c49l1r9FnVQ_KJ1zy8evTqOjP78-xEQER5EdcilAkeVhgzYo5Jp3LtYI3mxEWVqR4-F9bPXsOyUo1j0q3WRjmJsS7sV332Rwlg32gyqdhMNg0cIXrWTIYlvbWU-wraCGzey73lgNQkv5dG0vDDEoJtu7AK1otSxMt9RxVro146mByXOGN5LMgNBKGAIQpSQVhltks6YXdLHTl114qYsIIe5Vyg-GMF1CUp4Q6wFc79QC-1myq7je7lKm8kR9IoRgPSGc1OjPnP_dVJiInDeAtZ3WpX731zJiA')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('o4ICCICCAQDh74sk1vdrCcge13UqomLwRPBKh01DgJ0xzqYS-ZsMl6i0N0FT4-7z1mYWhD4OQcKTJktxthc9sc8NbNVYxYZXcG_PCX9wTEg-Wcv9_Vs-57yA10DF4PBH8-hfwNdYFXdqbz8jxdxeeXE5poguODNqSl-zYTdiD_NmPbrjKEcoAYYvcvL4eyArnImt181bCgdvfFPjUDn2ftF-yBXltDBcxjGXBo1eblebpt5fTj5X315OBy_yzkxm60UjOXOHUnWWOfAle_V9vVxEP7UVjM4KPTatx7oB8zoLttuyv5idYHES8jRNmT535WPB02He31falu8s_GhfACtjgkalswm5gYIBAEjolF7-AHVW1b9NXySeSAj3MH4pUR0yYtrvYdiAmPmqSovAYjqMl1c49l1r9FnVQ_KJ1zy8evTqOjP78-xEQER5EdcilAkeVhgzYo5Jp3LtYI3mxEWVqR4-F9bPXsOyUo1j0q3WRjmJsS7sV332Rwlg32gyqdhMNg0cIXrWTIYlvbWU-wraCGzey73lgNQkv5dG0vDDEoJtu7AK1otSxMt9RxVro146mByXOGN5LMgNBKGAIQpSQVhltks6YXdLHTl114qYsIIe5Vyg-GMF1CUp4Q6wFc79QC-1myq7je7lKm8kR9IoRgPSGc1OjPnP_dVJiInDeAtZ3WpX731zJiA', 'base64').toString('hex'))
    })
  })
  describe('06-ed25519.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex'), Buffer.from('MCKAINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex'), Buffer.from('pCeAIHmSOauo_E_36r-8TETmnovf7ZkzJOEu1keSq-KJzx1fgQMCAAA', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex'), Buffer.from('pGSAINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1EagUDlVkMAw2CscpCG4syAboKKhId_Hrjl2XTYc-BlIkkBVV-4ghWQozusxh45cBz5tGvSW_XwWVu-JGVRQUOOehAL', 'base64').toString('hex'))
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('pCeAIHmSOauo_E_36r-8TETmnovf7ZkzJOEu1keSq-KJzx1fgQMCAAA', 'base64'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri('pGSAINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1EagUDlVkMAw2CscpCG4syAboKKhId_Hrjl2XTYc-BlIkkBVV-4ghWQozusxh45cBz5tGvSW_XwWVu-JGVRQUOOehAL')
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex'), Buffer.from('pGSAINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1EagUDlVkMAw2CscpCG4syAboKKhId_Hrjl2XTYc-BlIkkBVV-4ghWQozusxh45cBz5tGvSW_XwWVu-JGVRQUOOehAL', 'base64').toString('hex'))
    })
  })
})
