'use strict'

const assert = require('chai').assert
const cc = require('..')

describe('valid', function () {
  describe('0001_preimage-sha-256_empty.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":""}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"preimage-sha-256","preimage":""}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A0028000')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":""}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?fpt=preimage-sha-256&cost=0')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A0028000', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A0028000')
    })
  })
  describe('0002_prefix-sha-256_empty.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"prefix-sha-256","maxMessageLength":0,"prefix":"","subfulfillment":{"type":"preimage-sha-256","preimage":""}}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '302E8000810100A227A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A12A8020BB1AC5260C0141B7E54B26EC2330637C5597BF811951AC09E744AD20FF77E2878102040082020780')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"prefix-sha-256","maxMessageLength":0,"prefix":"","subfulfillment":{"type":"preimage-sha-256","preimage":""}}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A10B8000810100A204A0028000')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"prefix-sha-256","maxMessageLength":0,"prefix":"","subfulfillment":{"type":"preimage-sha-256","preimage":""}}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A12A8020BB1AC5260C0141B7E54B26EC2330637C5597BF811951AC09E744AD20FF77E2878102040082020780', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uxrFJgwBQbflSybsIzBjfFWXv4EZUawJ50StIP934oc?fpt=prefix-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A10B8000810100A204A0028000', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A10B8000810100A204A0028000')
    })
  })
  describe('0003_threshold-sha-256_minimal.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '302C800101A127A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22A8020B4B84136DF48A71D73F4985C04C6767A778ECB65BA7023B4506823BEEE7631B98102040082020780')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A208A004A0028000A100')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":""}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22A8020B4B84136DF48A71D73F4985C04C6767A778ECB65BA7023B4506823BEEE7631B98102040082020780', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;tLhBNt9Ipx1z9JhcBMZ2eneOy2W6cCO0UGgjvu52Mbk?fpt=threshold-sha-256&cost=1024&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A208A004A0028000A100', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A208A004A0028000A100')
    })
  })
  describe('0004_preimage-sha-256_small.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '48656C6C6F20576F726C6421')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A00E800C48656C6C6F20576F726C6421')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk?fpt=preimage-sha-256&cost=12')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A00E800C48656C6C6F20576F726C6421', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A00E800C48656C6C6F20576F726C6421')
    })
  })
  describe('0005_rsa-sha-256_2048.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '3082010480820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B9')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;sx-oIG5Op-UVM3s7Mwgrh3ZRgBCF7YT7Ta6yR79pjX8?fpt=rsa-sha-256&cost=65536')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620')
    })
  })
  describe('0006_ed25519-sha-256_empty-message.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '30228020D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A4278020799239ABA8FC4FF7EABFBC4C44E69E8BDFED993324E12ED64792ABE289CF1D5F8103020000')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A4648020D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A8140E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"ed25519-sha-256","publicKey":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","signature":"5VZDAMNgrHKQhuLMgG6CioSHfx645dl02HPgZSJJAVVfuIIVkKM7rMYeOXAc-bRr0lv18FlbviRlUUFDjnoQCw"}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A4278020799239ABA8FC4FF7EABFBC4C44E69E8BDFED993324E12ED64792ABE289CF1D5F8103020000', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A4648020D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A8140E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A4648020D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A8140E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B')
    })
  })
  describe('0007_threshold-sha-256_1-of-2.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '3053800101A14EA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22A80205A218ECE7AC4BC77157F04CB4BC8DFCD5C9D225A55BD0AA760BCA2A4F1773DC68102080C82020780')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22A80205A218ECE7AC4BC77157F04CB4BC8DFCD5C9D225A55BD0AA760BCA2A4F1773DC68102080C82020780', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;WiGOznrEvHcVfwTLS8jfzVydIlpVvQqnYLyipPF3PcY?fpt=threshold-sha-256&cost=2060&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })
  })
  describe('0008_threshold-sha-256_rsa-and-preimage.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '3055800102A150A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22B802098BE9D5CBD8D8EADA8E3BD5BF7DFA44C0C8A4E8E649B4AA5D48FC6F4B0DC1038810301080C82020490')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A2820222A082021CA00E800C48656C6C6F20576F726C6421A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620A100')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":2,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22B802098BE9D5CBD8D8EADA8E3BD5BF7DFA44C0C8A4E8E649B4AA5D48FC6F4B0DC1038810301080C82020490', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;mL6dXL2Njq2o471b99-kTAyKTo5km0ql1I_G9LDcEDg?fpt=threshold-sha-256&cost=67596&subtypes=preimage-sha-256,rsa-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A2820222A082021CA00E800C48656C6C6F20576F726C6421A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620A100', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A2820222A082021CA00E800C48656C6C6F20576F726C6421A382020880820100E1EF8B24D6F76B09C81ED7752AA262F044F04A874D43809D31CEA612F99B0C97A8B4374153E3EEF3D66616843E0E41C293264B71B6173DB1CF0D6CD558C58657706FCF097F704C483E59CBFDFD5B3EE7BC80D740C5E0F047F3E85FC0D75815776A6F3F23C5DC5E797139A6882E38336A4A5FB36137620FF3663DBAE328472801862F72F2F87B202B9C89ADD7CD5B0A076F7C53E35039F67ED17EC815E5B4305CC63197068D5E6E579BA6DE5F4E3E57DF5E4E072FF2CE4C66EB452339738752759639F0257BF57DBD5C443FB5158CCE0A3D36ADC7BA01F33A0BB6DBB2BF989D607112F2344D993E77E563C1D361DEDF57DA96EF2CFC685F002B638246A5B309B98182010048E8945EFE007556D5BF4D5F249E4808F7307E29511D3262DAEF61D88098F9AA4A8BC0623A8C975738F65D6BF459D543F289D73CBC7AF4EA3A33FBF3EC4440447911D72294091E561833628E49A772ED608DE6C44595A91E3E17D6CF5EC3B2528D63D2ADD6463989B12EEC577DF6470960DF6832A9D84C360D1C217AD64C8625BDB594FB0ADA086CDECBBDE580D424BF9746D2F0C312826DBBB00AD68B52C4CB7D47156BA35E3A981C973863792CC80D04A180210A52415865B64B3A61774B1D3975D78A98B0821EE55CA0F86305D42529E10EB015CEFD402FB59B2ABB8DEEE52A6F2447D2284603D219CD4E8CF9CFFDD5498889C3780B59DD6A57EF7D732620A100')
    })
  })
  describe('0009_threshold-sha-256_two-levels.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '305A800101A155A22A80205A218ECE7AC4BC77157F04CB4BC8DFCD5C9D225A55BD0AA760BCA2A4F1773DC68102080C82020780A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22B8020BB0CB11735A8AF665A7A11EED17600ED5DDA1D563A6EF3CC77B070921D3881C38103010800820204B0')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A25EA031A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA129A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"rsa-sha-256","modulus":"4e-LJNb3awnIHtd1KqJi8ETwSodNQ4CdMc6mEvmbDJeotDdBU-Pu89ZmFoQ-DkHCkyZLcbYXPbHPDWzVWMWGV3Bvzwl_cExIPlnL_f1bPue8gNdAxeDwR_PoX8DXWBV3am8_I8XcXnlxOaaILjgzakpfs2E3Yg_zZj264yhHKAGGL3Ly-HsgK5yJrdfNWwoHb3xT41A59n7RfsgV5bQwXMYxlwaNXm5Xm6beX04-V99eTgcv8s5MZutFIzlzh1J1ljnwJXv1fb1cRD-1FYzOCj02rce6AfM6C7bbsr-YnWBxEvI0TZk-d-VjwdNh3t9X2pbvLPxoXwArY4JGpbMJuQ","signature":"SOiUXv4AdVbVv01fJJ5ICPcwfilRHTJi2u9h2ICY-apKi8BiOoyXVzj2XWv0WdVD8onXPLx69Oo6M_vz7ERARHkR1yKUCR5WGDNijkmncu1gjebERZWpHj4X1s9ew7JSjWPSrdZGOYmxLuxXffZHCWDfaDKp2Ew2DRwhetZMhiW9tZT7CtoIbN7LveWA1CS_l0bS8MMSgm27sArWi1LEy31HFWujXjqYHJc4Y3ksyA0EoYAhClJBWGW2Szphd0sdOXXXipiwgh7lXKD4YwXUJSnhDrAVzv1AL7WbKruN7uUqbyRH0ihGA9IZzU6M-c_91UmIicN4C1ndalfvfXMmIA"},{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22B8020BB0CB11735A8AF665A7A11EED17600ED5DDA1D563A6EF3CC77B070921D3881C38103010800820204B0', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;uwyxFzWor2ZaehHu0XYA7V3aHVY6bvPMd7Bwkh04gcM?fpt=threshold-sha-256&cost=67584&subtypes=preimage-sha-256,rsa-sha-256,threshold-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A25EA031A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA129A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A25EA031A22FA004A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA129A3278020B31FA8206E4EA7E515337B3B33082B877651801085ED84FB4DAEB247BF698D7F8103010000')
    })
  })
  describe('0010_threshold-sha-256_same-fulfillment-three-times.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":3,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '3081A2800103A1819CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100A0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22A8020618DDC367978196F17B2F33AA0259930F714814F7E68BFA720BDE8C47BC645168102100C82020780')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":3,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A237A00CA0028000A0028000A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":3,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""},{"type":"preimage-sha-256","preimage":""}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22A8020618DDC367978196F17B2F33AA0259930F714814F7E68BFA720BDE8C47BC645168102100C82020780', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;YY3cNnl4GW8XsvM6oCWZMPcUgU9-aL-nIL3oxHvGRRY?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A237A00CA0028000A0028000A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A237A00CA0028000A0028000A0028000A127A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })
  })
  describe('0011_threshold-sha-256_same-condition-three-times.json', function () {
    it('should correctly parse and reserialize the condition', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly generate the fingerprint contents', function () {
      const fulfillment = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}'))
      const fingerprintContents = fulfillment.getFingerprintContents()

      assert.equal(fingerprintContents.toString('hex').toUpperCase(), '3081A2800101A1819CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA0258020E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855810100')
    })

    it('should correctly serialize the condition to binary', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeBinary()

      assert.equal(generatedCondition.toString('hex').toUpperCase(), 'A22A8020969D19B902E5BD447297F8665D2A775BCBB11897398E8D00170CFF824F01499C8102100C82020780')
    })

    it('should correctly serialize the condition from a URI', function () {
      const parsedCondition = cc.fromConditionUri('ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
      const generatedCondition = parsedCondition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly serialize the fulfillment from json', function () {
      const jsonData = JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}')
      const fulfillment = cc.fromJson(jsonData).serializeBinary()

      assert.equal(fulfillment.toString('hex').toUpperCase(), 'A27DA004A0028000A175A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })

    it('should correctly serialize the condition URI from json', function () {
      const generatedCondition = cc.fromJson(JSON.parse('{"type":"threshold-sha-256","threshold":1,"subfulfillments":[{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":"SGVsbG8gV29ybGQh"},{"type":"preimage-sha-256","preimage":""}]}')).getConditionUri()

      assert.equal(generatedCondition, 'ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly parse the condition binary', function () {
      const condition = cc.fromConditionBinary(Buffer.from('A22A8020969D19B902E5BD447297F8665D2A775BCBB11897398E8D00170CFF824F01499C8102100C82020780', 'hex'))
      const generatedCondition = condition.serializeUri()

      assert.equal(generatedCondition, 'ni:sha-256;lp0ZuQLlvURyl_hmXSp3W8uxGJc5jo0AFwz_gk8BSZw?fpt=threshold-sha-256&cost=4108&subtypes=preimage-sha-256')
    })

    it('should correctly parse and reencode the fulfillment binary', function () {
      const fulfillment = cc.fromFulfillmentUri(Buffer.from('A27DA004A0028000A175A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C', 'hex').toString('base64'))
      const generatedFulfillment = fulfillment.serializeBase64Url()

      assert.equal(Buffer.from(generatedFulfillment, 'base64').toString('hex').toUpperCase(), 'A27DA004A0028000A175A02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010CA02580207F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D906981010C')
    })
  })
})
