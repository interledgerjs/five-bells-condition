# Fulfillment

Parsing armored
- Invalid prefix
  - ca
  - ac
  - af
- Invalid separator
- Invalid number of segments
- Invalid version
- Invalid bitmask
- Invalid fulfillment size
- Invalid base64 length
- Invalid base64 charset
- Invalid base64 (with padding)

Parsing binary
- Too short
- Extra bytes at end
- Fulfillment size too large
- Fulfillment size length prefix too large

Parsing prefix payload
- Zero length
- Extra bytes at end
- Large prefix length
- Missing bytes in prefix
- Invalid subfulfillment

Parsing threshold payload
- Improperly sorted fulfillment list (VALID)
- Invalid subfulfillment
- Threshold = 0
- Weight = 0
- Insufficient fulfillments

Parsing RSA payload
- Modulus too short
- Modulus too long
- Modulus has leading zero
- Very large modulus length
- Modulus underflow
- Signature length doesn't match modulus
- Very large signature length
- Signature underflow
- Extra bytes at end
- Invalid signature
- Minimum size modulus (VALID)
- Maximum size modulus (VALID)

Parsing ed25519 payload
- Too short
- Extra bytes at end
- Invalid signature
