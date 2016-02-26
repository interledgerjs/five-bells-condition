# Introduction

## Motivation

We would like a way to describe a signed message such that multiple actors in a distributed system can all verify the same signed message and agree on whether it matches the description.

This provides a useful primitive for distributed, event-based systems since we can describe events (represented by signed messages) and therefore define generic authenticated event handlers.

## Terminology

* ##### Condition
  A condition is the hash of a description of a signed message.

* ##### Fulfillment
  A fulfillment consists of a description of a signed message and a signed message that matches the description.

  The description can be hashed and compared to a condition. If the message matches the description and the hash of the description matches the condition, we say that the fulfillment **fulfills** the condition.

* ##### Hashlock
  A tuple consisting of a bytestring and its hash where the hash is published first and the publication of the corresponding bytestring acts as a one-bit, one-time signature.

## Requirements

* Secure
* Stable - will rarely have to change
* Crypto-agile - easy to add new crypto-algorithms and deprecate old ones
* Flexible delegation - can express complex trust graphs (e.g. I trust Bob, but only if Jenna or Nicki agree with him)

## Related Work

* [Bitcoin Pay-to-script-hash (P2SH)](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
* [Tree Signatures](https://blockstream.com/2015/08/24/treesignatures)
* [Merkle Abstract Syntax Trees](http://css.csail.mit.edu/6.858/2014/projects/jlrubin-mnaik-nityas.pdf)
* [Collaboration-oriented Architecture (COA)](https://en.wikipedia.org/wiki/Collaboration-oriented_architecture)
* [Smart Signatures](https://github.com/WebOfTrustInfo/rebooting-the-web-of-trust/blob/master/final-documents/smart-signatures.pdf)
* [Merkle DAGs](https://github.com/jbenet/random-ideas/issues/20)
* [Hashed Timelock Contract (HTLC)](https://lightning.network/lightning-network-paper.pdf)
* [State Channels](http://www.jeffcoleman.ca/state-channels/)

# Basic Format

## Bitmask

Any system accepting crypto-conditions must be able to state its supported
algorithms. It must be possible to verify that all algorithms used in a certain
condition are indeed supported even if the fulfillment is not available yet.

In order to meet these design goals, we use a bitmask to define the supported primitives.

The following bits are assigned:

|Bitmask  |Exp.         |Int.|Condition Type   |
|--------:|------------:|---:|-----------------|
|        1|2<sup>0</sup>|   1|SHA-256          |
|       10|2<sup>1</sup>|   2|RSA-SHA-256      |
|      1__|2<sup>2</sup>|   4|THRESHOLD-SHA-256|

### Features

* An implementation can verify whether it understands a given condition by verifying that the condition's bitmask `condition` and its own bitmask of supported algorithms `supported` satisfies `condition & ~supported == 0` where `&` is the bitwise AND operator and `~` is the bitwise NOT operator.
* New algorithms can be added by defining new bits.
* Any new high bit can redefine the meaning of any existing lower bits as long as it is set. This can be used to remove obsolete algorithms.
* The bitmask is encoded as a varint to minimize space usage.

## String encoding

### Condition

Conditions are string encoded as:

```
"cc:1:" BASE64(CONDITION)
```

### Fulfillment

Fulfillments are string encoded as:

```
"cf:1:" BASE64(FULFILLMENT)
```

# Condition Types

## SHA-256

Bitmask: 1

### Notes

SHA-224 is not supported for Bitcoin compatibility.

### Condition

```
CONDITION =
  VARUINT BITMASK = 1
  UINT256 HASH
  VARUINT MAX_FULLFILLMENT_LENGTH

HASH = SHA256(
  UINT8[] PREIMAGE
)
```

### Fulfillment

```
FULFILLMENT =
  VARUINT BITMASK = 1
  VARSTR PREIMAGE
```

## RSA-SHA-256

Bitmask: 2

### Condition

```
CONDITION =
  VARUINT BITMASK = 2
  UINT256 HASH
  VARUINT MAX_FULLFILLMENT_LENGTH

HASH = SHA256(
  SHA256("https://w3.org/2016/02/xxx-xxx.html#rsa-sha-256")
  VARUINT BITMASK = 2
  VARSTR MODULUS
  VARSTR MESSAGE_PREFIX
)
```

### Fulfillment

```
FULFILLMENT =
  VARUINT BITMASK = 2
  VARSTR MODULUS
  VARSTR MESSAGE_PREFIX
  VARSTR MESSAGE
  UINT8[LENGTH(MODULUS)] SIGNATURE
  VARUINT BYTES_UNUSED
```

The `SIGNATURE` must have the exact same number of octets as the `MODULUS`.

The `BYTES_UNUSED` field is used to determine the `MAX_FULFILLMENT_LENGTH`. It
denotes the number of bytes that the fulfillment is below the
`MAX_FULFILLMENT_LENGTH`, not counting the BYTES_UNUSED field's own length.

### Implementation

The signature algorithm used is RSASSA-PSS as defined in [PKCS#1 v2.2](https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf).

The public exponent e is set to 65537. Very large exponents can be a [DoS vector](https://www.imperialviolet.org/2012/03/17/rsados.html) and 65537 is the largest Fermat prime, which has [some nice properties](http://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537).

The recommended modulus size as of 2016 [is 2048 bits](https://www.keylength.com/en/compare/). In the future we anticipate an upgrade to 3072 bits which provides [approximately 128 bits of security](http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf) (p. 64), about the same level as SHA-256. Implementations MUST reject moduli smaller than 512 or greater than 4096 bits. Large moduli slow down signature verification which can be a DoS vector. DNSSEC [also limits the modulus to 4096 bits](https://tools.ietf.org/html/rfc3110#section-2). OpenSSL [supports up to 16384 bits](http://fm4dd.com/openssl/certexamples.htm).

## THRESHOLD-SHA-256

### Bitmask

Bitmask: 4 | any supported subconditions

### Condition

```
CONDITION =
  VARUINT BITMASK
  UINT256 HASH
  VARUINT MAX_FULFILLMENT_LENGTH

HASH = SHA256(
  SHA-256("https://w3.org/2016/02/xxx-xxx.html#threshold-sha-256")
  VARUINT BITMASK
  VARUINT THRESHOLD
  VARUINT NUM_ELEMENTS
  FOR EACH ELEMENT
    ELEMENT_CONDITION
)
```

### Fulfillment

```
FULFILLMENT =
  VARUINT BITMASK
  VARUINT THRESHOLD
  VARUINT NUM_ELEMENTS
  FOR EACH ELEMENT
    VARUINT PARAMS
    ELEMENT_CONDITION/FULFILLMENT

PARAMS = (WEIGHT << 1) | (IS_FULFILLED % 1)
```
