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
* Flexible delegation - can express arbitrary trust graphs (e.g. I trust Bob, but only if Jenna or Nicki agree with him)

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

Crypto-conditions are a simple multi-algorithm, multi-message, multi-level, multi-signature standard.

* **Multi-algorithm**

  Crypto-conditions can support several different signature and hash algorithms and support for new ones can be added in the future.

  Implementations can state their supported algorithms simply by providing a bitmask. It is easy to verify that a given implementation will be able to verify the fulfillment to a given condition, by verifying that the condition's bitmask `condition` and its own bitmask of supported algorithms `supported` satisfies `condition & ~supported == 0` where `&` is the bitwise AND operator and `~` is the bitwise NOT operator.

  Any new high bit can redefine the meaning of any existing lower bits as long as it is set. This can be used to remove obsolete algorithms.

  The bitmask is encoded as a varint to minimize space usage.

* **Multi-signature**

  Crypto-conditions can abstract away many of the details of multi-sign. When a party provides a condition, other parties can treat it opaquely and do not need to know about its internal structure. That allows parties to define arbitrary multi-signature setups without breaking compatibility.

  Protocol designers can use crypto-conditions as a drop-in replacement for public key signature algorithms and add multi-signature support to their protocols without adding any additional complexity.

* **Multi-level**

  Basic multi-sign is single-level and does not support more complex trust relationships such as "I trust Alice and Bob, but only when Candice also agrees". In single level 2-of-3 Alice and Bob could sign on their own, without Candice's approval.

  Crypto-conditions add that flexibility elegantly, by applying thresholds not just to signatures, but to conditions which can be signatures or further conditions. That allows the creation of an arbitrary threshold boolean circuit of signatures.

* **Multi-message**

  Crypto-conditions can sign not just one, but multiple messages at the same time and by different people. These messages can then be used as inputs for other algorithms.

  This allows resource-controlling systems to perform their functions without knowing the details of the higher-level protocols that these functions are a part of.

## Encoding

### Binary types

* **VARUINT**

  Unsigned variable-length integer. Implementation matches [Base128 Varints](https://developers.google.com/protocol-buffers/docs/encoding#varints) in Protocol Buffers. Implementations MAY define different maximum lengths for their varints, as long as that length is long enough to cover their bitmask and their maximum supported fulfillment length. (This is safe, because no larger varuint can appear in a valid crypto-condition.)

* **VARBYTES**

  Consists of a `VARUINT` length field followed by that many bytes.

* **VARARRAY**

  Consists of a `VARUINT` length fields followed by that many bytes filled with elements of the array.

### String types

* **BASE10**

  Variable-length integer encoded as a base-10 (decimal) number. Implementations MUST reject encodings that are too large for them to parse. Implementations MUST be tested for overflows.

* **BASE16**

  Variable-length integer encoded as a base-16 (hexadecimal) number. Implementations MUST reject encodings that are too large for them to parse. Implementations MUST be tested for overflows. No leading zeros.

* **BASE64URL**

  Base64-URL encoding. See [RFC4648 Section 5](https://tools.ietf.org/html/rfc4648#section-5).

### Condition

Conditions are string encoded as:

```
"cc:" BASE10(VERSION) ":" BASE16(BITMASK) ":" BASE64URL(HASH) ":" BASE10(MAX_FULFILLMENT_LENGTH)
```

Conditions are binary encoded as:

```
CONDITION =
  VARUINT BITMASK
  UINT256 HASH
  VARUINT MAX_FULFILLMENT_LENGTH
```

### Fulfillment

Fulfillments are string encoded as:

```
"cf:1:" BITMASK ":" BASE64URL(FULFILLMENT_PAYLOAD)
```

Fulfillments are binary encoded as:

```
FULFILLMENT =
  VARUINT BITMASK
  FULFILLMENT_PAYLOAD
```

# Condition Types

## SHA-256

Bitmask: 1

### Notes

This type of condition is also called a hashlock. We can use revealing the preimage as a type of one bit signature.

Bitcoin supports this type of condition via the `OP_HASH256` operator

### Condition

```
HASH = SHA256(PREIMAGE)
```

### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARBYTES PREIMAGE
```

## RSA-SHA-256

Bitmask: 2

### Condition

```
HASH = SHA256(
  SHA256("https://w3.org/2016/02/xxx-xxx.html#rsa-sha-256")
  VARUINT BITMASK = 2
  VARBYTES MODULUS
  VARBYTES MESSAGE_ID
  VARBYTES FIXED_PREFIX
  VARUINT DYNAMIC_MESSAGE_LENGTH
)
```

### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARBYTES MODULUS
  VARBYTES MESSAGE_ID
  VARBYTES FIXED_PREFIX
  VARUINT DYNAMIC_MESSAGE_LENGTH
  VARBYTES DYNAMIC_MESSAGE
  VARBYTES SIGNATURE
```

The `SIGNATURE` must have the exact same number of octets as the `MODULUS`. So theoretically we could omit the length prefix for the `SIGNATURE` field. But for consistency, we include the length prefix. Implementations MUST verify that the `SIGNATURE` and `MODULUS` are of the same length.

The `DYNAMIC_MESSAGE_LENGTH` is included to provide a maximum length `DYNAMIC_MESSAGE` even if the actual message suffix length is different. This value is also used to calculate the `MAX_FULFILLMENT_LENGTH` in the condition.

The `MESSAGE_ID` represents an identifier for the message. All messages in a cryptocondition that have a common identifier must match, otherwise the condition is invalid. Implementations may return messages as a map of `MESSAGE_ID` => `MESSAGE` pairs.

The message to be signed is the concatenation of the `FIXED_PREFIX` and `DYNAMIC_MESSAGE`.

### Implementation

The signature algorithm used is RSASSA-PSS as defined in [PKCS#1 v2.2](https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp.pdf).

The public exponent e is set to 65537. Very large exponents can be a [DoS vector](https://www.imperialviolet.org/2012/03/17/rsados.html) and 65537 is the largest Fermat prime, which has [some nice properties](http://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537).

The recommended modulus size as of 2016 [is 2048 bits](https://www.keylength.com/en/compare/). In the future we anticipate an upgrade to 3072 bits which provides [approximately 128 bits of security](http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf) (p. 64), about the same level as SHA-256. Implementations MUST reject moduli smaller than 512 or greater than 4096 bits. Large moduli slow down signature verification which can be a DoS vector. DNSSEC [also limits the modulus to 4096 bits](https://tools.ietf.org/html/rfc3110#section-2). OpenSSL [supports up to 16384 bits](http://fm4dd.com/openssl/certexamples.htm).

## THRESHOLD-SHA-256

### Bitmask

Bitmask: 4 | *bitmasks of all subconditions*

### Condition

```
HASH = SHA256(
  SHA256("https://w3.org/2016/02/xxx-xxx.html#threshold-sha-256")
  VARUINT BITMASK
  VARUINT THRESHOLD
  VARARRAY
    VARUINT WEIGHT
    CONDITION
)
```

The `VARARRAY` of conditions is sorted first based on length, shortest first. Elements of the same length are sorted in lexicographic (big-endian) order, smallest first.

### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARUINT THRESHOLD
  VARARRAY
    VARUINT WEIGHT
    FULFILLMENT
  VARARRAY
    VARUINT WEIGHT
    CONDITION
```
