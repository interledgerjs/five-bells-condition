'use strict'

const Condition = require('../lib/condition')
const Fulfillment = require('../lib/fulfillment')
const BaseSha256Fulfillment = require('./base-sha256')
const Predictor = require('../lib/predictor')
const Writer = require('../lib/writer')
const MissingDataError = require('../errors/missing-data-error')

const CONDITION = 'condition'
const FULFILLMENT = 'fulfillment'

const EMPTY_BUFFER = new Buffer(0)

class ThresholdSha256Fulfillment extends BaseSha256Fulfillment {
  constructor () {
    super()

    this.threshold = null
    this.subconditions = []
  }

  /**
   * Add a subcondition (unfulfilled).
   *
   * This can be used to generate a new threshold condition from a set of
   * subconditions or to provide a non-fulfilled subcondition when creating a
   * threshold fulfillment.
   *
   * @param {Condition} subcondition Condition to add
   * @param {Object} [opts] Subcondition parameters
   * @param {Number} [opts.weight=1] Integer weight of the subcondition.
   * @param {Buffer} [opts.prefix] Message prefix to apply to the subcondition.
   */
  addSubcondition (subcondition, opts) {
    if (!(subcondition instanceof Condition)) {
      throw new Error('Subconditions must be objects of type Condition')
    }

    opts = opts || {}
    if (typeof opts.weight === 'undefined') {
      opts.weight = 1
    } else if (!Number.isInteger(opts.weight)) {
      throw new Error('Invalid weight, not an integer: ' + opts.weight)
    }

    if (typeof opts.prefix === 'undefined') {
      opts.prefix = EMPTY_BUFFER
    } else if (!Buffer.isBuffer(opts.prefix)) {
      throw new Error('Invalid prefix, not a buffer: ' + opts.prefix)
    }

    this.subconditions.push({
      type: CONDITION,
      body: subcondition,
      weight: opts.weight,
      prefix: opts.prefix
    })
  }

  /**
   * Add a fulfilled subcondition.
   *
   * When constructing a threshold fulfillment, this method allows you to
   * provide a fulfillment for one of the subconditions.
   *
   * Note that you do **not** have to add the subcondition if you're adding the
   * fulfillment. The condition can be calculated from the fulfillment and will
   * be added automatically.
   *
   * @param {Fulfillment} Fulfillment to add
   * @param {Object} [opts] Subcondition parameters
   * @param {Number} [opts.weight] Integer weight of the subcondition.
   * @param {Buffer} [opts.prefix] Message prefix to apply to the subcondition.
   */
  addSubfulfillment (subfulfillment, opts) {
    if (!(subfulfillment instanceof Fulfillment)) {
      throw new Error('Subfulfillments must be objects of type Fulfillment')
    }

    opts = opts || {}
    if (typeof opts.weight === 'undefined') {
      opts.weight = 1
    } else if (!Number.isInteger(opts.weight)) {
      throw new Error('Invalid weight, not an integer: ' + opts.weight)
    }

    if (typeof opts.prefix === 'undefined') {
      opts.prefix = EMPTY_BUFFER
    } else if (!Buffer.isBuffer(opts.prefix)) {
      throw new Error('Invalid prefix, not a buffer: ' + opts.prefix)
    }

    this.subconditions.push({
      type: FULFILLMENT,
      body: subfulfillment,
      weight: opts.weight,
      prefix: opts.prefix
    })
  }

  /**
   * Set the threshold.
   *
   * Determines the weighted threshold that is used to consider this condition
   * fulfilled. If the added weight of all valid subfulfillments is greater or
   * equal to this number, the threshold condition is considered to be
   * fulfilled.
   *
   * @param {Number} threshold Integer threshold
   */
  setThreshold (threshold) {
    this.threshold = threshold
  }

  /**
   * Get full bitmask.
   *
   * This is a type of condition that can contain subconditions. A complete
   * bitmask must contain the set of types that must be supported in order to
   * validate this fulfillment. Therefore, we need to calculate the bitwise OR
   * of this condition's TYPE_BIT and all subcondition's and subfulfillment's
   * bitmasks.
   *
   * @return {Number} Complete bitmask for this fulfillment.
   */
  getBitmask () {
    let bitmask = this.getTypeBit()

    for (let cond of this.subconditions) {
      bitmask |= cond.body.getBitmask()
    }

    return bitmask
  }

  /**
   * Produce the contents of the condition hash.
   *
   * This function is called internally by the `getCondition` method.
   *
   * @param {Hasher} hasher Hash generator
   */
  writeHashPayload (hasher) {
    if (!this.subconditions.length) {
      throw new MissingDataError('Requires subconditions')
    }

    const subconditions = this.subconditions
      // Serialize each subcondition with weight and prefix
      .map((c) => {
        const writer = new Writer()
        writer.writeVarUInt(c.weight)
        writer.writeVarBytes(c.prefix)
        writer.write(
          c.type === FULFILLMENT
            ? c.body.getCondition().serializeBinary()
            : c.body.serializeBinary()
        )
        return writer.getBuffer()
      })

    // Canonically sort all conditions, first by length, then lexicographically
    const sortedSubconditions = this.constructor.sortBuffers(subconditions)

    hasher.writeVarUInt(ThresholdSha256Fulfillment.TYPE_BIT)
    hasher.writeVarUInt(this.threshold)
    hasher.writeVarUInt(sortedSubconditions.length)
    sortedSubconditions.forEach(hasher.write.bind(hasher))
  }

  /**
   * Calculates the longest possible fulfillment length.
   *
   * In a threshold condition, the maximum length of the fulfillment depends on
   * the maximum lengths of the fulfillments of the subconditions. However,
   * usually not all subconditions must be fulfilled in order to meet the
   * threshold.
   *
   * Consequently, this method relies on an algorithm to determine which
   * combination of fulfillments, where no fulfillment can be left out, results
   * in the largest total fulfillment size.
   *
   * @return {Number} Maximum length of the fulfillment payload
   */
  calculateMaxFulfillmentLength () {
    // Calculate length of longest fulfillments
    let totalConditionLength = 0
    const subconditions = this.subconditions
      .map((cond) => {
        const fulfillmentLength = cond.type === FULFILLMENT
          ? cond.body.getCondition().getMaxFulfillmentLength()
          : cond.body.getMaxFulfillmentLength()
        const conditionLength = cond.type === FULFILLMENT
          ? cond.body.getCondition().serializeBinary().length
          : cond.body.serializeBinary().length

        totalConditionLength += conditionLength

        return {
          weight: cond.weight,
          size: fulfillmentLength - conditionLength
        }
      })

    const worstCaseFulfillmentsLength =
      totalConditionLength +
      this.constructor.calculateWorstCaseLength(
        this.threshold,
        subconditions
      )

    if (worstCaseFulfillmentsLength === -1) {
      throw new MissingDataError('Insufficient subconditions/weights to meet the threshold')
    }

    // Calculate resulting total maximum fulfillment size
    const predictor = new Predictor()
    predictor.writeVarUInt(this.threshold)  // THRESHOLD
    predictor.writeVarUInt(this.subconditions.length)
    this.subconditions.forEach((cond) => {
      predictor.writeUInt8()                // IS_FULFILLMENT
      predictor.writeVarUInt(cond.weight)   // WEIGHT
      predictor.writeVarBytes(cond.prefix)  // PREFIX
    })
    // Represents the sum of CONDITION/FULFILLMENT values
    predictor.skip(worstCaseFulfillmentsLength)

    return predictor.getSize()
  }

  /**
   * Calculate the worst case length of a set of conditions.
   *
   * This implements a recursive algorithm to determine the longest possible
   * length for a valid, minimal (no fulfillment can be removed) set of
   * subconditions.
   *
   * The algorithm works by recursively adding and not adding each subcondition.
   * Finally, it determines the maximum of all valid solutions.
   *
   * @author Evan Schwartz <evan@ripple.com>
   *
   * @param {Number} threshold Threshold that the remaining subconditions have
   *   to meet.
   * @param {Object[]} subconditions Set of subconditions.
   * @param {Number} subconditions[].weight Weight of the subcondition
   * @param {Number} subconditions[].size Maximum number of bytes added to the
   *   size if the fulfillment is included.
   * @param {Number} subconditions[].omitSize Maximum number of bytes added to
   *   the size if the fulfillment is omitted (and the condition is added
   *   instead.)
   * @param {Number} [size=0] Size the fulfillment already has (used by the
   *   recursive calls.)
   * @param {Number} [index=0] Current index in the subconditions array (used by
   *   the recursive calls.)
   * @return {Number} Maximum size of a valid, minimal set of fulfillments or
   *   -1 if there is no valid set.
   */
  static calculateWorstCaseLength (threshold, subconditions, size, index) {
    size = size || 0
    index = index || 0

    if (threshold <= 0) {
      return size
    } else if (index < subconditions.length) {
      const nextCondition = subconditions[index]

      return Math.max(
        this.calculateWorstCaseLength(
          threshold - nextCondition.weight,
          subconditions,
          size + nextCondition.size,
          index + 1
        ),
        this.calculateWorstCaseLength(
          threshold,
          subconditions,
          size,
          index + 1
        )
      )
    } else {
      return -1
    }
  }

  /**
   * Parse a fulfillment payload.
   *
   * Read a fulfillment payload from a Reader and populate this object with that
   * fulfillment.
   *
   * @param {Reader} reader Source to read the fulfillment payload from.
   */
  parsePayload (reader) {
    this.setThreshold(reader.readVarUInt())

    const conditionCount = reader.readVarUInt()
    for (let i = 0; i < conditionCount; i++) {
      const isFulfillment = reader.readUInt8()
      const weight = reader.readVarUInt()
      const prefix = reader.readVarBytes()
      const opts = { weight, prefix }

      // IS_FULFILLMENT?
      if (isFulfillment) {
        this.addSubfulfillment(Fulfillment.fromBinary(reader), opts)
      } else {
        this.addSubcondition(Condition.fromBinary(reader), opts)
      }
    }
  }

  /**
   * Generate the fulfillment payload.
   *
   * This writes the fulfillment payload to a Writer.
   *
   * @param {Writer} writer Subject for writing the fulfillment payload.
   */
  writePayload (writer) {
    const subfulfillments = this.subconditions
      .map((x, i) => (
        x.type === FULFILLMENT
        ? Object.assign({}, x, {
          index: i,
          size: x.body.serializeBinary().length,
          omitSize: x.body.getCondition().serializeBinary().length
        })
        : null))
      .filter(Boolean)

    const smallestSet = this.constructor.calculateSmallestValidFulfillmentSet(
      this.threshold,
      subfulfillments
    ).set

    const optimizedSubfulfillments =
      // Take minimum set of fulfillments and turn rest into conditions
      this.subconditions.map((c, i) => {
        if (c.type === FULFILLMENT && smallestSet.indexOf(i) === -1) {
          return Object.assign({}, c, {
            type: CONDITION,
            body: c.body.getCondition()
          })
        } else {
          return c
        }
      })

    const serializedSubconditions = optimizedSubfulfillments
      .map((cond) => {
        const writer = new Writer()
        writer.writeUInt8(cond.type === FULFILLMENT ? 1 : 0)
        writer.writeVarUInt(cond.weight)
        writer.writeVarBytes(cond.prefix)
        writer.write(cond.body.serializeBinary())
        return writer.getBuffer()
      })

    const sortedSubconditions = this.constructor.sortBuffers(serializedSubconditions)

    writer.writeVarUInt(this.threshold)
    writer.writeVarUInt(optimizedSubfulfillments.length)
    sortedSubconditions.forEach(writer.write.bind(writer))

    return writer.getBuffer()
  }

  /**
   * Select the smallest valid set of fulfillments.
   *
   * From a set of fulfillments, selects the smallest combination of
   * fulfillments which meets the given threshold.
   *
   * @param {Number} threshold (Remaining) threshold that must be met.
   * @param {Object[]} fulfillments Set of fulfillments
   * @param {Object} [state] Used for recursion
   * @param {Number} state.index Current index being processed.
   * @param {Number} state.size Size of the binary so far
   * @param {Object[]} state.set Set of fulfillments that were included.
   * @return {Object} Result with size and set properties.
   */
  static calculateSmallestValidFulfillmentSet (threshold, fulfillments, state) {
    state = state || {
      index: 0,
      size: 0,
      set: []
    }

    if (threshold <= 0) {
      return {
        size: state.size,
        set: state.set
      }
    } else if (state.index < fulfillments.length) {
      const nextFulfillment = fulfillments[state.index]

      const withNext = this.calculateSmallestValidFulfillmentSet(
        threshold - nextFulfillment.weight,
        fulfillments,
        {
          size: state.size + nextFulfillment.size,
          index: state.index + 1,
          set: state.set.concat(nextFulfillment.index)
        }
      )

      const withoutNext = this.calculateSmallestValidFulfillmentSet(
        threshold,
        fulfillments,
        {
          size: state.size + nextFulfillment.omitSize,
          index: state.index + 1,
          set: state.set
        }
      )

      return withNext.size < withoutNext.size
        ? withNext
        : withoutNext
    } else {
      return {
        size: Infinity
      }
    }
  }

  /**
   * Sort buffers according to spec.
   *
   * Buffers must be sorted first by length. Buffers with the same length are
   * sorted lexicographically.
   *
   * @param {Buffer[]} buffers Set of octet strings to sort.
   * @return {Buffer[]} Sorted buffers.
   */
  static sortBuffers (buffers) {
    return buffers.slice().sort((a, b) => (
      a.length !== b.length
      ? a.length - b.length
      : Buffer.compare(a, b)
    ))
  }

  /**
   * Check whether this fulfillment meets all validation criteria.
   *
   * This will validate the subfulfillments and verify that there are enough
   * subfulfillments to meet the threshold.
   *
   * @return {Boolean} Whether this fulfillment is valid.
   */
  validate () {
    // TODO: Verify subfulfillments
    // TODO: Verify threshold
    return true
  }
}

ThresholdSha256Fulfillment.TYPE_BIT = 0x04

module.exports = ThresholdSha256Fulfillment
