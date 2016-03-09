'use strict'

const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

class BitmaskRegistry {
  /**
   * Determine fulfillment implementation class from a bitmask.
   *
   * Returns the class implementing a fulfillment type that matches a certain
   * bitmask.
   *
   * @return {Class} Class implementing the given fulfillment type.
   */
  static getClassFromBitmask (bitmask) {
    // Determine type of condition
    if (bitmask > Number.MAX_SAFE_INTEGER) {
      throw new UnsupportedBitmaskError('Bitmask ' + bitmask + ' is not supported')
    }

    for (let type of BitmaskRegistry.registeredMetaTypes) {
      if (bitmask & type.bitmask) return type.Class
    }

    for (let type of BitmaskRegistry.registeredTypes) {
      if (bitmask === type.bitmask) return type.Class
    }

    throw new UnsupportedBitmaskError('Bitmask ' + bitmask + ' is not supported')
  }

  /**
   * Add a new fulfillment type.
   *
   * This can be used to extend this cryptocondition implementation with new
   * fulfillment types that it does not yet support. But mostly it is used
   * internally to register the built-in types.
   *
   * In this method, we expect a regular fulfillment type, for information on
   * registering meta types please see `registerMetaType`.
   *
   * @param {Class} Class Implementation of a fulfillment type.
   */
  static registerType (Class) {
    // TODO Do some sanity checks on Class

    BitmaskRegistry.registeredTypes.push({
      bitmask: Class.BITMASK,
      Class
    })
  }

  /**
   * Add a new fulfillment meta type.
   *
   * This can be used to extend this cryptocondition implementation with new
   * fulfillment types that it does not yet support. But mostly it is used
   * internally to register the built-in types.
   *
   * Meta fulfillment types are those which can have subfulfillments. This means
   * that the bitmask will have more than one bit set where the additional bits
   * represent the types of subconditions that are found in this condition.
   *
   * @param {Class} Class Implementation of a fulfillment type.
   */
  static registerMetaType (Class) {
    BitmaskRegistry.registeredMetaTypes.push({
      bitmask: Class.BITMASK,
      Class
    })
  }
}

BitmaskRegistry.registeredMetaTypes = []
BitmaskRegistry.registeredTypes = []

module.exports = BitmaskRegistry
