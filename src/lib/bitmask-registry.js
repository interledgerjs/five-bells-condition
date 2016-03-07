'use strict'

const UnsupportedBitmaskError = require('../errors/unsupported-bitmask-error')

class BitmaskRegistry {
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

  static registerType (Class) {
    // TODO Do some sanity checks on Class

    BitmaskRegistry.registeredTypes.push({
      bitmask: Class.BITMASK,
      Class
    })
  }

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
