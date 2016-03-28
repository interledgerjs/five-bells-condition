'use strict'

const UnsupportedTypeError = require('../errors/unsupported-type-error')

class TypeRegistry {
  /**
   * Determine fulfillment implementation class from a type ID.
   *
   * Returns the class implementing a fulfillment type that matches a certain
   * type ID.
   *
   * @param {Number} type Type ID.
   * @return {Class} Class implementing the given fulfillment type ID.
   */
  static getClassFromTypeId (typeId) {
    // Determine type of condition
    if (typeId > Number.MAX_SAFE_INTEGER) {
      throw new UnsupportedTypeError('Type ' + typeId + ' is not supported')
    }

    for (let type of TypeRegistry.registeredTypes) {
      if (typeId === type.typeId) return type.Class
    }

    throw new UnsupportedTypeError('Type ' + typeId + ' is not supported')
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

    TypeRegistry.registeredTypes.push({
      typeId: Class.TYPE_ID,
      Class
    })
  }
}

TypeRegistry.registeredTypes = []

module.exports = TypeRegistry
