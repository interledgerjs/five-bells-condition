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
  static findByTypeId (typeId) {
    // Determine type of condition
    if (typeId > Number.MAX_SAFE_INTEGER) {
      throw new UnsupportedTypeError('Type ' + typeId + ' is not supported')
    }

    for (let type of TypeRegistry.registeredTypes) {
      if (typeId === type.typeId) return type
    }

    throw new UnsupportedTypeError('Type ' + typeId + ' is not supported')
  }

  static findByName (name) {
    for (let type of TypeRegistry.registeredTypes) {
      if (name === type.name) return type
    }

    throw new UnsupportedTypeError('Type ' + name + ' is not supported')
  }

  static findByAsn1ConditionType (asn1Type) {
    for (let type of TypeRegistry.registeredTypes) {
      if (asn1Type === type.asn1Condition) return type
    }

    throw new UnsupportedTypeError('Type ' + asn1Type + ' is not supported')
  }

  static findByAsn1FulfillmentType (asn1Type) {
    for (let type of TypeRegistry.registeredTypes) {
      if (asn1Type === type.asn1Fulfillment) return type
    }

    throw new UnsupportedTypeError('Type ' + asn1Type + ' is not supported')
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
      name: Class.TYPE_NAME,
      asn1Condition: Class.TYPE_ASN1_CONDITION,
      asn1Fulfillment: Class.TYPE_ASN1_FULFILLMENT,
      Class
    })
  }
}

TypeRegistry.registeredTypes = []

module.exports = TypeRegistry
