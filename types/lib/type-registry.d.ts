import type {
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeIds,
  TypeNames,
} from '../types';

export interface RegisteredType {
  typeId: TypeIds;
  name: TypeNames;
  asn1Condition: TypeAsn1Condition;
  asn1Fulfillment: TypeAsn1Fulfillment;
  Class: any; // one of  PreimageSha256 | PrefixSha256 | ThresholdSha256 | RsaSha256 | Ed25519Sha256
}

export default class TypeRegistry {
  private registeredTypes: RegisteredType[] = [];

  // returntype Fulfillement or RegisteredType['Class']
  static findByTypeId(typeId: TypeIds): RegisteredType['Class'];

  static findByName(name: TypeNames): RegisteredType['Class'];

  static findByAsn1ConditionType(
    asn1Type: TypeAsn1Condition
  ): RegisteredType['Class'];

  static findByAsn1FulfillmentType(
    asn1Type: TypeAsn1Fulfillment
  ): RegisteredType['Class'];

  static registerType(Class: RegisteredType['Class']): void;
}
