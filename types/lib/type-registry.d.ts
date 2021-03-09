import type {
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeId,
  TypeName,
} from '../types';
import type PreimageSha256 from '../types/preimage-sha256';
import type PrefixSha256 from '../types/prefix-sha256';
import type ThresholdSha256 from '../types/threshold-sha256';
import type RsaSha256 from '../types/rsa-sha256';
import type Ed25519Sha256 from '../types/ed25519-sha256';

export interface RegisteredType {
  typeId: TypeId;
  name: TypeName;
  asn1Condition: TypeAsn1Condition;
  asn1Fulfillment: TypeAsn1Fulfillment;
  Class:
    | PreimageSha256
    | PrefixSha256
    | ThresholdSha256
    | RsaSha256
    | Ed25519Sha256;
}

export default class TypeRegistry {
  private registeredTypes: RegisteredType[];

  static findByTypeId(typeId: TypeId): RegisteredType['Class'];

  static findByName(name: TypeName): RegisteredType['Class'];

  static findByAsn1ConditionType(
    asn1Type: TypeAsn1Condition
  ): RegisteredType['Class'];

  static findByAsn1FulfillmentType(
    asn1Type: TypeAsn1Fulfillment
  ): RegisteredType['Class'];

  static registerType(Class: RegisteredType['Class']): void;
}
