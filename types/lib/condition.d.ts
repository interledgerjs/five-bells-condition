import { Asn1Json, TypeAsn1Condition } from '../types';

export interface ConditionAsn1Json {
  type: TypeAsn1Condition;
  value: {
    fingerprint: Buffer;
    cost: string;
    subtypes?: {
      unused: number;
      data: Buffer;
    };
  };
}

export default class Condition {
  static readonly MAX_SAFE_SUBTYPES: number;
  static readonly SUPPORTED_SUBTYPES: number;
  static readonly MAX_COST: number;
  static readonly REGEX: RegExp;
  static readonly REGEX_STRICT: RegExp;

  static fromUri(serializedCondition: string): Condition;

  static fromBinary(data: Buffer): Condition;

  static fromAsn1Json(json: ConditionAsn1Json): Condition;

  // TODO: Condition.fromJson is used in treshold but undefined 
  // static fromJson(json: Asn1Json): Condition;

  getTypeId(): number;

  setTypeId(type: number): void;

  getTypeName(): string;

  getSubtypes(): number;

  setSubtypes(subtypes: number): void;

  getHash(): Buffer;

  setHash(hash: Buffer): void;

  getCost(): number;

  setCost(cost: number): void;

  serializeUri(): string;

  serializeBinary(): Buffer;

  getAsn1Json(): Asn1Json;

  validate(): boolean;
}
