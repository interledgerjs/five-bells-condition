import { TypeAsn1Condition, TypeId, TypeName } from '../types';

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
  private type?: TypeId;
  private subtypes?: Set<TypeName> | number;
  private hash?: Buffer;
  private cost?: number;

  static readonly MAX_SAFE_SUBTYPES = 0xffffffff;
  static readonly SUPPORTED_SUBTYPES = 0x3f;
  static readonly MAX_COST = 2097152;
  static readonly REGEX: RegExp;
  static readonly REGEX_STRICT: RegExp;

  static fromUri(serializedCondition: string): Condition;

  static fromBinary(data: Buffer): Condition;

  static fromAsn1Json(json: ConditionAsn1Json): Condition;

  // TODO: Condition.fromJson is used in treshold but undefined
  // static fromJson(json: Asn1Json): Condition;

  getTypeId(): number;

  setTypeId(type: TypeId): void;

  getTypeName(): string;

  //TODO: improve base on Condition typeCategory, if compound : Set<TypeName>, if simple : number
  getSubtypes(): Set<TypeName> | number;

  setSubtypes(subtypes: Set<TypeName> | number): void;

  getHash(): Buffer;

  setHash(hash: Buffer): void;

  getCost(): number;

  setCost(cost: number): void;

  serializeUri(): string;

  serializeBinary(): Buffer;

  getAsn1Json(): ConditionAsn1Json;

  validate(): boolean;
}
