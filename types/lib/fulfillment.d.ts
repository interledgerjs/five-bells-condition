import {
  Ed25519Sha256Json,
  PreimageSha256Json,
  PrefixSha256Json,
  RsaSha256Json,
  ThresholdSha256Json,
  TypeAsn1Fulfillment,
  TypeName,
  TypeId,
} from '../types';
import Condition from './condition';

interface FulfillmentAsn1JsonValueMap {
  [TypeAsn1Fulfillment.PreimageSha256]: PreimageSha256Json;
  [TypeAsn1Fulfillment.PrefixSha256]: PrefixSha256Json;
  [TypeAsn1Fulfillment.ThresholdSha256]: ThresholdSha256Json;
  [TypeAsn1Fulfillment.RsaSha256]: RsaSha256Json;
  [TypeAsn1Fulfillment.Ed25519Sha256]: Ed25519Sha256Json;
}

export interface FulfillmentAsn1Json<
  T extends keyof FulfillmentAsn1JsonValueMap
> {
  type: T;
  value: FulfillmentAsn1JsonValueMap[T];
}

export default class Fulfillment {
  static fromUri(serializedFulfillment: string): Fulfillment;

  static fromBinary(data: Buffer): Fulfillment;

  static fromAsn1Json(
    json: FulfillmentAsn1Json<keyof FulfillmentAsn1JsonValueMap>
  ): Fulfillment;

  static fromAsn1Json<T extends keyof FulfillmentAsn1JsonValueMap>(
    json: FulfillmentAsn1Json<T>
  ): Fulfillment;

  static fromJson(
    json:
      | PreimageSha256Json
      | PrefixSha256Json
      | ThresholdSha256Json
      | RsaSha256Json
      | Ed25519Sha256Json
  ): Fulfillment;

  getTypeId(): TypeId;

  getTypeName(): TypeName;

  getSubtypes(): Set<string>;

  getCondition(): Condition;

  getConditionUri(): string;

  getConditionBinary(): Buffer;

  generateHash(): Buffer;

  private calculateCost(): number;

  parseAsn1JsonPayload(
    json: FulfillmentAsn1Json<keyof FulfillmentAsn1JsonValueMap>['value']
  ): void;

  parseAsn1JsonPayload<T extends keyof FulfillmentAsn1JsonValueMap>(
    json: FulfillmentAsn1JsonValueMap[T]
  ): void;

  serializeUri(): string;

  getAsn1Json(): FulfillmentAsn1Json<keyof FulfillmentAsn1JsonValueMap>;

  getAsn1Json<
    T extends keyof FulfillmentAsn1JsonValueMap
  >(): FulfillmentAsn1Json<T>;

  serializeBinary(): Buffer;

  serializeBase64Url(): string;

  validate(message?: Buffer): boolean;
}
