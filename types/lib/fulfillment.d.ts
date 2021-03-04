import {
  Ed25519Json,
  PreImageJson,
  PrefixJson,
  RsaJson,
  TresholdJson,
  TypeAsn1Fulfillment,
  TypeNames,
} from '../types';

interface FulfillmentAsn1JsonValueMap {
  [TypeAsn1Fulfillment.PreimageSha256]: PreImageJson;
  [TypeAsn1Fulfillment.PrefixSha256]: PrefixJson;
  [TypeAsn1Fulfillment.ThresholdSha256]: TresholdJson;
  [TypeAsn1Fulfillment.RsaSha256]: RsaJson;
  [TypeAsn1Fulfillment.Ed25519Sha256]: Ed25519Json;
}

export interface FulfillmentAsn1Json<T = TypeAsn1Fulfillment> {
  type: T;
  value: FulfillmentAsn1JsonValueMap[T];
}

export default class Fulfillment {
  static fromUri(serializedFulfillment: string): Fulfillment;

  static fromBinary(data: Buffer): Fulfillment;

  static fromAsn1Json(json: FulfillmentAsn1Json): Fulfillment;

  static fromJson(
    json: PreImageJson | PrefixJson | TresholdJson | RsaJson | Ed25519Json
  ): Fulfillment;

  getTypeId(): TypeIds;

  getTypeName(): TypeNames;

  getSubtypes(): Set<string>;

  getCondition(): Condition;

  getConditionUri(): string;

  getConditionBinary(): Buffer;

  generateHash(): Buffer;

  private calculateCost(): number;

  parseAsn1JsonPayload(
    json: PreImageJson | PrefixJson | TresholdJson | RsaJson | Ed25519Json
  ): void;

  serializeUri(): string;

  getAsn1Json(): FulfillmentAsn1Json;

  serializeBinary(): Buffer;

  serializeBase64Url(): string;

  validate(): boolean;
}
