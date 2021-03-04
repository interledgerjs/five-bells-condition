import {
  Ed25519Sha256Json,
  PreimageSha256Json,
  PrefixSha256Json,
  RsaSha256Json,
  ThresholdSha256Json,
  TypeAsn1Fulfillment,
  TypeName,
} from '../types';

interface FulfillmentAsn1JsonValueMap {
  [TypeAsn1Fulfillment.PreimageSha256]: PreimageSha256Json;
  [TypeAsn1Fulfillment.PrefixSha256]: PrefixSha256Json;
  [TypeAsn1Fulfillment.ThresholdSha256]: ThresholdSha256Json;
  [TypeAsn1Fulfillment.RsaSha256]: RsaSha256Json;
  [TypeAsn1Fulfillment.Ed25519Sha256]: Ed25519Sha256Json;
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
    json: PreimageSha256Json | PrefixSha256Json | ThresholdSha256Json | RsaSha256Json | Ed25519Sha256Json
  ): Fulfillment;

  getTypeId(): TypeIds;

  getTypeName(): TypeName;

  getSubtypes(): Set<string>;

  getCondition(): Condition;

  getConditionUri(): string;

  getConditionBinary(): Buffer;

  generateHash(): Buffer;

  private calculateCost(): number;

  parseAsn1JsonPayload(
    json: PreimageSha256Json | PrefixSha256Json | ThresholdSha256Json | RsaSha256Json | Ed25519Sha256Json
  ): void;

  serializeUri(): string;

  getAsn1Json(): FulfillmentAsn1Json;

  serializeBinary(): Buffer;

  serializeBase64Url(): string;

  validate(): boolean;
}
