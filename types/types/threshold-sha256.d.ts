import type {
  ThresholdSha256Asn1Json,
  ThresholdSha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type Condition from '../lib/condition';
import type Fulfillment from '../lib/fulfillment';
import type BaseSha256 from './base-sha256';

export const CONDITION = 'condition';
export const FULFILLMENT = 'fulfillment';

interface SubConditionBodyMap {
  condition: Condition;
  fulfillment: Fulfillment;
}

export type SubCondition<T = 'condition' | 'fulfillment'> = {
  type: T;
  body: SubConditionBodyMap[T];
};

export const TYPE_ID = TypeId.ThresholdSha256;
export const TYPE_NAME = TypeName.ThresholdSha256;
export const TYPE_ASN1_CONDITION = TypeAsn1Condition.ThresholdSha256;
export const TYPE_ASN1_FULFILLMENT = TypeAsn1Fulfillment.ThresholdSha256;
export const TYPE_CATEGORY = TypeCategory.ThresholdSha256;

export default class ThresholdSha256 extends BaseSha256 {
  private threshold: number;
  private subconditions: SubCondition[];

  static TYPE_ID: TypeId.ThresholdSha256;
  static TYPE_NAME: TypeName.ThresholdSha256;
  static TYPE_ASN1_CONDITION: TypeAsn1Condition.ThresholdSha256;
  static TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.ThresholdSha256;
  static TYPE_CATEGORY: TypeCategory.ThresholdSha256;

  constructor();

  addSubcondition(subcondition: Condition | string): void;

  addSubfulfillment(subfulfillment: Fulfillment | string): void;

  setThreshold(threshold: number): void;

  getSubtypes(): Set<string>;

  private static compareConditions(a: Condition, b: Condition): number;

  private getFingerprintContents(): Buffer;

  private calculateCost(): number;

  static getSubconditionCost(cond: SubCondition): number;

  private static calculateWorstCaseLength(
    threshold: number,
    subconditionCosts: number[]
  ): number;

  parseJson(json: ThresholdSha256Json): void;

  parseAsn1JsonPayload(json: ThresholdSha256Asn1Json): void;

  getAsn1JsonPayload(): ThresholdSha256Asn1Json;

  // TODO: investigate what fulfillment is expected, where size property comes from ?
  private static calculateSmallestValidFulfillmentSet(
    threshold: number,
    fulfillments: any[]
  ): any[];

  validate(message: Buffer): boolean;
}
