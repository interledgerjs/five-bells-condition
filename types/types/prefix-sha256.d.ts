import type {
  PrefixSha256Asn1Json,
  PrefixSha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type Condition from '../lib/condition';
import type Fulfillment from '../lib/fulfillment';
import type BaseSha256 from './base-sha256';

export default class PrefixSha256 extends BaseSha256 {
  private prefix: Buffer;
  private subcondition: Condition | Fulfillment;
  private maxMessageLength: number;

  static TYPE_ID = TypeId.PrefixSha256;
  static TYPE_NAME = TypeName.PrefixSha256;
  static TYPE_ASN1_CONDITION = TypeAsn1Condition.PrefixSha256;
  static TYPE_ASN1_FULFILLMENT = TypeAsn1Fulfillment.PrefixSha256;
  static TYPE_CATEGORY = TypeCategory.PrefixSha256;

  static CONSTANT_BASE_COST = 16384;
  static CONSTANT_COST_DIVISOR = 256;

  constructor();

  setSubcondition(subcondition: Condition | string): void;

  setSubfulfillment(subfulfillment: Fulfillment | string): void;

  setPrefix(prefix: Buffer): void;

  setMaxMessageLength(maxMessageLength: number): void;

  getSubtypes(): Set<string>;

  private getFingerprintContents(): Buffer;

  getAsn1JsonPayload(): PrefixSha256Asn1Json;

  parseJson(json: PrefixSha256Json): void;

  parseAsn1JsonPayload(json: PrefixSha256Asn1Json): void;

  private calculateCost(): number;

  validate(message: Buffer): boolean;
}
