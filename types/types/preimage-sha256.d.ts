import type {
  PreimageSha256Asn1Json,
  PreimageSha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type BaseSha256 from './base-sha256';

export const TYPE_ID = TypeId.PreimageSha256;
export const TYPE_NAME = TypeName.PreimageSha256;
export const TYPE_ASN1_CONDITION = TypeAsn1Condition.PreimageSha256;
export const TYPE_ASN1_FULFILLMENT = TypeAsn1Fulfillment.PreimageSha256;
export const TYPE_CATEGORY = TypeCategory.PreimageSha256;

export default class PreimageSha256 extends BaseSha256 {
  private preimage: Buffer;

  static TYPE_ID: TypeId.PreimageSha256;
  static TYPE_NAME: TypeName.PreimageSha256;
  static TYPE_ASN1_CONDITION: TypeAsn1Condition.PreimageSha256;
  static TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.PreimageSha256;
  static TYPE_CATEGORY: TypeCategory.PreimageSha256;

  private getFingerprintContents(): Buffer;

  setPreimage(preimage: Buffer): void;

  parseJson(json: PreimageSha256Json): void;

  getAsn1JsonPayload(): PreimageSha256Asn1Json;

  validate(message: Buffer): boolean;
}
