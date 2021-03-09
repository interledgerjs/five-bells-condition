import type {
  RsaSha256Asn1Json,
  RsaSha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type BaseSha256 from './base-sha256';

export const TYPE_ID = TypeId.RsaSha256;
export const TYPE_NAME = TypeName.RsaSha256;
export const TYPE_ASN1_CONDITION = TypeAsn1Condition.RsaSha256;
export const TYPE_ASN1_FULFILLMENT = TypeAsn1Fulfillment.RsaSha256;
export const TYPE_CATEGORY = TypeCategory.RsaSha256;

export const COST_RIGHT_SHIFT = 6; // 2^6 = 64

export default class RsaSha256 extends BaseSha256 {
  private modulus: Buffer;
  private signature: Buffer;

  static TYPE_ID: TypeId.RsaSha256;
  static TYPE_NAME: TypeName.RsaSha256;
  static TYPE_ASN1_CONDITION: TypeAsn1Condition.RsaSha256;
  static TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.RsaSha256;
  static TYPE_CATEGORY: TypeCategory.RsaSha256;

  static COST_RIGHT_SHIFT: number;

  constructor();

  parseJson(json: RsaSha256Json): void;

  private getFingerprintContents(): Buffer;

  getAsn1JsonPayload(): RsaSha256Asn1Json;

  setPublicModulus(modulus: Buffer): void;

  setSignature(signature: Buffer): void;

  sign(message: Buffer, privateKey: string): void;

  validate(message: Buffer): boolean;
}
