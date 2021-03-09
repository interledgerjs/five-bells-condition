import type {
  Ed25519Sha256Asn1Json,
  Ed25519Sha256Json,
  TypeAsn1Condition,
  TypeAsn1Fulfillment,
  TypeCategory,
  TypeId,
  TypeName,
} from '.';
import type BaseSha256 from './base-sha256';

export const TYPE_ID: TypeId.Ed25519Sha256;
export const TYPE_NAME: TypeName.Ed25519Sha256;
export const TYPE_ASN1_CONDITION: TypeAsn1Condition.Ed25519Sha256;
export const TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.Ed25519Sha256;
export const TYPE_CATEGORY: TypeCategory.Ed25519Sha256;

export const CONSTANT_COST = 131072;
export default class Ed25519Sha256 extends BaseSha256 {
  private publicKey: Buffer;
  private signature: Buffer;

  static TYPE_ID: TypeId.Ed25519Sha256;
  static TYPE_NAME: TypeName.Ed25519Sha256;
  static TYPE_ASN1_CONDITION: TypeAsn1Condition.Ed25519Sha256;
  static TYPE_ASN1_FULFILLMENT: TypeAsn1Fulfillment.Ed25519Sha256;
  static TYPE_CATEGORY: TypeCategory.Ed25519Sha256;

  static CONSTANT_COST: number;

  constructor();

  setPublicKey(publicKey: Buffer): void;

  setSignature(signature: Buffer): void;

  sign(message: Buffer, privateKey: Buffer): void;

  parseJson(json: Ed25519Sha256Json): void;

  private getFingerprintContents(): Buffer;

  getAsn1JsonPayload(): Ed25519Sha256Asn1Json;

  validate(message: Buffer): boolean;
}
