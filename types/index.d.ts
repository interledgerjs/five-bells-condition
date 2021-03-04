import type Condition from './lib/condition';
import type Fulfillment from './lib/fulfillment';
import type TypeRegistry from './lib/type-registry';
import type {
  Ed25519Json,
  PrefixJson,
  PreImageJson,
  RsaJson,
  TresholdJson,
} from './types';
import type base64url from './util/base64url';

export { base64url, Condition, Fulfillment, TypeRegistry };
// export { PreimageSha256, RsaSha256, PrefixSha256, ThresholdSha256, Ed25519Sha256 };

export function fromConditionUri(serializedCondition: string): Condition;

export function fromConditionBinary(data: Buffer): Condition;

export function fromFulfillmentUri(serializedFulfillment: string): Fulfillment;

export function fromFulfillmentBinary(data: Buffer): Fulfillment;

export function validateCondition(serializedCondition: string): boolean;

export function validateFulfillment(
  serializedFulfillment: string,
  serializedCondition: string,
  message: Buffer
): boolean;

export function fulfillmentToCondition(serializedFulfillment: string): string;

export function fromJson(
  json: PreImageJson | PrefixJson | TresholdJson | RsaJson | Ed25519Json
): Fulfillment;

