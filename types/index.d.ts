import type Condition from './lib/condition';
import type Fulfillment from './lib/fulfillment';
import type TypeRegistry from './lib/type-registry';
import type {
  Ed25519Sha256Json,
  PrefixSha256Json,
  PreimageSha256Json,
  RsaSha256Json,
  ThresholdSha256Json,
} from './types';
import type PreimageSha256 from './types/preimage-sha256';
import type PrefixSha256 from './types/prefix-sha256';
import type ThresholdSha256 from './types/threshold-sha256';
import type RsaSha256 from './types/rsa-sha256';
import type Ed25519Sha256 from './types/ed25519-sha256';
import type base64url from './util/base64url';

export { base64url, Condition, Fulfillment, TypeRegistry };

export {
  PreimageSha256,
  RsaSha256,
  PrefixSha256,
  ThresholdSha256,
  Ed25519Sha256,
};

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
  json:
    | PreimageSha256Json
    | PrefixSha256Json
    | ThresholdSha256Json
    | RsaSha256Json
    | Ed25519Sha256Json
): Fulfillment;
