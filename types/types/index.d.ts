import type { ConditionAsn1Json } from '../lib/condition';
import type { FulfillmentAsn1Json } from '../lib/fulfillment';

export enum Types {
  PreimageSha256 = 'PreimageSha256',
  PrefixSha256 = 'PrefixSha256',
  ThresholdSha256 = 'ThresholdSha256',
  RsaSha256 = 'RsaSha256',
  Ed25519Sha256 = 'Ed25519Sha256',
}

export enum TypeId {
  PreimageSha256 = 0,
  PrefixSha256 = 1,
  ThresholdSha256 = 2,
  RsaSha256 = 3,
  Ed25519Sha256 = 4,
}

export enum TypeName {
  PreimageSha256 = 'preimage-sha-256',
  PrefixSha256 = 'prefix-sha-256',
  ThresholdSha256 = 'threshold-sha-256',
  RsaSha256 = 'rsa-sha-256',
  Ed25519Sha256 = 'ed25519-sha-256',
}

export enum TypeAsn1Condition {
  PreimageSha256 = 'preimageSha256Condition',
  PrefixSha256 = 'prefixSha256Condition',
  ThresholdSha256 = 'thresholdSha256Condition',
  RsaSha256 = 'rsaSha256Condition',
  Ed25519Sha256 = 'ed25519Sha256Condition',
}

export enum TypeAsn1Fulfillment {
  PreimageSha256 = 'preimageSha256Fulfillment',
  PrefixSha256 = 'prefixSha256Fulfillment',
  ThresholdSha256 = 'thresholdSha256Fulfillment',
  RsaSha256 = 'rsaSha256Fulfillment',
  Ed25519Sha256 = 'ed25519Sha256Fulfillment',
}

export enum TypeCategory {
  PreimageSha256 = 'simple',
  PrefixSha256 = 'compound',
  ThresholdSha256 = 'compound',
  RsaSha256 = 'simple',
  Ed25519Sha256 = 'simple',
}

export interface PreimageSha256Json {
  type: Types.PreimageSha256;
  preimage: string;
}

export interface PreimageSha256Asn1Json {
  preimage: Buffer;
}

export interface PrefixSha256Json {
  type: Types.PrefixSha256;
  prefix: string;
  maxMessageLength: number;
  subfulfillment: FulfillmentAsn1Json<any>; // TODO: improve type
}

export interface PrefixSha256Asn1Json {
  prefix: Buffer;
  maxMessageLength: number;
  subfulfillment: FulfillmentAsn1Json<any>; // TODO: improve type
}

export interface RsaSha256Json {
  type: Types.RsaSha256;
  modulus: string;
  signature: string;
}

export interface RsaSha256Asn1Json {
  modulus: Buffer;
  signature: Buffer;
}
export interface Ed25519Sha256Json {
  type: Types.Ed25519Sha256;
  publicKey: string;
  signature: string;
}

export interface Ed25519Sha256Asn1Json {
  publicKey: Buffer;
  signature: Buffer;
}

export interface ThresholdSha256Json {
  type: Types.ThresholdSha256;
  threshold: number;
  subfulfillments?: (
    | PreimageSha256Json
    | PrefixSha256Json
    | ThresholdSha256Json
    | RsaSha256Json
    | Ed25519Sha256Json
  )[];
  subconditions?: ConditionAsn1Json[];
}
export interface ThresholdSha256Asn1Json {
  subfulfillments?: FulfillmentAsn1Json<any>[];
  subconditions?: ConditionAsn1Json[];
}
