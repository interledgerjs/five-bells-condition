export enum Types {
  PreimageSha256 = 'PreimageSha256',
  PrefixSha256 = 'PrefixSha256',
  ThresholdSha256 = 'ThresholdSha256',
  RsaSha256 = 'RsaSha256',
  Ed25519Sha256 = 'Ed25519Sha256',
}

export enum TypeIds {
  PreimageSha256 = 0,
  PrefixSha256 = 1,
  ThresholdSha256 = 2,
  RsaSha256 = 3,
  Ed25519Sha256 = 4,
}

export enum TypeNames {
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

export interface Asn1Json {
  type: TypeAsn1Condition;
  value: {
    fingerprint: string;
    cost: string;
    subtypes?: {
      unused: number;
      data: Buffer;
    };
  };
}

export interface PreImageJson {
  type: Types.PreimageSha256;
  preimage: string;
}

export interface PrefixJson {
  type: Types.PrefixSha256;
  prefix: string;
  maxMessageLength: number;
  subfulfillment: any; // TODO: improve
}

export interface RsaJson {
  type: Types.RsaSha256;
  modulus: string;
  signature: string;
}

export interface Ed25519Json {
  type: Types.Ed25519Sha256;
  publicKey: string;
  signature: string;
}

export interface TresholdJson {
  type: Types.ThresholdSha256;
  threshold: number;
  subfulfillments?: Record<string, any>[]; // improve type
  subconditions?: Record<string, any>[]; // improve type
}
