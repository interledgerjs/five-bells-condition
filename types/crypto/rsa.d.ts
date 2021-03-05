export type RsaOptions = {
  hashAlgorithm?: string;
};

export default class Rsa {
  static ZERO_BYTE: Buffer;

  constructor(opts?: RsaOptions);

  getModulusBitLength(modulus: Buffer): number;

  sign(privateKey: string, message: Buffer): Buffer;

  verify(modulus: Buffer, message: Buffer, signature: Buffer): boolean;
}
