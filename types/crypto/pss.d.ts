export type PssOptions = {
  hashAlgorithm?: string;
};

export default class Pss {
  static EMPTY_BUFFER: Buffer;

  constructor(opts?: PssOptions);

  encode(message: Buffer, encodedMessageBits: number): Buffer;

  verify(
    message: Buffer,
    encodedMessage: Buffer,
    encodedMessageBits: number
  ): boolean;
}
