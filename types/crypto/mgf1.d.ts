export type Mgf1Options = {
  hashAlgorithm?: string;
};

export default class Mgf1 {
  constructor(opts?: Mgf1Options);

  generate(seed: Buffer, maskLength: number): Buffer;
}
