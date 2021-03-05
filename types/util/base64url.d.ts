export default class Base64Url {
  static decode(base64urlString: string): Buffer;
  
  static encode(buffer: Buffer): string;
}
