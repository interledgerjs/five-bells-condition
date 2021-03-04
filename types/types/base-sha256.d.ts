import type Fulfillment from '../lib/fulfillment';

export default class BaseSha256 extends Fulfillment {
  generateHash(): Buffer;
}
