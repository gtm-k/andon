import { subtotal } from '../src/cart';

describe('cart', () => {
  it('sums an empty cart', () => {
    subtotal([]).should.equal(0);
  });
  it('sums one line', () => {
    subtotal([{ sku: 'a', qty: 1, unitPrice: 2 }]).should.equal(2);
  });
});
