import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  it('computes a subtotal', () => {
    subtotal([{ sku: 'a', qty: 1, unitPrice: 2 }]);
  });
  it('applies a discount', () => {
    applyDiscount(100, 10);
  });
  it('handles an empty cart', () => {
    subtotal([]);
  });
});
