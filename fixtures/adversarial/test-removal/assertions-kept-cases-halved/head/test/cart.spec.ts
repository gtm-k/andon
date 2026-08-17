import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  it('sums carts', () => {
    expect(subtotal([])).toBe(0);
    expect(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  it('applies a discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
});
