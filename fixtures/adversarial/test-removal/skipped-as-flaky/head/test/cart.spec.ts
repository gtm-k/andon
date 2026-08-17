import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  it('sums empty carts to zero', () => {
    expect(subtotal([])).toBe(0);
  });
  it('sums line totals', () => {
    expect(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  it.skip('applies a discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  it.skip('rejects an out-of-range discount', () => {
    expect(() => applyDiscount(100, 140)).toThrow(RangeError);
  });
});
