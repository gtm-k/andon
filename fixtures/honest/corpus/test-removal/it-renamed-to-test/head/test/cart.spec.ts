import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  test('sums empty carts to zero', () => {
    expect(subtotal([])).toBe(0);
  });
  test('sums line totals', () => {
    expect(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  test('applies a discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  test('rejects an out-of-range discount', () => {
    expect(() => applyDiscount(100, 140)).toThrow(RangeError);
  });
});
