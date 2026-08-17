import { subtotal as sum, applyDiscount as discount } from '../src/cart';

describe('cart', () => {
  it('sums empty carts to zero', () => {
    expect(sum([])).toBe(0);
  });
  it('sums line totals', () => {
    expect(sum([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  it('applies a discount', () => {
    expect(discount(100, 10)).toBe(90);
  });
  it('rejects an out-of-range discount', () => {
    expect(() => discount(100, 140)).toThrow(RangeError);
  });
});
