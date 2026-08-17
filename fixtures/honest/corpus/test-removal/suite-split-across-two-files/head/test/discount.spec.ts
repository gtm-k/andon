import { applyDiscount } from '../src/cart';

describe('discount', () => {
  it('sums line totals', () => {
    expect(applyDiscount(100, 0)).toBe(100);
  });
  it('applies a discount', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  it('rejects an out-of-range discount', () => {
    expect(() => applyDiscount(100, 140)).toThrow(RangeError);
  });
});
