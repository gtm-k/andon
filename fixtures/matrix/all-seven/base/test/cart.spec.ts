import { subtotal } from '../src/cart';

describe('cart', () => {
  it('sums an empty cart', () => {
    expect(subtotal([], 1)).toBe(0);
  });
  it('sums one line', () => {
    expect(subtotal([2], 1)).toBe(2);
  });
  it('subtracts below the factor', () => {
    expect(subtotal([1], 5)).toBe(-1);
  });
  it('multiplies above the factor', () => {
    expect(subtotal([10], 2)).toBe(20);
  });
});
