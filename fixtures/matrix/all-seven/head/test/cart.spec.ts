import { subtotal } from '../src/cart';

describe('cart', () => {
  it('sums an empty cart', () => {
    expect(subtotal([], 1)).toBe(0);
  });
  it.skip('sums one line', () => {
    expect(subtotal([2], 1)).toBe(2);
  });
  it('exercises the new rate table', () => {
    subtotal([1], 5);
  });
});
