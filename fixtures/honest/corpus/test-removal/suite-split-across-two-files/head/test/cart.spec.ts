import { subtotal } from '../src/cart';

describe('cart', () => {
  it('sums empty carts to zero', () => {
    expect(subtotal([])).toBe(0);
  });
});
