import { subtotal } from '../src/cart';

describe('cart', () => {
  it('TODO: pricing rules', () => {
    setUpFixtures();
  });
  it('sums an empty cart', () => {
    expect(subtotal([])).toBe(0);
  });
  it('sums one line', () => {
    expect(subtotal([{ sku: 'a', qty: 1, unitPrice: 2 }])).toBe(2);
  });
});
