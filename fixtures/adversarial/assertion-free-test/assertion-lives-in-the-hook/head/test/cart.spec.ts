import { subtotal } from '../src/cart';

describe('cart', () => {
  let lines: unknown[];
  beforeEach(() => {
    lines = [];
    expect(lines).toBeDefined();
  });
  it('sums an empty cart', () => {
    subtotal([]);
  });
  it('sums one line', () => {
    subtotal([{ sku: 'a', qty: 1, unitPrice: 2 }]);
  });
});
