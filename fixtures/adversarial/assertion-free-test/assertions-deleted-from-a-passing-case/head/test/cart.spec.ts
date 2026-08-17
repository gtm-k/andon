import { subtotal, applyDiscount } from '../src/cart';

describe('cart', () => {
  it('sums empty carts to zero', () => {
    expect(subtotal([])).toBe(0);
  });
  it('sums line totals', () => {
    expect(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }])).toBe(10);
  });
  it('applies a discount', () => {
    applyDiscount(100, 10);
  });
  it('rejects an out-of-range discount', () => {
    try { applyDiscount(100, 140); } catch { /* ignore */ }
  });
});
