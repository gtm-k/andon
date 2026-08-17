import { assertTotals } from './helpers';
import { subtotal } from '../src/cart';

describe('cart', () => {
  it('sums line totals', () => {
    assertTotals(subtotal([{ sku: 'a', qty: 2, unitPrice: 5 }]), 10);
  });
  it('sums an empty cart', () => {
    assertTotals(subtotal([]), 0);
  });
});
