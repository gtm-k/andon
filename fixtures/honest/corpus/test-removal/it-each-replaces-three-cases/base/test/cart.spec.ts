import { applyDiscount } from '../src/cart';

describe('discount', () => {
  it('applies ten percent', () => {
    expect(applyDiscount(100, 10)).toBe(90);
  });
  it('applies fifty percent', () => {
    expect(applyDiscount(100, 50)).toBe(50);
  });
  it('applies nothing', () => {
    expect(applyDiscount(100, 0)).toBe(100);
  });
});
